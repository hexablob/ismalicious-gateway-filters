"""Scoped fail-closed IsMalicious filters for Obot and ToolHive. Python 3.11+."""

import argparse
import base64
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LIMIT = 1 << 20


class PolicyError(Exception):
    """An input or decision cannot be safely admitted."""


def encode(value):
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def decode(data):
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise PolicyError("duplicate JSON key")
            out[key] = value
        return out

    return json.loads(
        data,
        object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(
            PolicyError("invalid JSON number")
        ),
    )


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Gate:
    def __init__(
        self,
        key,
        secret,
        base="https://api.ismalicious.com",
        test_http=False,
        timeout=15,
    ):
        uri = urllib.parse.urlsplit(base)
        loopback = uri.hostname in ("localhost", "127.0.0.1", "::1")
        if (
            uri.username
            or uri.password
            or uri.query
            or uri.fragment
            or (
                uri.scheme != "https"
                and not (test_http and loopback and uri.scheme == "http")
            )
        ):
            raise PolicyError("Gate must use a credential-free HTTPS base URL")
        if not key or not secret:
            raise PolicyError("both API credentials are required")
        self.base = base.rstrip("/")
        self.credential = base64.b64encode((key + ":" + secret).encode()).decode()
        self.opener = urllib.request.build_opener(NoRedirect())
        self.timeout = min(timeout, 15)

    def request(self, path, data=None):
        body = encode(data) if data is not None else None
        if body is not None and len(body) > LIMIT:
            raise PolicyError("serialized scan exceeds 1 MiB")
        req = urllib.request.Request(
            self.base + path,
            data=body,
            headers={
                "X-API-KEY": self.credential,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        try:
            with self.opener.open(req, timeout=self.timeout) as response:
                raw = response.read(LIMIT + 1)
                if response.status != 200 or len(raw) > LIMIT:
                    raise PolicyError("Gate response rejected")
                value = decode(raw)
        except urllib.error.HTTPError as error:
            error.close()
            raise PolicyError("Gate unavailable or invalid") from None
        except Exception:  # noqa: BLE001 - boundary must fail closed without exposing payloads
            # Do not put response bodies, URLs, exception strings, or credentials in errors.
            raise PolicyError("Gate unavailable or invalid") from None
        if not isinstance(value, dict) or value.get("verdict") not in (
            "allow",
            "warn",
            "block",
        ):
            raise PolicyError("invalid Gate decision")
        if (
            type(value.get("latency_ms")) is not int
            or not 0 <= value["latency_ms"] <= (1 << 63) - 1
        ):
            raise PolicyError("invalid Gate latency")
        return value

    def url(self, original):
        uri = urllib.parse.urlsplit(original)
        if (
            uri.scheme not in ("http", "https")
            or not uri.hostname
            or uri.username
            or uri.password
        ):
            raise PolicyError("unsupported URL")
        value = self.request("/gate/url?u=" + urllib.parse.quote(original, safe=""))
        if (
            not isinstance(value.get("url"), str)
            or value["url"] != original
            or not isinstance(value.get("entity"), str)
            or type(value.get("sources")) is not int
            or value["sources"] < 0
        ):
            raise PolicyError("invalid URL result")
        if value["verdict"] != "allow":
            raise PolicyError("URL refused by policy")
        # allow may include unknown reputation; it is not a benignness proof.
        return value

    @staticmethod
    def validate_link(link):
        if (
            not isinstance(link, dict)
            or link.get("verdict")
            not in ("clean", "unknown", "suspicious", "malicious")
            or not isinstance(link.get("url"), str)
            or not isinstance(link.get("entity"), str)
            or type(link.get("sources")) is not int
            or link["sources"] < 0
        ):
            raise PolicyError("invalid link result")

    def scan(self, content):
        value = self.request("/gate/scan", {"content": content, "mode": "fast"})
        injection = value.get("injection")
        links = value.get("links")
        if (
            not isinstance(injection, dict)
            or type(injection.get("score")) not in (int, float)
            or not 0 <= injection["score"] <= 1
            or not isinstance(injection.get("families"), list)
            or not all(isinstance(f, str) for f in injection["families"])
            or not isinstance(injection.get("spans"), list)
        ):
            raise PolicyError("invalid injection report")
        for span in injection["spans"]:
            if (
                not isinstance(span, dict)
                or type(span.get("start")) is not int
                or type(span.get("end")) is not int
                or span["start"] < 0
                or span["end"] < span["start"]
                or not isinstance(span.get("family"), str)
            ):
                raise PolicyError("invalid injection span")
        if (
            not isinstance(links, list)
            or type(value.get("links_truncated")) is not bool
            or value.get("mode") != "fast"
        ):
            raise PolicyError("invalid scan result")
        for link in links:
            self.validate_link(link)
        if value.get("source") is not None:
            self.validate_link(value["source"])
        if value.get("sanitized_content") is not None and not isinstance(
            value["sanitized_content"], str
        ):
            raise PolicyError("invalid optional scan field")
        if value["links_truncated"] or value["verdict"] != "allow":
            raise PolicyError("content refused by policy")
        return value


class Policy:
    def __init__(self, gate, tools):
        self.gate = gate
        self.tools = (
            tools  # Explicit fetch tool -> URL argument; never infer by text search.
        )
        if not tools or not all(
            isinstance(k, str) and k and isinstance(v, str) and v
            for k, v in tools.items()
        ):
            raise PolicyError("configure at least one fetch tool and URL argument")

    def request(self, message):
        if (
            not isinstance(message, dict)
            or message.get("jsonrpc") != "2.0"
            or not isinstance(message.get("method"), str)
        ):
            raise PolicyError("invalid request envelope")
        if message["method"] != "tools/call":
            return
        params = message.get("params")
        if not isinstance(params, dict) or not isinstance(params.get("name"), str):
            raise PolicyError("invalid tools/call")
        name = params["name"]
        if name not in self.tools:
            return
        arguments = params.get("arguments")
        if not isinstance(arguments, dict) or not isinstance(
            arguments.get(self.tools[name]), str
        ):
            raise PolicyError("missing configured fetch URL")
        self.gate.url(arguments[self.tools[name]])

    def obot(self, argument):
        message = argument.get("message") if isinstance(argument, dict) else None
        try:
            if (
                not isinstance(message, dict)
                or len(encode(message)) > LIMIT
                or message.get("jsonrpc") != "2.0"
            ):
                raise PolicyError("unsupported message")
            # Obot restores the original method on a correlated response hook.
            # A result therefore takes precedence over that synthetic method.
            if "result" in message:
                if "params" in message or "error" in message:
                    raise PolicyError("ambiguous response envelope")
                result = message["result"]
                if not isinstance(result, dict) or not isinstance(
                    result.get("content"), list
                ):
                    raise PolicyError("unsupported result")
                for block in result["content"]:
                    if (
                        not isinstance(block, dict)
                        or block.get("type") != "text"
                        or not isinstance(block.get("text"), str)
                    ):
                        raise PolicyError("non-text content unsupported")
                self.gate.scan(encode(result).decode())
            elif message.get("method"):
                self.request(message)
            else:
                raise PolicyError("unsupported response, including error content")
            return {
                "accept": True,
                "mutated": False,
                "message": message,
                "reason": "Gate admitted within configured scope",
            }
        except Exception:  # noqa: BLE001 - boundary must fail closed without exposing payloads
            return {
                "accept": False,
                "mutated": False,
                "message": message,
                "reason": "IsMalicious policy refused the message",
            }

    def toolhive(self, value):
        uid = value.get("uid") if isinstance(value, dict) else None
        response = {
            "version": "v0.1.0",
            "uid": uid,
            "allowed": False,
            "reason": "ismalicious-policy-denied",
        }
        try:
            if (
                not isinstance(value, dict)
                or value.get("version") != "v0.1.0"
                or not isinstance(uid, str)
                or not uid
                or len(encode(value)) > LIMIT
            ):
                raise PolicyError("invalid ToolHive envelope")
            self.request(value.get("mcp_request"))
            response["allowed"] = True
            response["reason"] = "within-configured-scope"
        except Exception:  # noqa: BLE001 - boundary must fail closed without exposing payloads
            response["allowed"] = False
        return response


def rpc(policy, request):
    if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
        raise PolicyError("invalid JSON-RPC")
    if "id" not in request:
        return None
    result = None
    method = request.get("method")
    if method == "initialize":
        result = {
            "protocolVersion": request.get("params", {}).get(
                "protocolVersion", "2025-06-18"
            ),
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "ismalicious-obot-filter", "version": "0.1.0"},
        }
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        result = {
            "tools": [
                {
                    "name": "ismalicious_filter",
                    "description": "Obot gateway filter. Invoke only as a configured filter, not as an agent security recommendation.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "message": {"type": "object"},
                            "accept": {"type": "boolean"},
                            "mutated": {"type": "boolean"},
                            "reason": {"type": "string"},
                        },
                        "required": ["message"],
                    },
                }
            ]
        }
    elif (
        method == "tools/call"
        and request.get("params", {}).get("name") == "ismalicious_filter"
    ):
        decision = policy.obot(request["params"].get("arguments"))
        result = {
            "structuredContent": decision,
            "content": [{"type": "text", "text": encode(decision).decode()}],
            "isError": False,
        }
    else:
        return {
            "jsonrpc": "2.0",
            "id": request["id"],
            "error": {"code": -32601, "message": "Method not supported"},
        }
    return {"jsonrpc": "2.0", "id": request["id"], "result": result}


def handler(policy, token, signing_secret):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            self.connection.settimeout(20)
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= LIMIT or self.headers.get("Transfer-Encoding"):
                    raise PolicyError("invalid body size")
                raw = self.rfile.read(size)
                if len(raw) != size:
                    raise PolicyError("incomplete body")
                if self.path == "/mcp":
                    if not token or not hmac.compare_digest(
                        self.headers.get("Authorization", ""), "Bearer " + token
                    ):
                        self.send_error(401)
                        return
                    result = rpc(policy, decode(raw))
                    if result is None:
                        self.send_response(202)
                        self.end_headers()
                        return
                elif self.path == "/toolhive":
                    if not signing_secret:
                        raise PolicyError("HMAC required")
                    timestamp = self.headers.get("X-ToolHive-Timestamp", "")
                    if abs(time.time() - int(timestamp)) > 300:
                        raise PolicyError("expired signature")
                    signature = (
                        "sha256="
                        + hmac.new(
                            signing_secret.encode(),
                            timestamp.encode() + b"." + raw,
                            hashlib.sha256,
                        ).hexdigest()
                    )
                    if not hmac.compare_digest(
                        self.headers.get("X-ToolHive-Signature", ""), signature
                    ):
                        raise PolicyError("invalid signature")
                    result = policy.toolhive(decode(raw))
                else:
                    self.send_error(404)
                    return
                body = encode(result)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except Exception:  # noqa: BLE001 - boundary must fail closed without exposing payloads
                self.send_error(422, "Policy request rejected")

    return Handler


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8099)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--stdio", action="store_true")
    args = parser.parse_args()
    try:
        gate = Gate(
            os.environ.get("ISMALICIOUS_API_KEY"),
            os.environ.get("ISMALICIOUS_API_SECRET"),
            os.environ.get("ISMALICIOUS_GATE_BASE", "https://api.ismalicious.com"),
            os.environ.get("ISMALICIOUS_TEST_HTTP") == "1",
        )
        policy = Policy(
            gate, decode(os.environ.get("ISMALICIOUS_FETCH_TOOLS", '{"fetch":"url"}'))
        )
        if args.stdio:
            while True:
                line = sys.stdin.buffer.readline(LIMIT + 1)
                if not line:
                    return
                if len(line) > LIMIT:
                    raise PolicyError("MCP input exceeds limit")
                output = rpc(policy, decode(line))
                if output is not None:
                    sys.stdout.buffer.write(encode(output) + b"\n")
                    sys.stdout.buffer.flush()
        else:
            server = ThreadingHTTPServer(
                (args.host, args.port),
                handler(
                    policy,
                    os.environ.get("ISMALICIOUS_FILTER_TOKEN"),
                    os.environ.get("ISMALICIOUS_WEBHOOK_SECRET"),
                ),
            )
            server.serve_forever()
    except Exception:  # noqa: BLE001 - boundary must fail closed without exposing payloads
        print("Filter configuration or input rejected", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
