import copy
import hashlib
import hmac
import subprocess
import sys
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from gateway_filters import LIMIT, Gate, Policy, PolicyError, decode, encode, handler

URL = "https://example.com/page?a=1,2&b=yes#section"
REQUEST = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {"name": "fetch", "arguments": {"url": URL}},
}
RESULT = {
    "jsonrpc": "2.0",
    "id": 1,
    "result": {
        "content": [{"type": "text", "text": "hello"}],
        "structuredContent": {"nested": {"text": "untrusted text"}},
    },
}


def scan(verdict="allow"):
    return {
        "verdict": verdict,
        "injection": {"score": 0.1, "families": [], "spans": []},
        "links": [],
        "links_truncated": False,
        "mode": "fast",
        "latency_ms": 3,
    }


class MockGate:
    def __init__(self):
        self.status = 200
        self.response = None
        self.requests = []
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                owner.requests.append((self.path, None))
                original = urllib.parse.parse_qs(
                    urllib.parse.urlsplit(self.path).query
                )["u"][0]
                self.answer(
                    {
                        "url": original,
                        "entity": "domain",
                        "verdict": "allow",
                        "sources": 0,
                        "latency_ms": 1,
                    }
                )

            def do_POST(self):
                data = decode(self.rfile.read(int(self.headers["Content-Length"])))
                owner.requests.append((self.path, data))
                self.answer(scan())

            def answer(self, default):
                self.send_response(owner.status)
                if owner.status == 302:
                    self.send_header("Location", owner.server_url + "/redirect-target")
                self.end_headers()
                body = owner.response if owner.response is not None else default
                self.wfile.write(body if isinstance(body, bytes) else encode(body))

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server_url = "http://127.0.0.1:" + str(self.server.server_port)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


class Tests(unittest.TestCase):
    def setUp(self):
        self.mock = MockGate()
        self.gate = Gate(
            "test-key", "test-secret", self.mock.server_url, test_http=True, timeout=0.2
        )
        self.policy = Policy(self.gate, {"fetch": "url"})

    def tearDown(self):
        self.mock.close()

    def test_obot_allow_preserves_every_field(self):
        decision = self.policy.obot({"message": copy.deepcopy(RESULT)})
        self.assertTrue(decision["accept"])
        self.assertFalse(decision["mutated"])
        self.assertEqual(decision["message"], RESULT)
        self.assertEqual(decode(self.mock.requests[0][1]["content"]), RESULT["result"])

    def test_obot_correlated_response_method_does_not_become_request(self):
        value = copy.deepcopy(RESULT)
        value["method"] = "tools/call"
        self.assertTrue(self.policy.obot({"message": value})["accept"])
        self.assertEqual(self.mock.requests[0][0], "/gate/scan")

    def test_original_url_query_comma_fragment(self):
        self.assertTrue(self.policy.obot({"message": REQUEST})["accept"])
        self.assertEqual(
            urllib.parse.parse_qs(
                urllib.parse.urlsplit(self.mock.requests[0][0]).query
            )["u"][0],
            URL,
        )

    def test_unknown_link_can_allow_but_does_not_imply_known_good(self):
        response = scan()
        response["links"] = [
            {"url": URL, "entity": "domain", "verdict": "unknown", "sources": 0}
        ]
        self.mock.response = response
        self.assertTrue(self.policy.obot({"message": RESULT})["accept"])

    def test_warn_and_block_are_refused(self):
        for verdict in ["warn", "block"]:
            with self.subTest(verdict=verdict):
                self.mock.response = scan(verdict)
                self.assertFalse(self.policy.obot({"message": RESULT})["accept"])

    def test_http_quota_error_redirect_never_retry_or_follow(self):
        for status in [429, 500, 302]:
            with self.subTest(status=status):
                self.mock.status = status
                before = len(self.mock.requests)
                self.assertFalse(self.policy.obot({"message": RESULT})["accept"])
                self.assertEqual(len(self.mock.requests), before + 1)

    def test_malformed_or_incomplete_decisions(self):
        responses = [
            b"not-json",
            b'{"verdict":"allow","verdict":"block"}',
            {},
            {"verdict": "unknown"},
            {"verdict": "allow", "latency_ms": 1},
            scan() | {"injection": {"score": True, "families": [], "spans": []}},
            scan() | {"links_truncated": True},
            scan() | {"links": [{"verdict": "clean"}]},
            scan() | {"mode": "thorough"},
        ]
        for response in responses:
            with self.subTest(response=response):
                self.mock.response = response
                self.assertFalse(self.policy.obot({"message": RESULT})["accept"])

    def test_latency_int64_and_optional_source_schema(self):
        invalid = [
            scan() | {"latency_ms": 1.5},
            scan() | {"latency_ms": True},
            scan() | {"latency_ms": 1 << 64},
            scan() | {"source": {"verdict": "unknown"}},
            scan() | {"source": "wrong"},
            scan() | {"sanitized_content": 42},
        ]
        for response in invalid:
            with self.subTest(response=response):
                self.mock.response = response
                self.assertFalse(self.policy.obot({"message": RESULT})["accept"])
        self.mock.response = encode(scan()).replace(
            b'"latency_ms":3', b'"latency_ms":1e309'
        )
        self.assertFalse(self.policy.obot({"message": RESULT})["accept"])
        for source in [
            None,
            {"url": URL, "entity": "domain", "verdict": "unknown", "sources": 0},
        ]:
            self.mock.response = scan() | {"source": source}
            self.assertTrue(self.policy.obot({"message": RESULT})["accept"])

    def test_url_decision_schema(self):
        for response in [
            {"verdict": "allow", "latency_ms": 1},
            {
                "url": "different",
                "entity": "domain",
                "verdict": "allow",
                "sources": 0,
                "latency_ms": 0,
            },
        ]:
            self.mock.response = response
            self.assertFalse(self.policy.obot({"message": REQUEST})["accept"])

    def test_unsupported_media_and_oversize_fail_closed_without_api(self):
        for content in [
            [{"type": "image", "data": "abc", "mimeType": "image/png"}],
            [{"type": "text", "text": "é" * LIMIT}],
        ]:
            value = copy.deepcopy(RESULT)
            value["result"]["content"] = content
            self.assertFalse(self.policy.obot({"message": value})["accept"])
        self.assertEqual(self.mock.requests, [])

    def test_body_serialization_limit_applies_to_scan_envelope(self):
        with self.assertRaises(PolicyError):
            self.gate.scan("é" * LIMIT)
        self.assertEqual(self.mock.requests, [])

    def test_invalid_selected_fetch_denied_unselected_scope_admitted(self):
        value = copy.deepcopy(REQUEST)
        value["params"]["arguments"] = {}
        self.assertFalse(self.policy.obot({"message": value})["accept"])
        value["params"]["name"] = "other"
        self.assertTrue(self.policy.obot({"message": value})["accept"])
        self.assertEqual(self.mock.requests, [])

    def test_toolhive_uid_version_and_decision(self):
        value = {"version": "v0.1.0", "uid": "uid-123", "mcp_request": REQUEST}
        result = self.policy.toolhive(value)
        self.assertEqual(result["uid"], value["uid"])
        self.assertEqual(result["version"], value["version"])
        self.assertTrue(result["allowed"])
        self.assertFalse(self.policy.toolhive(value | {"version": "wrong"})["allowed"])
        self.assertFalse(self.policy.toolhive(value | {"uid": None})["allowed"])

    def test_network_error_denies(self):
        self.gate.base = "http://127.0.0.1:0"
        self.assertFalse(self.policy.obot({"message": RESULT})["accept"])

    def test_stdio_is_a_runnable_mcp_server(self):
        import os

        env = os.environ.copy()
        env.update(
            {
                "ISMALICIOUS_API_KEY": "stdio-dummy-key",
                "ISMALICIOUS_API_SECRET": "stdio-dummy-secret",
                "ISMALICIOUS_GATE_BASE": self.mock.server_url,
                "ISMALICIOUS_TEST_HTTP": "1",
            }
        )
        messages = [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2025-06-18"},
            },
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "ismalicious_filter",
                    "arguments": {"message": RESULT},
                },
            },
        ]
        process = subprocess.run(
            [
                sys.executable,
                str(Path(__file__).resolve().parents[1] / "gateway_filters.py"),
                "--stdio",
            ],
            env=env,
            input=b"".join(encode(m) + b"\n" for m in messages),
            capture_output=True,
            check=True,
        )
        lines = [decode(line) for line in process.stdout.splitlines()]
        self.assertEqual(len(lines), 3)
        self.assertEqual(lines[1]["result"]["tools"][0]["name"], "ismalicious_filter")
        self.assertTrue(lines[2]["result"]["structuredContent"]["accept"])
        self.assertNotIn(b"stdio-dummy", process.stdout + process.stderr)

    def test_non_tls_gate_rejected_and_credentials_never_in_reason(self):
        with self.assertRaises(PolicyError):
            Gate("key", "secret", "http://example.com", test_http=True)
        self.mock.response = b"secret-key"
        decision = self.policy.obot({"message": RESULT})
        self.assertNotIn("secret-key", encode(decision).decode())

    def test_http_protocol_authentication_signature_and_expiration(self):
        service = ThreadingHTTPServer(
            ("127.0.0.1", 0), handler(self.policy, "filter-token", "test-hmac")
        )
        thread = threading.Thread(target=service.serve_forever, daemon=True)
        thread.start()
        base = "http://127.0.0.1:" + str(service.server_port)
        try:
            request = encode(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": "ismalicious_filter",
                        "arguments": {"message": RESULT},
                    },
                }
            )
            with urllib.request.urlopen(
                urllib.request.Request(
                    base + "/mcp",
                    request,
                    headers={"Authorization": "Bearer filter-token"},
                )
            ) as response:
                self.assertTrue(
                    decode(response.read())["result"]["structuredContent"]["accept"]
                )
            with self.assertRaises(urllib.error.HTTPError) as caught:
                urllib.request.urlopen(urllib.request.Request(base + "/mcp", request))
            self.assertEqual(caught.exception.code, 401)
            caught.exception.close()
            payload = encode(
                {"version": "v0.1.0", "uid": "http-123", "mcp_request": REQUEST}
            )
            for timestamp, expected in [(str(int(time.time())), 200), ("1", 422)]:
                signature = (
                    "sha256="
                    + hmac.new(
                        b"test-hmac",
                        timestamp.encode() + b"." + payload,
                        hashlib.sha256,
                    ).hexdigest()
                )
                req = urllib.request.Request(
                    base + "/toolhive",
                    payload,
                    headers={
                        "X-ToolHive-Signature": signature,
                        "X-ToolHive-Timestamp": timestamp,
                    },
                )
                try:
                    with urllib.request.urlopen(req) as response:
                        self.assertEqual(response.status, expected)
                        self.assertEqual(decode(response.read())["uid"], "http-123")
                except urllib.error.HTTPError as error:
                    self.assertEqual(error.code, expected)
                    error.close()
        finally:
            service.shutdown()
            service.server_close()
            thread.join()


if __name__ == "__main__":
    unittest.main()
