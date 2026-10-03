# IsMalicious gateway filters

A Python 3.11+ server implementing Obot's MCP filter contract and ToolHive's request validation webhook. It has no runtime dependencies beyond the standard library.

This applies an administrator-configured policy to selected `tools/call` fetch tools. It is not an optional scanner tool offered to the model. Configure only tool names and URL arguments you know, for example `{"fetch":"url"}`.

## Policy and limits

- Before a selected fetch: send the **original HTTP(S) URL** to `GET /gate/url?u=...`. Query, commas and fragments are preserved. The reputation check does not fetch the destination.
- Obot selected responses: serialize the **whole result**, including nested `structuredContent` and text blocks, to `POST /gate/scan` in fast mode before forwarding. Refuse image/audio/embedded resource content rather than claiming to inspect it.
- ToolHive inspects **requests only**. Its validating webhook does not inspect tool results, streaming response content or tool metadata.
- Admit only a valid top-level `allow`; refuse `warn`, `block`, malformed data, API errors, timeout, quota 429, redirected API calls and `links_truncated`. Never retry a 429 or silently truncate input.
- Enforce 1 MiB on the UTF-8 serialized envelope and scan body. TLS verification is enabled for Gate; credentialed requests never follow redirects. Timeout is 15 seconds per Gate request.
- `allow` means this policy did not block. Unknown inner link reputation may still be present and does **not** prove a URL or content benign. No detector accuracy claim is made by the synthetic fixtures.
- MCP error responses, notifications, malformed/unmatched messages, binary media, uncorrelated responses and other MCP methods are outside the supported response scope. Obot's native gateway may pass malformed/uncorrelated traffic without invoking a filter; it must not be advertised as universally inspected.
- Gate `/gate/scan` and `/gate/url` use the separate scan quota. Do not substitute `/check` quota counts or freeze plan prices into configuration.
- The original authorized payload is returned without mutation. `sanitized_content` is never substituted.

## Run

Clone this repository at a release tag or commit, then:

```sh
python3 -m pip install .
ismalicious-gateway-filter --port 8099
```

Supply `ISMALICIOUS_API_KEY`, `ISMALICIOUS_API_SECRET`, and `ISMALICIOUS_FETCH_TOOLS` using your secret/deployment manager. The latter is a JSON map such as `{"fetch":"url"}`. Credentials are available from [your IsMalicious account](https://ismalicious.com/app/account).

The server binds to `127.0.0.1` by default. For remote HTTP use, place it behind an authenticated TLS reverse proxy and restrict network access. Never expose the plain HTTP listener to an untrusted network.

### Obot

The recommended Obot hosted deployment is `uvx`, which uses stdio and does not expose an HTTP listener. Import/configure the fields in [`examples/obot-filter.json`](examples/obot-filter.json), set the key/secret and tool mapping through Obot's sensitive configuration fields, and ensure the selector identifier matches the actual upstream tool name.

The tool name is `ismalicious_filter`. Obot sends a `SessionMessageHook` envelope whose `message` contains the JSON-RPC request or response. The filter returns `accept`, `mutated:false`, the original `message`, and a generic reason. Use only supported selected tool traffic; do not apply a wildcard selector to all MCP methods.

For a remote deployment, `/mcp` implements stateless Streamable HTTP with JSON replies and requires `Authorization: Bearer <ISMALICIOUS_FILTER_TOKEN>`. Configure that same header as a sensitive Obot remote-server field. This is not the older Obot HTTP webhook accept-by-status contract. Do not configure `/mcp` as an HTTP webhook.

Native validation uses a real HTTP upstream and ReverseProxy with Obot's hook processor, not a running full Obot service. It covers same-exchange correlation; it does not cover deployed multi-replica correlation. Native validation pins Obot to `cf4337b8966c8e76a6e5e896c8f122a8fa4e3305`. It starts this server and connects the actual MCP Go SDK before exercising the native gateway hook processor for request refusal and JSON/SSE response suppression.

### ToolHive

Set `ISMALICIOUS_WEBHOOK_SECRET` on this service and put the same secret in the file referenced by [`examples/toolhive-webhooks.yaml`](examples/toolhive-webhooks.yaml). The service requires ToolHive's HMAC-SHA256 signature and a timestamp within five minutes. This checks expiration, not unique nonce consumption: a valid signed payload can be replayed within the window. Protect this endpoint with TLS and restrict access to ToolHive.

```sh
thv run --webhook-config examples/toolhive-webhooks.yaml <your-fetch-server-image>
```

Use `failure_policy: fail`, TLS validation, and a 20-second webhook timeout. The ToolHive chain must parse MCP requests **before** the validating webhook; the native middleware bypasses a request with no parsed MCP context. Configuration that omits the webhook provides no enforcement. Unselected tools are admitted without a Gate call.

Native validation pins ToolHive to `3ca3c8f71152ad6e109dbb881be13ceb17a2cf3c`. It starts this webhook, uses the real signing client and validating middleware, and asserts the next handler is never called for block/warn/429/invalid decisions. Loopback HTTP/TLS bypass is enabled **only in these synthetic local tests**; production examples use HTTPS.

## Verification

```sh
python3 -m unittest discover -s tests -v
```

For native validation, place clones named `obot-native` and `toolhive-native` beside this directory at the SHAs above, then run:

```sh
python3 native-tests/run.py
```

The runner copies an integration test into each isolated clone, invokes the actual native package, and removes the temporary test. ToolHive uses a generated targeted Taskfile with its native macOS linker/race flags, via pinned go-task 3.45.4. This does not install a system binary. Full ToolHive API/CLI container E2E and Obot multi-replica deployment remain separate validation scopes; these tests do not claim to cover them.

All API decisions in the native tests come from a local deterministic server with dummy credentials. They test protocol/enforcement behavior, not production account access or scanner accuracy. No real credentials are written to this repository or logged.

This contribution was developed with an AI assistant. The supported scope and limitations are explicit so operators and maintainers can assess it.
