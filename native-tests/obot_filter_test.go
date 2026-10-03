package mcpgateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/obot-platform/obot/apiclient/types"
	"github.com/obot-platform/obot/pkg/mcp"
)

type ismaliciousNativeRunner struct{ session *gomcp.ClientSession }

func (r *ismaliciousNativeRunner) RunHook(ctx context.Context, _ mcp.HookServerConfigs, input mcp.SessionMessageHook, _ string) (*mcp.SessionMessageHook, error) {
	result, err := r.session.CallTool(ctx, &gomcp.CallToolParams{Name: "ismalicious_filter", Arguments: input})
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(result.StructuredContent)
	if err != nil {
		return nil, err
	}
	var decision mcp.SessionMessageHook
	err = json.Unmarshal(data, &decision)
	return &decision, err
}

type ismaliciousAuthTransport struct{}

func (ismaliciousAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	cloned := req.Clone(req.Context())
	cloned.Header = req.Header.Clone()
	cloned.Header.Set("Authorization", "Bearer native-filter-token")
	return http.DefaultTransport.RoundTrip(cloned)
}

func TestIsMaliciousPublishedFilterNativeJSONAndSSE(t *testing.T) {
	var verdict atomic.Value
	verdict.Store("allow")
	gate := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(map[string]any{"url": r.URL.Query().Get("u"), "entity": "domain", "verdict": verdict.Load(), "sources": 0, "latency_ms": 1})
		} else {
			_ = json.NewEncoder(w).Encode(map[string]any{"verdict": verdict.Load(), "injection": map[string]any{"score": 0, "families": []any{}, "spans": []any{}}, "links": []any{}, "links_truncated": false, "mode": "fast", "latency_ms": 1})
		}
	}))
	defer gate.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	script := os.Getenv("ISMALICIOUS_FILTER_SCRIPT")
	if script == "" {
		t.Fatal("set ISMALICIOUS_FILTER_SCRIPT to the adapter file")
	}
	example, err := os.ReadFile(strings.TrimSuffix(script, "gateway_filters.py") + "examples/obot-filter.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest types.MCPWebhookValidationManifest
	if err := json.Unmarshal(example, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.SystemMCPServerManifest == nil || manifest.SystemMCPServerManifest.Runtime != types.RuntimeUVX || manifest.ToolName != "ismalicious_filter" {
		t.Fatal("invalid native filter manifest")
	}
	if err := (types.MCPServerManifest{Config: manifest.SystemMCPServerManifest.Config}).ValidateConfig(); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("python3", script, "--port", fmt.Sprint(port))
	cmd.Env = append(os.Environ(), "ISMALICIOUS_API_KEY=native-dummy-key", "ISMALICIOUS_API_SECRET=native-dummy-secret", "ISMALICIOUS_GATE_BASE="+gate.URL, "ISMALICIOUS_TEST_HTTP=1", "ISMALICIOUS_FILTER_TOKEN=native-filter-token")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	endpoint := fmt.Sprintf("http://127.0.0.1:%d/mcp", port)
	deadline := time.Now().Add(10 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		if err == nil {
			_ = conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("filter did not start")
		}
		time.Sleep(50 * time.Millisecond)
	}
	client := gomcp.NewClient(&gomcp.Implementation{Name: "obot-native-filter-validation", Version: "test"}, nil)
	session, err := client.Connect(t.Context(), &gomcp.StreamableClientTransport{Endpoint: endpoint, HTTPClient: &http.Client{Transport: ismaliciousAuthTransport{}, Timeout: 20 * time.Second}, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	runner := &ismaliciousNativeRunner{session: session}
	hooks := mcp.Hooks{{Name: "tools/call", Params: map[string]string{"name": "fetch"}, Targets: []mcp.HookTarget{{Target: "filter/ismalicious_filter"}}}}
	requestBody := `{"jsonrpc":"2.0","id":77,"method":"tools/call","params":{"name":"fetch","arguments":{"url":"https://example.com/a?x=1,2#f"}}}`
	t.Run("blocked request never reaches actual upstream", func(t *testing.T) {
		verdict.Store("block")
		var upstreamCalls atomic.Int32
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { upstreamCalls.Add(1); w.WriteHeader(200) }))
		defer upstream.Close()
		upstreamURL, _ := url.Parse(upstream.URL)
		gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			processor, err := newHookProcessor(r, runner, hooks, nil, nil, nil)
			if err != nil {
				t.Error(err)
				w.WriteHeader(500)
				return
			}
			body, blocked, _ := processor.blockedRequest()
			if blocked {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(body)
				return
			}
			proxy := httputil.NewSingleHostReverseProxy(upstreamURL)
			proxy.ModifyResponse = processor.filterResponse
			proxy.ServeHTTP(w, r)
		}))
		defer gateway.Close()
		response, err := http.Post(gateway.URL, "application/json", strings.NewReader(requestBody))
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if upstreamCalls.Load() != 0 || !strings.Contains(string(data), "error") {
			t.Fatal("blocked request reached upstream")
		}
	})
	for _, transport := range []string{"json", "sse"} {
		t.Run(transport+" actual proxy suppresses blocked upstream content", func(t *testing.T) {
			verdict.Store("allow")
			var upstreamCalls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamCalls.Add(1)
				verdict.Store("block")
				body := `{"jsonrpc":"2.0","id":77,"result":{"content":[{"type":"text","text":"ACTUAL_BLOCKED_SENTINEL"}],"structuredContent":{"nested":"ACTUAL_NESTED_SENTINEL"}}}`
				if transport == "sse" {
					w.Header().Set("Content-Type", "text/event-stream")
					_, _ = io.WriteString(w, "event: message\ndata: "+body+"\n\n")
				} else {
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, body)
				}
			}))
			defer upstream.Close()
			upstreamURL, _ := url.Parse(upstream.URL)
			gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				processor, err := newHookProcessor(r, runner, hooks, nil, nil, nil)
				if err != nil {
					t.Error(err)
					w.WriteHeader(500)
					return
				}
				body, blocked, _ := processor.blockedRequest()
				if blocked {
					_, _ = w.Write(body)
					return
				}
				proxy := httputil.NewSingleHostReverseProxy(upstreamURL)
				proxy.ModifyResponse = processor.filterResponse
				proxy.ServeHTTP(w, r)
			}))
			defer gateway.Close()
			response, err := http.Post(gateway.URL, "application/json", strings.NewReader(requestBody))
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if upstreamCalls.Load() != 1 || strings.Contains(string(data), "ACTUAL_BLOCKED_SENTINEL") || strings.Contains(string(data), "ACTUAL_NESTED_SENTINEL") || !strings.Contains(string(data), "error") {
				t.Fatalf("content escaped actual proxy: %s", data)
			}
		})
	}

	for _, transport := range []string{"json", "sse"} {
		t.Run(transport+" blocked response removed", func(t *testing.T) {
			verdict.Store("allow")
			processor, err := newHookProcessor(mustMCPHookRequest(t, requestBody), runner, hooks, nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			verdict.Store("block")
			body := `{"jsonrpc":"2.0","id":77,"result":{"content":[{"type":"text","text":"BLOCKED_CONTENT_SENTINEL"}],"structuredContent":{"nested":"BLOCKED_NESTED_SENTINEL"}}}`
			response := mcpHookResponse(body)
			if transport == "sse" {
				response.Header.Set("Content-Type", "text/event-stream")
				response.Body = io.NopCloser(strings.NewReader("event: message\ndata: " + body + "\n\n"))
			}
			if err := processor.filterResponse(response); err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), "BLOCKED_CONTENT_SENTINEL") || strings.Contains(string(data), "BLOCKED_NESTED_SENTINEL") || !strings.Contains(string(data), "error") {
				t.Fatalf("content escaped filter: %s", data)
			}
		})
	}
	t.Run("allowed JSON preserved exactly", func(t *testing.T) {
		verdict.Store("allow")
		processor, err := newHookProcessor(mustMCPHookRequest(t, requestBody), runner, hooks, nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		body := `{"jsonrpc":"2.0","id":77,"result":{"content":[{"type":"text","text":"original content"}],"structuredContent":{"n":42}}}`
		response := mcpHookResponse(body)
		if err := processor.filterResponse(response); err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != body {
			t.Fatalf("allow mutated output: %s", data)
		}
	})
}
