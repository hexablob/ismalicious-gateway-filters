// SPDX-FileCopyrightText: Copyright 2026 IsMalicious
// SPDX-License-Identifier: Apache-2.0
package validating

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stacklok/toolhive/pkg/mcp"
	"github.com/stacklok/toolhive/pkg/webhook"
)

func TestIsMaliciousPublishedWebhookNativeEnforcement(t *testing.T) {
	var verdict atomic.Value
	verdict.Store("allow")
	gate := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if verdict.Load() == "429" {
			w.WriteHeader(429)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"url": r.URL.Query().Get("u"), "entity": "domain", "verdict": verdict.Load(), "sources": 0, "latency_ms": 1})
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
		t.Fatal("set ISMALICIOUS_FILTER_SCRIPT")
	}
	cmd := exec.Command("python3", script, "--port", fmt.Sprint(port))
	cmd.Env = append(os.Environ(), "ISMALICIOUS_API_KEY=native-dummy-key", "ISMALICIOUS_API_SECRET=native-dummy-secret", "ISMALICIOUS_GATE_BASE="+gate.URL, "ISMALICIOUS_TEST_HTTP=1", "ISMALICIOUS_WEBHOOK_SECRET=native-test-hmac")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	deadline := time.Now().Add(10 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		if err == nil {
			_ = conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("webhook did not start")
		}
		time.Sleep(50 * time.Millisecond)
	}
	config := webhook.Config{Name: "ismalicious", URL: fmt.Sprintf("http://127.0.0.1:%d/toolhive", port), Timeout: 20 * time.Second, FailurePolicy: webhook.FailurePolicyFail, TLSConfig: &webhook.TLSConfig{InsecureSkipVerify: true}}
	client, err := webhook.NewClient(config, webhook.TypeValidating, []byte("native-test-hmac"))
	if err != nil {
		t.Fatal(err)
	}
	middleware := createValidatingHandler([]clientExecutor{{client: client, config: config}}, "native-test", "streamable-http")
	for _, decision := range []string{"allow", "block", "warn", "429", "unknown"} {
		t.Run(decision, func(t *testing.T) {
			verdict.Store(decision)
			body := []byte(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"fetch","arguments":{"url":"https://example.com/x?a=1,2#f"}}}`)
			request := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
			called := 0
			response := httptest.NewRecorder()
			mcp.ParsingMiddleware(middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called++; w.WriteHeader(200) }))).ServeHTTP(response, request)
			if decision == "allow" {
				if called != 1 || response.Code != 200 {
					t.Fatal("allow not delivered")
				}
			} else {
				if called != 0 || response.Code != 403 {
					t.Fatalf("blocked request executed: %d calls, status %d", called, response.Code)
				}
			}
		})
	}
}
