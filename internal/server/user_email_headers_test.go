package server

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stainless-api/mcp-front/internal/config"
	"github.com/stainless-api/mcp-front/internal/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type seenHeaders struct {
	email, auth, cookie string
}

func recordingBackend(t *testing.T) (*httptest.Server, func() []seenHeaders) {
	t.Helper()
	var mu sync.Mutex
	var seen []seenHeaders
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, seenHeaders{
			email:  r.Header.Get("X-MCP-User-Email"),
			auth:   r.Header.Get("Authorization"),
			cookie: r.Header.Get("Cookie"),
		})
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	t.Cleanup(srv.Close)
	return srv, func() []seenHeaders {
		mu.Lock()
		defer mu.Unlock()
		return append([]seenHeaders(nil), seen...)
	}
}

func userEmailConfig(url string, transport config.MCPClientType) *config.MCPClientConfig {
	return &config.MCPClientConfig{
		TransportType: transport,
		URL:           url,
		Timeout:       5 * time.Second,
		Headers: map[string]string{
			"Authorization":    "Bearer service-key",
			"X-MCP-User-Email": "{{userEmail}}",
		},
	}
}

func serve(h *MCPHandler, method, path, email string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	if email != "" {
		req = req.WithContext(context.WithValue(req.Context(), oauth.GetUserContextKey(), email))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestUserEmailHeaderReachesBackendPerUser(t *testing.T) {
	cases := []struct {
		name      string
		transport config.MCPClientType
		path      string
		urlSuffix string
	}{
		{"streamable POST", config.MCPClientTypeStreamable, "/svc/mcp", ""},
		{"sse message passthrough", config.MCPClientTypeSSE, "/svc/message", "/sse"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			backend, seen := recordingBackend(t)
			h := createTestMCPHandler("svc", userEmailConfig(backend.URL+tc.urlSuffix, tc.transport))

			var wg sync.WaitGroup
			users := []string{"alice@example.com", "bob@example.com"}
			for i := 0; i < 40; i++ {
				wg.Add(1)
				go func(email string) {
					defer wg.Done()
					rec := serve(h, http.MethodPost, tc.path, email, nil)
					assert.Equal(t, http.StatusOK, rec.Code)
				}(users[i%2])
			}
			wg.Wait()

			got := seen()
			require.Len(t, got, 40)
			counts := map[string]int{}
			for _, s := range got {
				counts[s.email]++
				assert.Equal(t, "Bearer service-key", s.auth)
			}
			assert.Equal(t, map[string]int{"alice@example.com": 20, "bob@example.com": 20}, counts)
		})
	}
}

func TestClientSuppliedIdentityHeadersNeverReachBackend(t *testing.T) {
	backend, seen := recordingBackend(t)
	h := createTestMCPHandler("svc", userEmailConfig(backend.URL, config.MCPClientTypeStreamable))

	serve(h, http.MethodPost, "/svc/mcp", "alice@example.com", map[string]string{
		"X-MCP-User-Email": "admin@example.com",
		"Authorization":    "Bearer attacker",
		"Cookie":           "session=abc",
	})
	rec := serve(h, http.MethodPost, "/svc/mcp", "", map[string]string{
		"X-MCP-User-Email": "admin@example.com",
		"Authorization":    "Bearer attacker",
	})
	assert.Equal(t, http.StatusUnauthorized, rec.Code, "no authenticated user: refused, nothing forwarded")

	got := seen()
	require.Len(t, got, 1)
	assert.Equal(t, seenHeaders{email: "alice@example.com", auth: "Bearer service-key"}, got[0])
}

func TestDebugLogsNeverContainConfiguredHeaderValues(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	for _, tc := range []struct {
		transport config.MCPClientType
		path      string
		suffix    string
	}{
		{config.MCPClientTypeStreamable, "/svc/mcp", ""},
		{config.MCPClientTypeSSE, "/svc/message", "/sse"},
		{config.MCPClientTypeSSE, "/svc/sse", "/sse"},
	} {
		backend, _ := recordingBackend(t)
		h := createTestMCPHandler("svc", userEmailConfig(backend.URL+tc.suffix, tc.transport))
		method := http.MethodPost
		if tc.path == "/svc/sse" {
			method = http.MethodGet
		}
		serve(h, method, tc.path, "alice@example.com", nil)
	}

	out := buf.String()
	require.Contains(t, out, "X-MCP-User-Email", "header names are still logged")
	assert.NotContains(t, out, "service-key")
}
