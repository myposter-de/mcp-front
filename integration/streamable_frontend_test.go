package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStreamableFrontendIntegration tests the Streamable HTTP endpoint (/<name>/mcp)
// mcp-front serves for backends behind its own session frontend (stdio, reexposeSSE)
func TestStreamableFrontendIntegration(t *testing.T) {
	startMCPFront(t, "config/config.streamable-frontend-test.json")
	waitForMCPFront(t)

	backends := []struct {
		server, tool string
		args         map[string]any
		want         string
	}{
		{"test-reexpose", "echo_streamable", map[string]any{"text": "hello"}, "hello"},
		{"postgres", "execute_sql", map[string]any{"sql": "SELECT COUNT(*) as user_count FROM users"}, "user_count"},
	}

	for _, b := range backends {
		t.Run(b.server, func(t *testing.T) {
			url := "http://localhost:8080/" + b.server + "/mcp"
			token := "streamable-frontend-token"
			sessionID := streamableInitialize(t, url, token)

			t.Run("lists backend tools", func(t *testing.T) {
				resp, out := streamableSend(t, url, token, http.MethodPost, sessionID, map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
				require.Equal(t, http.StatusOK, resp.StatusCode)
				require.Contains(t, out, "result")
				var names []string
				for _, tool := range out["result"].(map[string]any)["tools"].([]any) {
					names = append(names, tool.(map[string]any)["name"].(string))
				}
				assert.Contains(t, names, b.tool)
			})

			t.Run("calls a backend tool", func(t *testing.T) {
				resp, out := streamableSend(t, url, token, http.MethodPost, sessionID, map[string]any{
					"jsonrpc": "2.0", "id": 3, "method": "tools/call",
					"params": map[string]any{"name": b.tool, "arguments": b.args},
				})
				require.Equal(t, http.StatusOK, resp.StatusCode)
				require.Contains(t, out, "result")
				raw, _ := json.Marshal(out["result"])
				assert.Contains(t, string(raw), b.want)
			})

			t.Run("rejects unknown sessions with 404", func(t *testing.T) {
				resp, _ := streamableSend(t, url, token, http.MethodPost, "mcp-session-00000000-0000-0000-0000-000000000000", map[string]any{"jsonrpc": "2.0", "id": 4, "method": "tools/list"})
				assert.Equal(t, http.StatusNotFound, resp.StatusCode)
			})

			t.Run("GET is not offered", func(t *testing.T) {
				resp, _ := streamableSend(t, url, token, http.MethodGet, "", nil)
				assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
			})

			t.Run("DELETE ends the session", func(t *testing.T) {
				resp, _ := streamableSend(t, url, token, http.MethodDelete, sessionID, nil)
				assert.Equal(t, http.StatusOK, resp.StatusCode)

				resp, _ = streamableSend(t, url, token, http.MethodPost, sessionID, map[string]any{"jsonrpc": "2.0", "id": 5, "method": "tools/list"})
				assert.Equal(t, http.StatusNotFound, resp.StatusCode)
			})
		})
	}
}

// streamableInitialize runs the initialize handshake and returns the session ID
func streamableInitialize(t *testing.T, url, token string) string {
	t.Helper()
	resp, out := streamableSend(t, url, token, http.MethodPost, "", map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]any{
			"protocolVersion": "2025-06-18",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "test", "version": "1.0"},
		},
	})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, out, "result")
	sessionID := resp.Header.Get("Mcp-Session-Id")
	require.NotEmpty(t, sessionID, "initialize must return a session ID")

	resp, _ = streamableSend(t, url, token, http.MethodPost, sessionID, map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	require.Equal(t, http.StatusAccepted, resp.StatusCode)
	return sessionID
}

// streamableSend sends one Streamable HTTP request and decodes a JSON response body
func streamableSend(t *testing.T, url, token, method, sessionID string, msg map[string]any) (*http.Response, map[string]any) {
	t.Helper()
	var body []byte
	if msg != nil {
		var err error
		body, err = json.Marshal(msg)
		require.NoError(t, err)
	}
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+token)
	if sessionID != "" {
		req.Header.Set("Mcp-Session-Id", sessionID)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp, out
}
