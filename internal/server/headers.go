package server

import "net/http"

// copyRequestHeaders copies relevant headers from the client request to the backend request,
// excluding hop-by-hop headers (per RFC 9110), sensitive credentials and the
// per-user identity header, which only the gateway config may set.
func copyRequestHeaders(dst, src http.Header) {
	for k, v := range src {
		switch k {
		case "Connection", "Upgrade", "Host",
			"Keep-Alive", "Transfer-Encoding", "TE", "Trailer",
			"Proxy-Authorization", "Proxy-Authenticate",
			"Authorization", "Cookie",
			"X-Mcp-User-Email",
			"Accept-Encoding":
			continue
		}
		dst[k] = v
	}
}
