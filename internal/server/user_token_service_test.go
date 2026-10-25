package server

import (
	"testing"

	"github.com/stainless-api/mcp-front/internal/config"
	"github.com/stainless-api/mcp-front/internal/storage"
	"github.com/stretchr/testify/assert"
)

func TestFormatUserTokenRefreshToken(t *testing.T) {
	stored := &storage.StoredToken{
		Type:      storage.TokenTypeOAuth,
		OAuthData: &storage.OAuthTokenData{AccessToken: "access", RefreshToken: "refresh"},
	}

	assert.Equal(t, "refresh", formatUserToken(stored, &config.UserAuthentication{TokenFormat: "{{refreshToken}}"}))
	assert.Equal(t, "Bearer access", formatUserToken(stored, &config.UserAuthentication{TokenFormat: "Bearer {{token}}"}))
}
