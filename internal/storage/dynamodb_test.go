package storage

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/stainless-api/mcp-front/internal/crypto"
	"github.com/stainless-api/mcp-front/internal/idp"
	"github.com/stainless-api/mcp-front/internal/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDynamoDBStorageConfig(t *testing.T) {
	t.Run("missing table", func(t *testing.T) {
		ctx := context.Background()
		encryptor, _ := crypto.NewEncryptor([]byte("test-encryption-key-32-bytes-ok!"))

		_, err := NewDynamoDBStorage(ctx, "", "", "", encryptor)
		assert.Error(t, err, "Expected error when table is missing for DynamoDB storage")
		assert.Contains(t, err.Error(), "table is required")
	})

	t.Run("nil encryptor", func(t *testing.T) {
		ctx := context.Background()

		_, err := NewDynamoDBStorage(ctx, "test-table", "", "", nil)
		assert.Error(t, err, "Expected error when encryptor is nil")
		assert.Contains(t, err.Error(), "encryptor is required")
	})
}

// newTestDynamoDBStorage connects to a dynamodb-local instance and creates a
// fresh table. Tests are skipped unless DYNAMODB_TEST_ENDPOINT is set, e.g.:
//
//	docker run --rm -p 8000:8000 amazon/dynamodb-local
//	DYNAMODB_TEST_ENDPOINT=http://localhost:8000 go test ./internal/storage/...
func newTestDynamoDBStorage(t *testing.T) *DynamoDBStorage {
	t.Helper()

	endpoint := os.Getenv("DYNAMODB_TEST_ENDPOINT")
	if endpoint == "" {
		t.Skip("DYNAMODB_TEST_ENDPOINT not set, skipping DynamoDB integration tests")
	}

	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")

	ctx := context.Background()
	encryptor, err := crypto.NewEncryptor([]byte("test-encryption-key-32-bytes-ok!"))
	require.NoError(t, err)

	table := "mcp_front_test_" + t.Name()
	store, err := NewDynamoDBStorage(ctx, table, "us-east-1", endpoint, encryptor)
	require.NoError(t, err)

	_, err = store.client.CreateTable(ctx, &dynamodb.CreateTableInput{
		TableName: aws.String(table),
		AttributeDefinitions: []types.AttributeDefinition{
			{AttributeName: aws.String(dynamoPKAttr), AttributeType: types.ScalarAttributeTypeS},
			{AttributeName: aws.String(dynamoSKAttr), AttributeType: types.ScalarAttributeTypeS},
		},
		KeySchema: []types.KeySchemaElement{
			{AttributeName: aws.String(dynamoPKAttr), KeyType: types.KeyTypeHash},
			{AttributeName: aws.String(dynamoSKAttr), KeyType: types.KeyTypeRange},
		},
		BillingMode: types.BillingModePayPerRequest,
	})
	require.NoError(t, err)

	t.Cleanup(func() {
		_, _ = store.client.DeleteTable(context.Background(), &dynamodb.DeleteTableInput{
			TableName: aws.String(table),
		})
	})

	return store
}

func TestDynamoDBStorageClients(t *testing.T) {
	store := newTestDynamoDBStorage(t)
	ctx := context.Background()

	t.Run("public client roundtrip", func(t *testing.T) {
		created, err := store.CreateClient(ctx, "public-123", []string{"https://example.com/callback"}, []string{"read"}, "https://issuer.com")
		require.NoError(t, err)
		assert.True(t, created.Public)
		assert.Nil(t, created.Secret)

		// Bypass the in-memory cache to verify persistence
		store.clientsMutex.Lock()
		delete(store.clients, "public-123")
		store.clientsMutex.Unlock()

		got, err := store.GetClient(ctx, "public-123")
		require.NoError(t, err)
		assert.Equal(t, "public-123", got.ID)
		assert.Equal(t, []string{"https://example.com/callback"}, got.RedirectURIs)
		assert.Equal(t, []string{"read"}, got.Scopes)
		assert.True(t, got.Public)
	})

	t.Run("confidential client secret is encrypted and roundtrips", func(t *testing.T) {
		hashedSecret := []byte("hashed-secret-value")
		_, err := store.CreateConfidentialClient(ctx, "confidential-123", hashedSecret, []string{"https://example.com/callback"}, []string{"read"}, "https://issuer.com")
		require.NoError(t, err)

		store.clientsMutex.Lock()
		delete(store.clients, "confidential-123")
		store.clientsMutex.Unlock()

		got, err := store.GetClient(ctx, "confidential-123")
		require.NoError(t, err)
		assert.False(t, got.Public)
		assert.Equal(t, hashedSecret, got.Secret)

		// Verify the secret is not stored in plaintext
		out, err := store.client.GetItem(ctx, &dynamodb.GetItemInput{
			TableName: aws.String(store.table),
			Key:       store.key(clientPKPrefix+"confidential-123", clientSK),
		})
		require.NoError(t, err)
		secretAttr, ok := out.Item["secret"].(*types.AttributeValueMemberS)
		require.True(t, ok)
		assert.NotEqual(t, string(hashedSecret), secretAttr.Value)
	})

	t.Run("unknown client", func(t *testing.T) {
		_, err := store.GetClient(ctx, "nonexistent")
		require.ErrorIs(t, err, ErrClientNotFound)
	})
}

func TestDynamoDBStorageGrants(t *testing.T) {
	store := newTestDynamoDBStorage(t)
	ctx := context.Background()

	grant := &oauth.Grant{
		Code:        "test-code",
		ClientID:    "client-123",
		RedirectURI: "https://example.com/callback",
		Identity: idp.Identity{
			Email:  "user@example.com",
			Domain: "example.com",
		},
		Scopes:        []string{"read", "write"},
		Audience:      []string{"https://issuer.com"},
		PKCEChallenge: "challenge-value",
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(10 * time.Minute),
	}

	t.Run("store and consume", func(t *testing.T) {
		err := store.StoreGrant(ctx, grant.Code, grant)
		require.NoError(t, err)

		consumed, err := store.ConsumeGrant(ctx, grant.Code)
		require.NoError(t, err)
		assert.Equal(t, grant.ClientID, consumed.ClientID)
		assert.Equal(t, grant.Identity.Email, consumed.Identity.Email)
		assert.Equal(t, grant.Scopes, consumed.Scopes)
		assert.Equal(t, grant.PKCEChallenge, consumed.PKCEChallenge)
	})

	t.Run("consume is one-time", func(t *testing.T) {
		err := store.StoreGrant(ctx, "one-time-code", grant)
		require.NoError(t, err)

		_, err = store.ConsumeGrant(ctx, "one-time-code")
		require.NoError(t, err)

		_, err = store.ConsumeGrant(ctx, "one-time-code")
		require.ErrorIs(t, err, ErrGrantNotFound)
	})

	t.Run("consume nonexistent grant", func(t *testing.T) {
		_, err := store.ConsumeGrant(ctx, "nonexistent")
		require.ErrorIs(t, err, ErrGrantNotFound)
	})
}

func TestDynamoDBStorageUserTokens(t *testing.T) {
	store := newTestDynamoDBStorage(t)
	ctx := context.Background()

	t.Run("manual token roundtrip", func(t *testing.T) {
		err := store.SetUserToken(ctx, "user@example.com", "harness", &StoredToken{
			Type:  TokenTypeManual,
			Value: "super-secret-api-key",
		})
		require.NoError(t, err)

		got, err := store.GetUserToken(ctx, "user@example.com", "harness")
		require.NoError(t, err)
		assert.Equal(t, TokenTypeManual, got.Type)
		assert.Equal(t, "super-secret-api-key", got.Value)
	})

	t.Run("token value is encrypted at rest", func(t *testing.T) {
		out, err := store.client.GetItem(ctx, &dynamodb.GetItemInput{
			TableName: aws.String(store.table),
			Key:       store.key(tokenPKPrefix+"user@example.com", servicePKPrefix+"harness"),
		})
		require.NoError(t, err)
		valueAttr, ok := out.Item["value"].(*types.AttributeValueMemberS)
		require.True(t, ok)
		assert.NotEqual(t, "super-secret-api-key", valueAttr.Value)
	})

	t.Run("oauth token roundtrip", func(t *testing.T) {
		expires := time.Now().Add(time.Hour)
		err := store.SetUserToken(ctx, "user@example.com", "linear", &StoredToken{
			Type: TokenTypeOAuth,
			OAuthData: &OAuthTokenData{
				AccessToken:  "access-token-value",
				RefreshToken: "refresh-token-value",
				TokenType:    "Bearer",
				ExpiresAt:    expires,
				Scopes:       []string{"read"},
			},
		})
		require.NoError(t, err)

		got, err := store.GetUserToken(ctx, "user@example.com", "linear")
		require.NoError(t, err)
		assert.Equal(t, TokenTypeOAuth, got.Type)
		require.NotNil(t, got.OAuthData)
		assert.Equal(t, "access-token-value", got.OAuthData.AccessToken)
		assert.Equal(t, "refresh-token-value", got.OAuthData.RefreshToken)
		assert.Equal(t, "Bearer", got.OAuthData.TokenType)
		assert.Equal(t, []string{"read"}, got.OAuthData.Scopes)
	})

	t.Run("list user services", func(t *testing.T) {
		services, err := store.ListUserServices(ctx, "user@example.com")
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"harness", "linear"}, services)
	})

	t.Run("list services for unknown user", func(t *testing.T) {
		services, err := store.ListUserServices(ctx, "nobody@example.com")
		require.NoError(t, err)
		assert.Empty(t, services)
	})

	t.Run("delete token", func(t *testing.T) {
		err := store.DeleteUserToken(ctx, "user@example.com", "harness")
		require.NoError(t, err)

		_, err = store.GetUserToken(ctx, "user@example.com", "harness")
		require.ErrorIs(t, err, ErrUserTokenNotFound)
	})

	t.Run("get nonexistent token", func(t *testing.T) {
		_, err := store.GetUserToken(ctx, "user@example.com", "nonexistent")
		require.ErrorIs(t, err, ErrUserTokenNotFound)
	})
}

func TestDynamoDBStorageSessions(t *testing.T) {
	store := newTestDynamoDBStorage(t)
	ctx := context.Background()

	t.Run("track and revoke session", func(t *testing.T) {
		err := store.TrackSession(ctx, ActiveSession{
			SessionID:  "sess-1",
			UserEmail:  "user@example.com",
			ServerName: "harness",
		})
		require.NoError(t, err)

		err = store.RevokeSession(ctx, "sess-1")
		require.NoError(t, err)
	})

	t.Run("revoke nonexistent session is idempotent", func(t *testing.T) {
		err := store.RevokeSession(ctx, "nonexistent")
		require.NoError(t, err)
	})
}
