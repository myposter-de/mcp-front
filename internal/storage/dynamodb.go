package storage

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/stainless-api/mcp-front/internal/crypto"
	"github.com/stainless-api/mcp-front/internal/idp"
	"github.com/stainless-api/mcp-front/internal/log"
	"github.com/stainless-api/mcp-front/internal/oauth"
)

// Single-table design. Partition/sort key patterns:
//
//	OAuth client:  PK=CLIENT#<id>      SK=CLIENT
//	Grant:         PK=GRANT#<code>     SK=GRANT     (+ ttl attribute for expiry)
//	User token:    PK=TOKEN#<email>    SK=SERVICE#<service>
//	Session:       PK=SESSION#<id>     SK=SESSION
const (
	dynamoPKAttr  = "PK"
	dynamoSKAttr  = "SK"
	dynamoTTLAttr = "ttl"

	clientPKPrefix  = "CLIENT#"
	grantPKPrefix   = "GRANT#"
	tokenPKPrefix   = "TOKEN#"
	sessionPKPrefix = "SESSION#"

	clientSK        = "CLIENT"
	grantSK         = "GRANT"
	sessionSK       = "SESSION"
	servicePKPrefix = "SERVICE#"
)

type DynamoDBStorage struct {
	client       *dynamodb.Client
	table        string
	encryptor    crypto.Encryptor
	clients      map[string]*Client
	clientsMutex sync.RWMutex
}

var _ Storage = (*DynamoDBStorage)(nil)

type dynamoClientItem struct {
	PK            string   `dynamodbav:"PK"`
	SK            string   `dynamodbav:"SK"`
	ID            string   `dynamodbav:"id"`
	Secret        *string  `dynamodbav:"secret,omitempty"`
	RedirectURIs  []string `dynamodbav:"redirect_uris"`
	Scopes        []string `dynamodbav:"scopes"`
	GrantTypes    []string `dynamodbav:"grant_types"`
	ResponseTypes []string `dynamodbav:"response_types"`
	Audience      []string `dynamodbav:"audience"`
	Public        bool     `dynamodbav:"public"`
	CreatedAt     int64    `dynamodbav:"created_at"`
}

type dynamoGrantItem struct {
	PK            string    `dynamodbav:"PK"`
	SK            string    `dynamodbav:"SK"`
	Code          string    `dynamodbav:"code"`
	ClientID      string    `dynamodbav:"client_id"`
	RedirectURI   string    `dynamodbav:"redirect_uri"`
	Identity      []byte    `dynamodbav:"identity"`
	Scopes        []string  `dynamodbav:"scopes"`
	Audience      []string  `dynamodbav:"audience"`
	PKCEChallenge string    `dynamodbav:"pkce_challenge"`
	CreatedAt     time.Time `dynamodbav:"created_at,unixtime"`
	ExpiresAt     time.Time `dynamodbav:"expires_at,unixtime"`
	TTL           int64     `dynamodbav:"ttl"`
}

type dynamoTokenItem struct {
	PK        string          `dynamodbav:"PK"`
	SK        string          `dynamodbav:"SK"`
	UserEmail string          `dynamodbav:"user_email"`
	Service   string          `dynamodbav:"service"`
	Type      TokenType       `dynamodbav:"type"`
	Value     string          `dynamodbav:"value,omitempty"`
	OAuthData *OAuthTokenData `dynamodbav:"oauth_data,omitempty"`
	UpdatedAt time.Time       `dynamodbav:"updated_at,unixtime"`
}

type dynamoSessionItem struct {
	PK         string    `dynamodbav:"PK"`
	SK         string    `dynamodbav:"SK"`
	SessionID  string    `dynamodbav:"session_id"`
	UserEmail  string    `dynamodbav:"user_email"`
	ServerName string    `dynamodbav:"server_name"`
	Created    time.Time `dynamodbav:"created,unixtime"`
	LastActive time.Time `dynamodbav:"last_active,unixtime"`
}

func NewDynamoDBStorage(ctx context.Context, table, region, endpoint string, encryptor crypto.Encryptor) (*DynamoDBStorage, error) {
	if encryptor == nil {
		return nil, fmt.Errorf("encryptor is required")
	}
	if table == "" {
		return nil, fmt.Errorf("table is required")
	}

	var optFns []func(*awsconfig.LoadOptions) error
	if region != "" {
		optFns = append(optFns, awsconfig.WithRegion(region))
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, optFns...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) {
		if endpoint != "" {
			o.BaseEndpoint = aws.String(endpoint)
		}
	})

	return &DynamoDBStorage{
		client:    client,
		table:     table,
		encryptor: encryptor,
		clients:   make(map[string]*Client),
	}, nil
}

func (s *DynamoDBStorage) key(pk, sk string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		dynamoPKAttr: &types.AttributeValueMemberS{Value: pk},
		dynamoSKAttr: &types.AttributeValueMemberS{Value: sk},
	}
}

// OAuth client management

func (s *DynamoDBStorage) clientToItem(client *Client) (*dynamoClientItem, error) {
	var secret *string
	if len(client.Secret) > 0 {
		encrypted, err := s.encryptor.Encrypt(string(client.Secret))
		if err != nil {
			return nil, fmt.Errorf("encrypting client secret: %w", err)
		}
		secret = &encrypted
	}

	return &dynamoClientItem{
		PK:            clientPKPrefix + client.ID,
		SK:            clientSK,
		ID:            client.ID,
		Secret:        secret,
		RedirectURIs:  client.RedirectURIs,
		Scopes:        client.Scopes,
		GrantTypes:    client.GrantTypes,
		ResponseTypes: client.ResponseTypes,
		Audience:      client.Audience,
		Public:        client.Public,
		CreatedAt:     client.CreatedAt,
	}, nil
}

func (s *DynamoDBStorage) itemToClient(item *dynamoClientItem) (*Client, error) {
	var secret []byte
	if item.Secret != nil {
		decrypted, err := s.encryptor.Decrypt(*item.Secret)
		if err != nil {
			return nil, fmt.Errorf("decrypting client secret: %w", err)
		}
		secret = []byte(decrypted)
	}

	return &Client{
		ID:            item.ID,
		Secret:        secret,
		RedirectURIs:  item.RedirectURIs,
		Scopes:        item.Scopes,
		GrantTypes:    item.GrantTypes,
		ResponseTypes: item.ResponseTypes,
		Audience:      item.Audience,
		Public:        item.Public,
		CreatedAt:     item.CreatedAt,
	}, nil
}

func (s *DynamoDBStorage) GetClient(ctx context.Context, id string) (*Client, error) {
	s.clientsMutex.RLock()
	client, ok := s.clients[id]
	s.clientsMutex.RUnlock()

	if ok {
		return client, nil
	}

	out, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.table),
		Key:       s.key(clientPKPrefix+id, clientSK),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get client from DynamoDB: %w", err)
	}
	if out.Item == nil {
		return nil, ErrClientNotFound
	}

	var item dynamoClientItem
	if err := attributevalue.UnmarshalMap(out.Item, &item); err != nil {
		return nil, fmt.Errorf("failed to unmarshal client: %w", err)
	}

	client, err = s.itemToClient(&item)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt client secret: %w", err)
	}

	s.clientsMutex.Lock()
	s.clients[id] = client
	s.clientsMutex.Unlock()

	return client, nil
}

func (s *DynamoDBStorage) storeClient(ctx context.Context, client *Client) error {
	item, err := s.clientToItem(client)
	if err != nil {
		log.LogError("Failed to encrypt client for DynamoDB (client_id: %s): %v", client.ID, err)
		return fmt.Errorf("failed to encrypt client: %w", err)
	}

	av, err := attributevalue.MarshalMap(item)
	if err != nil {
		return fmt.Errorf("failed to marshal client: %w", err)
	}

	if _, err := s.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(s.table),
		Item:      av,
	}); err != nil {
		log.LogError("Failed to store client in DynamoDB (client_id: %s): %v", client.ID, err)
		return fmt.Errorf("failed to store client in DynamoDB: %w", err)
	}

	s.clientsMutex.Lock()
	s.clients[client.ID] = client
	s.clientsMutex.Unlock()

	return nil
}

func (s *DynamoDBStorage) CreateClient(ctx context.Context, clientID string, redirectURIs []string, scopes []string, issuer string) (*Client, error) {
	client := &Client{
		ID:            clientID,
		Secret:        nil,
		RedirectURIs:  redirectURIs,
		Scopes:        scopes,
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code"},
		Audience:      []string{issuer},
		Public:        true,
		CreatedAt:     time.Now().Unix(),
	}

	if err := s.storeClient(ctx, client); err != nil {
		return nil, err
	}

	log.Logf("Created client %s, redirect_uris: %v, scopes: %v", clientID, redirectURIs, scopes)
	return client, nil
}

func (s *DynamoDBStorage) CreateConfidentialClient(ctx context.Context, clientID string, hashedSecret []byte, redirectURIs []string, scopes []string, issuer string) (*Client, error) {
	client := &Client{
		ID:            clientID,
		Secret:        hashedSecret,
		RedirectURIs:  redirectURIs,
		Scopes:        scopes,
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code"},
		Audience:      []string{issuer},
		Public:        false,
		CreatedAt:     time.Now().Unix(),
	}

	if err := s.storeClient(ctx, client); err != nil {
		return nil, err
	}

	log.Logf("Created confidential client %s, redirect_uris: %v, scopes: %v", clientID, redirectURIs, scopes)
	return client, nil
}

// Grant management

func (s *DynamoDBStorage) StoreGrant(ctx context.Context, code string, grant *oauth.Grant) error {
	identityJSON, err := encodeJSON(grant.Identity)
	if err != nil {
		return fmt.Errorf("failed to encode identity: %w", err)
	}

	item := dynamoGrantItem{
		PK:            grantPKPrefix + code,
		SK:            grantSK,
		Code:          code,
		ClientID:      grant.ClientID,
		RedirectURI:   grant.RedirectURI,
		Identity:      identityJSON,
		Scopes:        grant.Scopes,
		Audience:      grant.Audience,
		PKCEChallenge: grant.PKCEChallenge,
		CreatedAt:     grant.CreatedAt,
		ExpiresAt:     grant.ExpiresAt,
		TTL:           grant.ExpiresAt.Unix(),
	}

	av, err := attributevalue.MarshalMap(item)
	if err != nil {
		return fmt.Errorf("failed to marshal grant: %w", err)
	}

	if _, err := s.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(s.table),
		Item:      av,
	}); err != nil {
		return fmt.Errorf("failed to store grant in DynamoDB: %w", err)
	}
	return nil
}

func (s *DynamoDBStorage) ConsumeGrant(ctx context.Context, code string) (*oauth.Grant, error) {
	// Atomic one-time consume: delete and return the old item in a single call.
	out, err := s.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName:    aws.String(s.table),
		Key:          s.key(grantPKPrefix+code, grantSK),
		ReturnValues: types.ReturnValueAllOld,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to consume grant from DynamoDB: %w", err)
	}
	if len(out.Attributes) == 0 {
		return nil, ErrGrantNotFound
	}

	var item dynamoGrantItem
	if err := attributevalue.UnmarshalMap(out.Attributes, &item); err != nil {
		return nil, fmt.Errorf("failed to unmarshal grant: %w", err)
	}

	var identity idp.Identity
	if err := decodeJSON(item.Identity, &identity); err != nil {
		return nil, fmt.Errorf("failed to decode identity: %w", err)
	}

	return &oauth.Grant{
		Code:          item.Code,
		ClientID:      item.ClientID,
		RedirectURI:   item.RedirectURI,
		Identity:      identity,
		Scopes:        item.Scopes,
		Audience:      item.Audience,
		PKCEChallenge: item.PKCEChallenge,
		CreatedAt:     item.CreatedAt,
		ExpiresAt:     item.ExpiresAt,
	}, nil
}

// User token methods

func (s *DynamoDBStorage) GetUserToken(ctx context.Context, userEmail, service string) (*StoredToken, error) {
	out, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.table),
		Key:       s.key(tokenPKPrefix+userEmail, servicePKPrefix+service),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get token from DynamoDB: %w", err)
	}
	if out.Item == nil {
		return nil, ErrUserTokenNotFound
	}

	var item dynamoTokenItem
	if err := attributevalue.UnmarshalMap(out.Item, &item); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token: %w", err)
	}

	storedToken := &StoredToken{
		Type:      item.Type,
		UpdatedAt: item.UpdatedAt,
	}

	switch item.Type {
	case TokenTypeManual:
		if item.Value != "" {
			decrypted, err := s.encryptor.Decrypt(item.Value)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt manual token: %w", err)
			}
			storedToken.Value = decrypted
		}
	case TokenTypeOAuth:
		if item.OAuthData != nil {
			decryptedAccess, err := s.encryptor.Decrypt(item.OAuthData.AccessToken)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt access token: %w", err)
			}

			oauthData := &OAuthTokenData{
				AccessToken: decryptedAccess,
				TokenType:   item.OAuthData.TokenType,
				ExpiresAt:   item.OAuthData.ExpiresAt,
				Scopes:      item.OAuthData.Scopes,
			}

			if item.OAuthData.RefreshToken != "" {
				decryptedRefresh, err := s.encryptor.Decrypt(item.OAuthData.RefreshToken)
				if err != nil {
					return nil, fmt.Errorf("failed to decrypt refresh token: %w", err)
				}
				oauthData.RefreshToken = decryptedRefresh
			}

			storedToken.OAuthData = oauthData
		}
	}

	return storedToken, nil
}

func (s *DynamoDBStorage) SetUserToken(ctx context.Context, userEmail, service string, token *StoredToken) error {
	if token == nil {
		return fmt.Errorf("token cannot be nil")
	}

	item := dynamoTokenItem{
		PK:        tokenPKPrefix + userEmail,
		SK:        servicePKPrefix + service,
		UserEmail: userEmail,
		Service:   service,
		Type:      token.Type,
		UpdatedAt: time.Now(),
	}

	switch token.Type {
	case TokenTypeManual:
		if token.Value != "" {
			encrypted, err := s.encryptor.Encrypt(token.Value)
			if err != nil {
				return fmt.Errorf("failed to encrypt manual token: %w", err)
			}
			item.Value = encrypted
		}
	case TokenTypeOAuth:
		if token.OAuthData != nil {
			encryptedAccess, err := s.encryptor.Encrypt(token.OAuthData.AccessToken)
			if err != nil {
				return fmt.Errorf("failed to encrypt access token: %w", err)
			}

			oauthData := &OAuthTokenData{
				AccessToken: encryptedAccess,
				TokenType:   token.OAuthData.TokenType,
				ExpiresAt:   token.OAuthData.ExpiresAt,
				Scopes:      token.OAuthData.Scopes,
			}

			if token.OAuthData.RefreshToken != "" {
				encryptedRefresh, err := s.encryptor.Encrypt(token.OAuthData.RefreshToken)
				if err != nil {
					return fmt.Errorf("failed to encrypt refresh token: %w", err)
				}
				oauthData.RefreshToken = encryptedRefresh
			}

			item.OAuthData = oauthData
		}
	default:
		return fmt.Errorf("unknown token type: %s", token.Type)
	}

	av, err := attributevalue.MarshalMap(item)
	if err != nil {
		return fmt.Errorf("failed to marshal token: %w", err)
	}

	if _, err := s.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(s.table),
		Item:      av,
	}); err != nil {
		return fmt.Errorf("failed to store token in DynamoDB: %w", err)
	}

	return nil
}

func (s *DynamoDBStorage) DeleteUserToken(ctx context.Context, userEmail, service string) error {
	if _, err := s.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(s.table),
		Key:       s.key(tokenPKPrefix+userEmail, servicePKPrefix+service),
	}); err != nil {
		return fmt.Errorf("failed to delete token from DynamoDB: %w", err)
	}
	return nil
}

func (s *DynamoDBStorage) ListUserServices(ctx context.Context, userEmail string) ([]string, error) {
	var services []string
	var lastKey map[string]types.AttributeValue

	for {
		out, err := s.client.Query(ctx, &dynamodb.QueryInput{
			TableName:              aws.String(s.table),
			KeyConditionExpression: aws.String("#pk = :pk"),
			ExpressionAttributeNames: map[string]string{
				"#pk": dynamoPKAttr,
			},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":pk": &types.AttributeValueMemberS{Value: tokenPKPrefix + userEmail},
			},
			ExclusiveStartKey: lastKey,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to query user tokens: %w", err)
		}

		for _, av := range out.Items {
			var item dynamoTokenItem
			if err := attributevalue.UnmarshalMap(av, &item); err != nil {
				log.LogError("Failed to unmarshal user token: %v", err)
				continue
			}
			services = append(services, item.Service)
		}

		if out.LastEvaluatedKey == nil {
			break
		}
		lastKey = out.LastEvaluatedKey
	}

	return services, nil
}

// Session tracking

func (s *DynamoDBStorage) TrackSession(ctx context.Context, session ActiveSession) error {
	now := time.Now()
	if session.Created.IsZero() {
		session.Created = now
	}

	item := dynamoSessionItem{
		PK:         sessionPKPrefix + session.SessionID,
		SK:         sessionSK,
		SessionID:  session.SessionID,
		UserEmail:  session.UserEmail,
		ServerName: session.ServerName,
		Created:    session.Created,
		LastActive: now,
	}

	av, err := attributevalue.MarshalMap(item)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	if _, err := s.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(s.table),
		Item:      av,
	}); err != nil {
		return fmt.Errorf("failed to store session in DynamoDB: %w", err)
	}
	return nil
}

func (s *DynamoDBStorage) RevokeSession(ctx context.Context, sessionID string) error {
	if _, err := s.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(s.table),
		Key:       s.key(sessionPKPrefix+sessionID, sessionSK),
	}); err != nil {
		var notFound *types.ResourceNotFoundException
		if errors.As(err, &notFound) {
			return nil
		}
		return fmt.Errorf("failed to delete session from DynamoDB: %w", err)
	}
	return nil
}
