package oauth1

import (
	"errors"
	"time"
)

// A TokenSource can return a Token.
type TokenSource interface {
	Token() (*Token, error)
}

type TokenAdditionalData struct {
	ExpireTimestamp              *time.Time // When does the current access token expire?
	AuthorizationExpireTimestamp *time.Time // When is no longer possible to refresh the token?
	SessionHandle                string     // Needed for refreshing the token
}

// Token is an AccessToken (token credential) which allows a consumer (client)
// to access resources from an OAuth1 provider server.
type Token struct {
	Token          string
	TokenSecret    string
	AdditionalData *TokenAdditionalData
}

// NewToken returns a new Token with the given token and token secret.
func NewToken(token, tokenSecret string) *Token {
	return &Token{
		Token:       token,
		TokenSecret: tokenSecret,
	}
}

// StaticTokenSource returns a TokenSource which always returns the same Token.
// This is appropriate for tokens which do not have a time expiration.
func StaticTokenSource(token *Token, config *Config) TokenSource {
	return staticTokenSource{
		config: config,
		token:  token,
	}
}

// staticTokenSource is a TokenSource that always returns the same Token.
type staticTokenSource struct {
	config *Config
	token  *Token
}

func (s staticTokenSource) Token() (*Token, error) {
	if s.token == nil {
		return nil, errors.New("oauth1: Token is nil")
	}

	// If enough data is available and the token is expired, try to refresh the token
	if s.token.AdditionalData != nil && s.token.AdditionalData.SessionHandle != "" && s.token.AdditionalData.ExpireTimestamp != nil {
		// The token expires with a margin of 30 seconds, to prevent unexpected errors
		expireAfter := time.Now().UTC().Add(time.Second * 30)
		if expireAfter.After(*s.token.AdditionalData.ExpireTimestamp) {
			refreshedToken, err := s.config.RefreshToken(*s.token)

			if err != nil {
				return nil, err
			}

			s.token = refreshedToken
		}
	}

	return s.token, nil
}
