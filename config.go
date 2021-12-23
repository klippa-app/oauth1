package oauth1

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	oauthTokenSecretParam       = "oauth_token_secret"
	oauthCallbackConfirmedParam = "oauth_callback_confirmed"

	// Source: https://github.com/mrjones/oauth/blob/master/oauth.go
	SessionHandleParam          = "oauth_session_handle"
	ExpiresInParam              = "oauth_expires_in"
	AuthorizationExpiresInParam = "oauth_authorization_expires_in"
)

// Config represents an OAuth1 consumer's (client's) key and secret, the
// callback URL, and the provider Endpoint to which the consumer corresponds.
type Config struct {
	// Consumer Key (Client Identifier)
	ConsumerKey string
	// Consumer Secret (Client Shared-Secret)
	ConsumerSecret string
	// Callback URL
	CallbackURL string
	// Provider Endpoint specifying OAuth1 endpoint URLs
	Endpoint Endpoint
	// Realm of authorization
	Realm string
	// OAuth1 Signer (defaults to HMAC-SHA1)
	Signer Signer
	// Noncer creates request nonces (defaults to DefaultNoncer)
	Noncer Noncer
	// HTTPClient overrides the choice of http.DefaultClient for RequestToken and AccessToken
	HTTPClient *http.Client
	// Call function with new token when the old token refreshes
	OAuth10aTokenNotifyFunc *func(*Token)
}

// NewConfig returns a new Config with the given consumer key and secret.
func NewConfig(consumerKey, consumerSecret string) *Config {
	return &Config{
		ConsumerKey:    consumerKey,
		ConsumerSecret: consumerSecret,
	}
}

// Client returns an HTTP client which uses the provided ctx and access Token.
func (c *Config) Client(ctx context.Context, t *Token) *http.Client {
	return NewClient(ctx, c, t)
}

// NewClient returns a new http Client which signs requests via OAuth1.
func NewClient(ctx context.Context, config *Config, token *Token) *http.Client {
	transport := &Transport{
		Base:   contextTransport(ctx),
		source: StaticTokenSource(token, config),
		auther: newAuther(config),
	}
	return &http.Client{Transport: transport}
}

// RequestToken obtains a Request token and secret (temporary credential) by
// POSTing a request (with oauth_callback in the auth header) to the Endpoint
// RequestTokenURL. The response body form is validated to ensure
// oauth_callback_confirmed is true. Returns the request token and secret
// (temporary credentials). The extraParams parameter can be used to add extra
// parameters (in addition to the standard OAuth parameters) to the Auth header.
// See RFC 5849 2.1 Temporary Credentials.
func (c *Config) RequestToken(extraParams map[string]string) (requestToken, requestSecret string, err error) {
	req, err := http.NewRequest("POST", c.Endpoint.RequestTokenURL, nil)
	if err != nil {
		return "", "", err
	}
	err = newAuther(c).setRequestTokenAuthHeader(req, extraParams)
	if err != nil {
		return "", "", err
	}

	values, err := c.handleTokenRequest(req)
	if err != nil {
		return "", "", err
	}

	requestToken = values.Get(oauthTokenParam)
	requestSecret = values.Get(oauthTokenSecretParam)
	if requestToken == "" || requestSecret == "" {
		return "", "", errors.New("oauth1: Response missing oauth_token or oauth_token_secret")
	}
	if values.Get(oauthCallbackConfirmedParam) != "true" {
		return "", "", errors.New("oauth1: oauth_callback_confirmed was not true")
	}
	return requestToken, requestSecret, nil
}

// AuthorizationURL accepts a request token and returns the *url.URL to the
// Endpoint's authorization page that asks the user (resource owner) for to
// authorize the consumer to act on his/her/its behalf.
// See RFC 5849 2.2 Resource Owner Authorization.
func (c *Config) AuthorizationURL(requestToken string) (*url.URL, error) {
	authorizationURL, err := url.Parse(c.Endpoint.AuthorizeURL)
	if err != nil {
		return nil, err
	}
	values := authorizationURL.Query()
	values.Add(oauthTokenParam, requestToken)
	authorizationURL.RawQuery = values.Encode()
	return authorizationURL, nil
}

// ParseAuthorizationCallback parses an OAuth1 authorization callback request
// from a provider server. The oauth_token and oauth_verifier parameters are
// parsed to return the request token from earlier in the flow and the
// verifier string.
// See RFC 5849 2.2 Resource Owner Authorization.
func ParseAuthorizationCallback(req *http.Request) (requestToken, verifier string, err error) {
	// parse the raw query from the URL into req.Form
	err = req.ParseForm()
	if err != nil {
		return "", "", err
	}
	requestToken = req.Form.Get(oauthTokenParam)
	verifier = req.Form.Get(oauthVerifierParam)
	if requestToken == "" || verifier == "" {
		return "", "", errors.New("oauth1: Request missing oauth_token or oauth_verifier")
	}
	return requestToken, verifier, nil
}

// AccessToken obtains an access token (token credential) by POSTing a
// request (with oauth_token and oauth_verifier in the auth header) to the
// Endpoint AccessTokenURL. Returns the access token and secret (token
// credentials). The extraParams parameter can be used to add extra
// parameters (in addition to the standard OAuth parameters) to the Auth header.
// See RFC 5849 2.3 Token Credentials.
func (c *Config) AccessToken(requestToken, requestSecret, verifier string, extraParams map[string]string) (token *Token, err error) {
	req, err := http.NewRequest("POST", c.Endpoint.AccessTokenURL, nil)
	if err != nil {
		return nil, err
	}
	err = newAuther(c).setAccessTokenAuthHeader(req, requestToken, requestSecret, verifier, extraParams)
	if err != nil {
		return nil, err
	}

	values, err := c.handleTokenRequest(req)
	if err != nil {
		return nil, err
	}

	accessToken := values.Get(oauthTokenParam)
	accessSecret := values.Get(oauthTokenSecretParam)
	if accessToken == "" || accessSecret == "" {
		return nil, errors.New("oauth1: Response missing oauth_token or oauth_token_secret")
	}

	return &Token{
		Token:       accessToken,
		TokenSecret: accessSecret,
		refreshData: parseTokenRefreshDataFromAccessTokenResponse(values),
		Realm:       c.Realm,
	}, nil
}

func (c *Config) RefreshToken(expiredToken Token) (refreshedToken *Token, err error) {
	refreshTokenUrl := c.Endpoint.AccessTokenURL
	if c.Endpoint.RefreshTokenUrl != "" {
		refreshTokenUrl = c.Endpoint.RefreshTokenUrl
	}

	req, err := http.NewRequest("POST", refreshTokenUrl, nil)
	if err != nil {
		return nil, err
	}
	err = newAuther(c).setRefreshAccessTokenAuthHeader(req, expiredToken)
	if err != nil {
		return nil, err
	}

	values, err := c.handleTokenRequest(req)
	if err != nil {
		return nil, err
	}

	accessToken := values.Get(oauthTokenParam)
	accessSecret := values.Get(oauthTokenSecretParam)
	if accessToken == "" || accessSecret == "" {
		return nil, errors.New("oauth1: Response missing oauth_token or oauth_token_secret")
	}

	refreshedToken = &Token{
		Token:       accessToken,
		TokenSecret: accessSecret,
		refreshData: parseTokenRefreshDataFromAccessTokenResponse(values),
		Realm:       c.Realm,
	}

	// Execute the refresh function, to let external applications know a new token is used
	if c.OAuth10aTokenNotifyFunc != nil {
		(*c.OAuth10aTokenNotifyFunc)(refreshedToken)
	}

	return refreshedToken, nil
}

func (c *Config) handleTokenRequest(req *http.Request) (values url.Values, err error) {
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	// when err is nil, resp contains a non-nil resp.Body which must be closed
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("oauth1: error reading Body: %v", err)
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("oauth1: invalid status %d: %s", resp.StatusCode, body)
	}

	// ParseQuery to decode URL-encoded application/x-www-form-urlencoded body
	// TrimSpace is needed because some integrations append a newline to the body
	return url.ParseQuery(strings.TrimSpace(string(body)))
}

// This function is added for the accounting software 'Xero'
func parseTokenRefreshDataFromAccessTokenResponse(responseValues url.Values) *TokenRefreshData {
	additionData := TokenRefreshData{}

	expiresInValue := responseValues.Get(ExpiresInParam)
	if expiresInValue != "" {
		expiresInSeconds, err := strconv.ParseInt(expiresInValue, 10, 64)

		if err == nil {
			expiresInTime := time.Now().UTC().Add(time.Second * time.Duration(expiresInSeconds))
			additionData.ExpireTimestamp = &expiresInTime
		}
	}

	authorizationExpiresInValue := responseValues.Get(AuthorizationExpiresInParam)
	if authorizationExpiresInValue != "" {
		authorizationExpiresInSeconds, err := strconv.ParseInt(authorizationExpiresInValue, 10, 64)

		if err == nil {
			authorizationExpiresInTime := time.Now().UTC().Add(time.Second * time.Duration(authorizationExpiresInSeconds))
			additionData.AuthorizationExpireTimestamp = &authorizationExpiresInTime
		}
	}

	sessionHandle := responseValues.Get(SessionHandleParam)
	if sessionHandle != "" {
		additionData.SessionHandle = sessionHandle
	}

	if additionData.SessionHandle == "" || additionData.ExpireTimestamp == nil || additionData.AuthorizationExpireTimestamp == nil {
		return nil
	}

	return &additionData
}

func (c *Config) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}
