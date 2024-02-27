package oauth1

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

const (
	oauthUserId     = "user_id"
	oauthScreenName = "screen_name"
)

// AccessTokenInfo obtains an access token (token credential) by POSTing a
// request (with oauth_token and oauth_verifier in the auth header) to the
// Endpoint AccessTokenURL. Returns the access token and secret (token
// credentials).
// See RFC 5849 2.3 Token Credentials.
func (c *Config) AccessTokenInfo(requestToken, requestSecret, verifier string) (accessToken, accessSecret, userId, screenName string, err error) {
	req, err := http.NewRequest("POST", c.Endpoint.AccessTokenURL, nil)
	if err != nil {
		return "", "", "", "", err
	}
	err = newAuther(c).setAccessTokenAuthHeader(req, requestToken, requestSecret, verifier)
	if err != nil {
		return "", "", "", "", err
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return "", "", "", "", err
	}
	// when err is nil, resp contains a non-nil resp.Body which must be closed
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", "", "", fmt.Errorf("oauth1: error reading Body: %v", err)
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", "", "", "", fmt.Errorf("oauth1: invalid status %d: %s", resp.StatusCode, body)
	}
	//oauth_token=1522376594-UAAwMOR0zysZy5tFeEolrU8ZbkAE1OmgyaTkRU3&oauth_token_secret=8nLayDpCO5ihUKerqnYShRDHj1GhXrx6p8fWGP2rTTDj5&user_id=1522376594&screen_name=wolferhua

	// ParseQuery to decode URL-encoded application/x-www-form-urlencoded body
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return "", "", "", "", err
	}
	accessToken = values.Get(oauthTokenParam)
	accessSecret = values.Get(oauthTokenSecretParam)
	userId = values.Get(oauthUserId)
	screenName = values.Get(oauthScreenName)
	if accessToken == "" || accessSecret == "" {
		return "", "", "", "", errors.New("oauth1: Response missing oauth_token or oauth_token_secret")
	}
	return accessToken, accessSecret, userId, screenName, nil
}
