// Copyright 2026 Matthew Holt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package acmez

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"

	"github.com/mholt/acmez/v3/acme"
)

// WIF01TokenSource obtains a WIF Token from a workload identity provider.
// The returned token MUST have the given audience as its "aud" claim and
// SHOULD have the shortest lifetime the provider permits. A new token is
// requested for every challenge; implementations MUST NOT cache, persist,
// or log tokens. draft-rasmussen-acme-wif-00 §4.3
type WIF01TokenSource func(ctx context.Context, audience string) (string, error)

// WIF01Solver solves wif-01 challenges by presenting a WIF Token whose
// audience is bound to the challenge's key authorization.
// draft-rasmussen-acme-wif-00 §4
//
// It implements Solver and Payloader.
type WIF01Solver struct {
	// Issuer is the issuer identifier of the tokens returned by TokenSource.
	// If set, and the challenge lists the issuers the server accepts, the
	// solver fails without requesting a token when Issuer is not among them.
	Issuer string

	// TokenSource obtains the WIF Token. Required.
	TokenSource WIF01TokenSource
}

// Present is a no-op; there is nothing to provision for wif-01.
func (s *WIF01Solver) Present(context.Context, acme.Challenge) error { return nil }

// CleanUp is a no-op; there is nothing to clean up for wif-01.
func (s *WIF01Solver) CleanUp(context.Context, acme.Challenge) error { return nil }

// Payload obtains a WIF Token for the challenge's Audience Binding Value and
// returns the wif-01 challenge response. draft-rasmussen-acme-wif-00 §4.3
func (s *WIF01Solver) Payload(ctx context.Context, chal acme.Challenge) (any, error) {
	if s.TokenSource == nil {
		return nil, errors.New("wif-01: no token source configured")
	}
	if s.Issuer != "" && len(chal.Issuers) > 0 && !slices.Contains(chal.Issuers, s.Issuer) {
		return nil, fmt.Errorf("wif-01: issuer %q is not accepted by the server for this challenge (accepted: %v)", s.Issuer, chal.Issuers)
	}
	if chal.KeyAuthorization == "" {
		return nil, errors.New("wif-01: challenge has no key authorization")
	}
	token, err := s.TokenSource(ctx, chal.WIF01AudienceBindingValue())
	if err != nil {
		return nil, fmt.Errorf("wif-01: obtaining token: %w", err)
	}
	return acme.WIF01Response{WIFToken: token}, nil
}

// GitHubActionsIssuer is the issuer identifier of GitHub Actions OIDC tokens.
// draft-rasmussen-acme-wif-00 Appendix A.1
const GitHubActionsIssuer = "https://token.actions.githubusercontent.com"

// Environment variables set by the GitHub Actions runner when the job has
// the "id-token: write" permission.
const (
	gitHubActionsTokenRequestURLEnv   = "ACTIONS_ID_TOKEN_REQUEST_URL"
	gitHubActionsTokenRequestTokenEnv = "ACTIONS_ID_TOKEN_REQUEST_TOKEN"
)

// GitHubActionsTokenSource returns a WIF01TokenSource that requests OIDC
// tokens from the GitHub Actions runner. The workflow job must be granted
// the "id-token: write" permission. If client is nil, http.DefaultClient
// is used. draft-rasmussen-acme-wif-00 Appendix A.1
func GitHubActionsTokenSource(client *http.Client) WIF01TokenSource {
	if client == nil {
		client = http.DefaultClient
	}
	return func(ctx context.Context, audience string) (string, error) {
		requestURL := os.Getenv(gitHubActionsTokenRequestURLEnv)
		requestToken := os.Getenv(gitHubActionsTokenRequestTokenEnv)
		if requestURL == "" || requestToken == "" {
			return "", fmt.Errorf("%s and %s must be set; is this a GitHub Actions job with 'permissions: id-token: write'?",
				gitHubActionsTokenRequestURLEnv, gitHubActionsTokenRequestTokenEnv)
		}

		// the request URL already carries query parameters (e.g. api-version)
		u, err := url.Parse(requestURL)
		if err != nil {
			return "", fmt.Errorf("parsing %s: %w", gitHubActionsTokenRequestURLEnv, err)
		}
		q := u.Query()
		q.Set("audience", audience)
		u.RawQuery = q.Encode()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("Authorization", "Bearer "+requestToken)
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return "", fmt.Errorf("requesting GitHub Actions OIDC token: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("requesting GitHub Actions OIDC token: HTTP %d", resp.StatusCode)
		}

		var body struct {
			Value string `json:"value"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
			return "", fmt.Errorf("decoding GitHub Actions OIDC token response: %w", err)
		}
		if body.Value == "" {
			return "", errors.New("GitHub Actions OIDC token response has no token")
		}
		return body.Value, nil
	}
}

// NewGitHubActionsWIF01Solver returns a wif-01 solver that presents GitHub
// Actions OIDC tokens. The workflow job must be granted the
// "id-token: write" permission.
func NewGitHubActionsWIF01Solver() *WIF01Solver {
	return &WIF01Solver{
		Issuer:      GitHubActionsIssuer,
		TokenSource: GitHubActionsTokenSource(nil),
	}
}

// Interface guards
var (
	_ Solver    = (*WIF01Solver)(nil)
	_ Payloader = (*WIF01Solver)(nil)
)
