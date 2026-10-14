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
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mholt/acmez/v3/acme"
)

func wif01TestChallenge(issuers ...string) acme.Challenge {
	return acme.Challenge{
		Type:             acme.ChallengeTypeWIF01,
		Token:            "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0",
		KeyAuthorization: "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0.9jg46WB3rR_AHD-EBXdN7cBkH1WOu0tA3M9fm21mqTI",
		Issuers:          issuers,
	}
}

func TestWIF01SolverPayload(t *testing.T) {
	errSource := errors.New("idp unavailable")

	tests := []struct {
		name       string
		issuer     string
		chal       acme.Challenge
		sourceErr  error
		wantCalled bool
		wantErr    string
	}{
		{
			name:       "issuer accepted",
			issuer:     GitHubActionsIssuer,
			chal:       wif01TestChallenge("https://other.example", GitHubActionsIssuer),
			wantCalled: true,
		},
		{
			name:       "challenge lists no issuers",
			issuer:     GitHubActionsIssuer,
			chal:       wif01TestChallenge(),
			wantCalled: true,
		},
		{
			name:       "solver issuer unset",
			chal:       wif01TestChallenge("https://other.example"),
			wantCalled: true,
		},
		{
			name:       "issuer not accepted, no token requested",
			issuer:     GitHubActionsIssuer,
			chal:       wif01TestChallenge("https://other.example"),
			wantCalled: false,
			wantErr:    "not accepted",
		},
		{
			name:       "missing key authorization",
			chal:       acme.Challenge{Type: acme.ChallengeTypeWIF01, Token: "abc"},
			wantCalled: false,
			wantErr:    "key authorization",
		},
		{
			name:       "token source error",
			chal:       wif01TestChallenge(),
			sourceErr:  errSource,
			wantCalled: true,
			wantErr:    errSource.Error(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var called bool
			var gotAudience string
			solver := &WIF01Solver{
				Issuer: test.issuer,
				TokenSource: func(_ context.Context, audience string) (string, error) {
					called = true
					gotAudience = audience
					return "header.claims.sig", test.sourceErr
				},
			}

			payload, err := solver.Payload(context.Background(), test.chal)
			if called != test.wantCalled {
				t.Errorf("token source called = %v, want %v", called, test.wantCalled)
			}
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("Payload() error = %v, want containing %q", err, test.wantErr)
				}
				if test.sourceErr != nil && !errors.Is(err, test.sourceErr) {
					t.Errorf("Payload() error = %v, want wrapping %v", err, test.sourceErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Payload() error = %v", err)
			}
			if want := test.chal.WIF01AudienceBindingValue(); gotAudience != want {
				t.Errorf("requested audience = %q, want %q", gotAudience, want)
			}
			if want := (acme.WIF01Response{WIFToken: "header.claims.sig"}); payload != want {
				t.Errorf("Payload() = %#v, want %#v", payload, want)
			}
		})
	}
}

func TestWIF01SolverNoTokenSource(t *testing.T) {
	if _, err := (&WIF01Solver{}).Payload(context.Background(), wif01TestChallenge()); err == nil {
		t.Error("Payload() without a token source succeeded")
	}
}

func TestGitHubActionsTokenSource(t *testing.T) {
	const requestToken = "runner-request-token"
	const audience = "urn:ietf:params:acme:wif:LPsIwTo7o8BoG0-vjCyGQGBWSVIPxI-i_X336eUOQZo"

	var status int
	var body string
	var gotAuth, gotAudience, gotAPIVersion string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotAudience = r.URL.Query().Get("audience")
		gotAPIVersion = r.URL.Query().Get("api-version")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	tests := []struct {
		name       string
		requestURL string
		token      string
		status     int
		body       string
		want       string
		wantErr    string
	}{
		{
			name:       "token issued",
			requestURL: srv.URL + "/idtoken?api-version=2.0",
			token:      requestToken,
			status:     http.StatusOK,
			body:       `{"count":1,"value":"header.claims.sig"}`,
			want:       "header.claims.sig",
		},
		{
			name:    "not running in GitHub Actions",
			wantErr: "id-token: write",
		},
		{
			name:       "request token missing",
			requestURL: srv.URL + "/idtoken?api-version=2.0",
			wantErr:    "id-token: write",
		},
		{
			name:       "runner refuses",
			requestURL: srv.URL + "/idtoken?api-version=2.0",
			token:      requestToken,
			status:     http.StatusForbidden,
			body:       `{"message":"forbidden"}`,
			wantErr:    "HTTP 403",
		},
		{
			name:       "empty token",
			requestURL: srv.URL + "/idtoken?api-version=2.0",
			token:      requestToken,
			status:     http.StatusOK,
			body:       `{"count":0}`,
			wantErr:    "no token",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(gitHubActionsTokenRequestURLEnv, test.requestURL)
			t.Setenv(gitHubActionsTokenRequestTokenEnv, test.token)
			status, body = test.status, test.body
			gotAuth, gotAudience, gotAPIVersion = "", "", ""

			got, err := GitHubActionsTokenSource(srv.Client())(context.Background(), audience)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("error = %v, want containing %q", err, test.wantErr)
				}
				if strings.Contains(err.Error(), requestToken) {
					t.Errorf("error leaks the request token: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("error = %v", err)
			}
			if got != test.want {
				t.Errorf("token = %q, want %q", got, test.want)
			}
			if gotAuth != "Bearer "+requestToken {
				t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer "+requestToken)
			}
			if gotAudience != audience {
				t.Errorf("audience = %q, want %q", gotAudience, audience)
			}
			if gotAPIVersion != "2.0" {
				t.Errorf("api-version = %q, want existing query parameters preserved", gotAPIVersion)
			}
		})
	}
}
