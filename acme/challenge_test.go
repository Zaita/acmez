// Copyright 2020 Matthew Holt
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

package acme

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestChallenge_DNSAccount01TXTRecordName(t *testing.T) {
	tests := []struct {
		name       string
		account    Account
		identifier Identifier
		expected   string
	}{
		{
			name:       "standard account location",
			account:    Account{Location: "https://acme-v02.api.letsencrypt.org/acme/acct/12345"},
			identifier: Identifier{Type: "dns", Value: "example.com"},
			expected:   "_lvrajhh53e27yh7f._acme-challenge.example.com",
		},
		{
			name:       "different account location",
			account:    Account{Location: "https://example.com/acme/account/67890"},
			identifier: Identifier{Type: "dns", Value: "test.example.org"},
			expected:   "_pbvtvcg2uxbmkni3._acme-challenge.test.example.org",
		},
		{
			name:       "empty account location",
			account:    Account{Location: ""},
			identifier: Identifier{Type: "dns", Value: "sub.domain.net"},
			expected:   "_4oymiquy7qobjgx3._acme-challenge.sub.domain.net",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := Challenge{
				Identifier: test.identifier,
			}
			got := c.DNSAccount01TXTRecordName(test.account)
			if got != test.expected {
				t.Errorf("DNSAccount01TXTRecordName() = %q, want %q", got, test.expected)
			}
		})
	}
}

func TestChallenge_DNSPersist01TXTRecordName(t *testing.T) {
	tests := []struct {
		name       string
		identifier Identifier
		expected   string
	}{
		{
			name:       "apex domain",
			identifier: Identifier{Type: "dns", Value: "example.com"},
			expected:   "_validation-persist.example.com",
		},
		{
			name:       "subdomain",
			identifier: Identifier{Type: "dns", Value: "sub.example.com"},
			expected:   "_validation-persist.sub.example.com",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := Challenge{Identifier: test.identifier}
			got := c.DNSPersist01TXTRecordName()
			if got != test.expected {
				t.Errorf("DNSPersist01TXTRecordName() = %q, want %q", got, test.expected)
			}
		})
	}
}

func TestChallenge_DNSPersist01TXTRecordValue(t *testing.T) {
	account := Account{Location: "https://acme-v02.api.letsencrypt.org/acme/acct/12345"}

	tests := []struct {
		name       string
		issuer     string
		wildcard   bool
		expected   string
	}{
		{
			name:     "without wildcard",
			issuer:   "letsencrypt.org",
			wildcard: false,
			expected: "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/12345",
		},
		{
			name:     "with wildcard",
			issuer:   "letsencrypt.org",
			wildcard: true,
			expected: "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/12345; policy=wildcard",
		},
		{
			name:     "different issuer",
			issuer:   "ca.example.net",
			wildcard: false,
			expected: "ca.example.net; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/12345",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := Challenge{
				Identifier: Identifier{Type: "dns", Value: "example.com"},
			}
			got := c.DNSPersist01TXTRecordValue(account, test.issuer, test.wildcard)
			if got != test.expected {
				t.Errorf("DNSPersist01TXTRecordValue() = %q, want %q", got, test.expected)
			}
		})
	}
}

func TestChallenge_WIF01AudienceBindingValue(t *testing.T) {
	// token from draft-rasmussen-acme-wif-00 Appendix B; expected value computed with
	// printf %s "$keyAuthorization" | openssl dgst -sha256 -binary | basenc --base64url | tr -d =
	c := Challenge{
		Token:            "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0",
		KeyAuthorization: "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0.9jg46WB3rR_AHD-EBXdN7cBkH1WOu0tA3M9fm21mqTI",
	}
	const expected = "urn:ietf:params:acme:wif:LPsIwTo7o8BoG0-vjCyGQGBWSVIPxI-i_X336eUOQZo"

	got := c.WIF01AudienceBindingValue()
	if got != expected {
		t.Errorf("WIF01AudienceBindingValue() = %q, want %q", got, expected)
	}
	if !strings.HasPrefix(got, WIFAudiencePrefix) {
		t.Errorf("WIF01AudienceBindingValue() = %q, want prefix %q", got, WIFAudiencePrefix)
	}
	// "The resulting ABV is 68 ASCII characters." §4.3
	if len(got) != 68 {
		t.Errorf("len(WIF01AudienceBindingValue()) = %d, want 68", len(got))
	}

	// the binding must change with the account key
	c.KeyAuthorization = c.Token + ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if c.WIF01AudienceBindingValue() == expected {
		t.Error("ABV did not change when the key authorization changed")
	}
}

func TestChallenge_WIF01JSON(t *testing.T) {
	// challenge object as in draft-rasmussen-acme-wif-00 §4.2
	const in = `{
		"type": "wif-01",
		"url": "https://example.com/acme/chall/prV_B7yEyA4",
		"status": "pending",
		"token": "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0",
		"issuers": ["https://token.actions.githubusercontent.com"]
	}`
	var c Challenge
	if err := json.Unmarshal([]byte(in), &c); err != nil {
		t.Fatal(err)
	}
	if c.Type != ChallengeTypeWIF01 {
		t.Errorf("Type = %q, want %q", c.Type, ChallengeTypeWIF01)
	}
	if c.Token != "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0" {
		t.Errorf("Token = %q", c.Token)
	}
	if want := []string{"https://token.actions.githubusercontent.com"}; !reflect.DeepEqual(c.Issuers, want) {
		t.Errorf("Issuers = %v, want %v", c.Issuers, want)
	}

	// response payload, §4.3
	out, err := json.Marshal(WIF01Response{WIFToken: "eyJhbGciOiJSUzI1NiJ9.e30.c2ln"})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"wifToken":"eyJhbGciOiJSUzI1NiJ9.e30.c2ln"}`; string(out) != want {
		t.Errorf("WIF01Response JSON = %s, want %s", out, want)
	}
}
