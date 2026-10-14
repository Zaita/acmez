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

package acme

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestDirectoryMetaWIF(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want *DirectoryMetaWIF
	}{
		{
			// draft-rasmussen-acme-wif-00 §6
			name: "wif advertised",
			in: `{"newNonce": "https://example.com/acme/new-nonce", "meta": {
				"wif": {
					"issuers": ["https://token.actions.githubusercontent.com"],
					"maxTokenLifetime": 600
				}
			}}`,
			want: &DirectoryMetaWIF{
				Issuers:          []string{"https://token.actions.githubusercontent.com"},
				MaxTokenLifetime: 600,
			},
		},
		{
			name: "wif without maxTokenLifetime, unknown members ignored",
			in: `{"meta": {"wif": {
				"issuers": ["https://a.example", "https://b.example"],
				"futureMember": true
			}}}`,
			want: &DirectoryMetaWIF{Issuers: []string{"https://a.example", "https://b.example"}},
		},
		{
			name: "wif not advertised",
			in:   `{"meta": {"website": "https://example.com"}}`,
			want: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var dir Directory
			if err := json.Unmarshal([]byte(test.in), &dir); err != nil {
				t.Fatal(err)
			}
			if dir.Meta == nil {
				t.Fatal("Meta = nil")
			}
			if !reflect.DeepEqual(dir.Meta.WIF, test.want) {
				t.Errorf("Meta.WIF = %+v, want %+v", dir.Meta.WIF, test.want)
			}
		})
	}
}
