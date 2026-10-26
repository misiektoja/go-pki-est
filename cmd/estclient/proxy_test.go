/*
Copyright (c) 2026 the go-pki-est contributors.

Licensed under the MIT License (the "License"); you may not use this file except
in compliance with the License. You may obtain a copy of the License at

https://opensource.org/licenses/MIT

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"net/http"
	"testing"
)

// TestMakeClientProxy checks that the proxy setting reaches the client and that a bad URL is
// refused.
func TestMakeClientProxy(t *testing.T) {
	t.Parallel()

	cfg := config{Server: "est.fake.host:8443", Proxy: "http://proxy.fake.host:3128", Token: "tok-123"}
	client, err := cfg.MakeClient()
	if err != nil {
		t.Fatalf("failed to make client: %v", err)
	}
	if client.BearerToken != cfg.Token {
		t.Errorf("got bearer token %q, want %q", client.BearerToken, cfg.Token)
	}
	req, err := http.NewRequest(http.MethodGet, "https://est.fake.host:8443/.well-known/est/cacerts", nil)
	if err != nil {
		t.Fatal(err)
	}
	proxyURL, err := client.Proxy(req)
	if err != nil || proxyURL == nil || proxyURL.String() != cfg.Proxy {
		t.Errorf("got proxy %v, %v, want %s", proxyURL, err, cfg.Proxy)
	}

	cfg.Proxy = "://bad"
	if _, err := cfg.MakeClient(); err == nil {
		t.Error("MakeClient accepted a bad proxy URL")
	}
}
