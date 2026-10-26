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

package est_test

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// authorizationRecorder records the Authorization header of every request.
type authorizationRecorder struct {
	next http.RoundTripper
	mu   sync.Mutex
	seen []string
}

// RoundTrip records the Authorization header and passes the request on.
func (rec *authorizationRecorder) RoundTrip(r *http.Request) (*http.Response, error) {
	rec.mu.Lock()
	rec.seen = append(rec.seen, r.Header.Get("Authorization"))
	rec.mu.Unlock()
	return rec.next.RoundTrip(r)
}

// TestClientBearerToken checks that BearerToken is sent as Bearer authorization, that Username
// takes precedence and that no header is sent without credentials.
func TestClientBearerToken(t *testing.T) {
	t.Parallel()

	srv, newClient := newTestServer(t)
	defer srv.Close()

	for name, tt := range map[string]struct {
		username, token, want string
	}{
		"token":      {"", "tok-123", "Bearer tok-123"},
		"basic wins": {"testuser", "tok-123", "Basic "},
		"none":       {"", "", ""},
	} {
		t.Run(name, func(t *testing.T) {
			client := newClient()
			client.Username, client.BearerToken = tt.username, tt.token
			rec := &authorizationRecorder{}
			client.WrapTransport = func(next http.RoundTripper) http.RoundTripper {
				rec.next = next
				return rec
			}
			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()
			if _, err := client.CACerts(ctx); err != nil {
				t.Fatalf("CACerts: %v", err)
			}
			rec.mu.Lock()
			defer rec.mu.Unlock()
			if len(rec.seen) != 1 || !strings.HasPrefix(rec.seen[0], tt.want) || tt.want == "" && rec.seen[0] != "" {
				t.Errorf("Authorization headers %q, want one starting with %q", rec.seen, tt.want)
			}
		})
	}
}
