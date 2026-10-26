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
	"net/http"
	"strings"
	"testing"

	est "github.com/misiektoja/go-pki-est"
)

// TestAdditionalPathSegmentLength checks that the server serves an additional path segment of
// 255 bytes and refuses a longer one with 414 before any endpoint runs. The segment keys the CA
// certificate cache, so a client must not choose its size.
func TestAdditionalPathSegmentLength(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name   string
		length int
		method string
		op     string
		body   []byte
		status int
	}{
		{name: "LongestCACerts", length: 255, method: http.MethodGet, op: "cacerts", status: http.StatusOK},
		{name: "TooLongCACerts", length: 256, method: http.MethodGet, op: "cacerts", status: http.StatusRequestURITooLong},
		{name: "TooLongEnroll", length: 4096, method: http.MethodPost, op: "simpleenroll", body: mustMakeBase64CSR(t, "Device"), status: http.StatusRequestURITooLong},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			refusals := &refusalLog{}
			h := newHookRouter(t, est.ServerConfig{Refusals: refusals})
			aps := strings.Repeat("a", tc.length)

			contentType := ""
			if tc.body != nil {
				contentType = mimeTypePKCS10
			}
			w := serve(h, tc.method, "/.well-known/est/"+aps+"/"+tc.op, contentType, tc.body)

			if w.Code != tc.status {
				t.Fatalf("got status %d, want %d: %s", w.Code, tc.status, w.Body.String())
			}

			recorded := refusals.recorded()
			if tc.status == http.StatusOK {
				if len(recorded) != 0 {
					t.Fatalf("got %d refusals, want none", len(recorded))
				}
				return
			}
			if len(recorded) != 1 {
				t.Fatalf("got %d refusals, want 1", len(recorded))
			}
			if r := recorded[0]; r.Status != tc.status || r.Operation != tc.op || r.AdditionalPathSegment != aps {
				t.Errorf("got refusal %d %q with segment of %d bytes, want %d %q with %d bytes", r.Status, r.Operation, len(r.AdditionalPathSegment), tc.status, tc.op, tc.length)
			}
		})
	}
}
