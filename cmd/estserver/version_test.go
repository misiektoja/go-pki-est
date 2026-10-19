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
	"net/http/httptest"
	"strings"
	"testing"

	est "github.com/misiektoja/go-pki-est"
)

// TestVersionMatchesLibrary checks that estserver -version reports the version
// that the library sends in its Server header.
func TestVersionMatchesLibrary(t *testing.T) {
	t.Parallel()

	r, err := est.NewRouter(&est.ServerConfig{})
	if err != nil {
		t.Fatalf("failed to create router: %v", err)
	}

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	server := w.Header().Get("Server")
	if !strings.HasSuffix(server, " v"+versionString) {
		t.Fatalf("estserver reports version %q, the library Server header is %q", versionString, server)
	}
}
