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
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	est "github.com/misiektoja/go-pki-est"
)

// TestVersionMatchesLibrary checks that estclient -version reports the version
// that the library sends in its User-Agent header.
func TestVersionMatchesLibrary(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if err := version(&buf, nil); err != nil {
		t.Fatalf("failed to write version: %v", err)
	}
	fields := strings.Fields(buf.String())
	if len(fields) == 0 {
		t.Fatal("version wrote nothing")
	}
	got := fields[len(fields)-1]

	agents := make(chan string, 1)
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case agents <- r.UserAgent():
		default:
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer s.Close()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	client := est.Client{Host: strings.TrimPrefix(s.URL, "https://"), InsecureSkipVerify: true}
	_, _ = client.CACerts(ctx)

	var agent string
	select {
	case agent = <-agents:
	default:
		t.Fatal("the server received no request")
	}
	if !strings.Contains(agent, " v"+got+" ") {
		t.Fatalf("estclient reports version %q, the library User-Agent is %q", got, agent)
	}
}
