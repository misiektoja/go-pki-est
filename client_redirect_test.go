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
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	est "github.com/misiektoja/go-pki-est"
)

// TestClientRefusesRedirect checks that the client returns a redirect as an error with its
// status instead of following it. A followed redirect to an http URL on the same host would
// resend the client's credentials in cleartext.
func TestClientRefusesRedirect(t *testing.T) {
	t.Parallel()

	// A plaintext listener stands in for the redirect target and counts its connections.
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer target.Close()
	var connections atomic.Int32
	go func() {
		for {
			conn, err := target.Accept()
			if err != nil {
				return
			}
			connections.Add(1)
			_ = conn.Close()
		}
	}()

	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://"+target.Addr().String()+r.URL.Path, http.StatusFound)
	}))
	defer s.Close()

	pool := x509.NewCertPool()
	pool.AddCert(s.Certificate())
	client := &est.Client{
		Host:           strings.TrimPrefix(s.URL, "https://"),
		ExplicitAnchor: pool,
		Username:       "device-1",
		Password:       "xyzzy",
	}

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	_, err = client.CACerts(ctx)
	var estErr est.Error
	if !errors.As(err, &estErr) || estErr.StatusCode() != http.StatusFound {
		t.Fatalf("CACerts returned %v, want an error with status 302", err)
	}
	if n := connections.Load(); n != 0 {
		t.Errorf("the redirect target received %d connections, want none", n)
	}
}
