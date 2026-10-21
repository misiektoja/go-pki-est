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
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	srptls "github.com/misiektoja/go-tls-srp"

	est "github.com/misiektoja/go-pki-est"
	"github.com/misiektoja/go-pki-est/internal/mockca"
)

// srpConnCtxKey is the request context key of the TLS-SRP connection in the test server.
type srpConnCtxKey struct{}

// challengeCA records whether each request carried a challenge password.
type challengeCA struct {
	*mockca.MockCA
	mu        sync.Mutex
	challenge []bool
}

// oidChallengePassword identifies the challengePassword attribute.
var oidChallengePassword = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}

// Enroll records whether the request has a challenge password, then issues a certificate.
func (ca *challengeCA) Enroll(ctx context.Context, csr *x509.CertificateRequest, aps string, r *http.Request) (*x509.Certificate, error) {
	// crypto/x509 leaves a challengePassword out of Attributes, because its value is a string.
	oid, err := asn1.Marshal(oidChallengePassword)
	if err != nil {
		return nil, err
	}
	found := bytes.Contains(csr.RawTBSCertificateRequest, oid)
	ca.mu.Lock()
	ca.challenge = append(ca.challenge, found)
	ca.mu.Unlock()
	return ca.MockCA.Enroll(ctx, csr, aps, r)
}

// newSRPServer serves the EST router over TLS-SRP for one user and returns its address. Like a host
// that terminates TLS-SRP, it passes the username of each connection to the router.
func newSRPServer(t *testing.T, ca est.CA, username, password string) string {
	t.Helper()

	router, err := est.NewRouter(&est.ServerConfig{
		CA: ca,
		CheckBasicAuth: func(ctx context.Context, _ *http.Request, _, _, _ string) error {
			if est.SRPUsernameFromContext(ctx) != username {
				return errors.New("not signed in with TLS-SRP")
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("failed to create router: %v", err)
	}
	group, err := srptls.GroupByBits(2048)
	if err != nil {
		t.Fatal(err)
	}
	salt, err := srptls.NewSalt(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := srptls.NewVerifier(group, []byte(username), []byte(password), salt)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := srptls.Listen("tcp", "127.0.0.1:0", &srptls.Config{
		GetVerifier: func(info *srptls.ClientHelloInfo) (*srptls.Verifier, error) {
			if info.Username != username {
				return nil, srptls.ErrUnknownUsername
			}
			return verifier, nil
		},
	})
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, _ := r.Context().Value(srpConnCtxKey{}).(*srptls.Conn)
			if conn == nil {
				http.Error(w, "no TLS-SRP connection", http.StatusInternalServerError)
				return
			}
			ctx := est.WithSRPUsername(r.Context(), conn.ConnectionState().SRPUsername)
			router.ServeHTTP(w, r.WithContext(ctx))
		}),
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, srpConnCtxKey{}, c)
		},
		ReadHeaderTimeout: testTimeout,
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

// TestClientSRP checks that the client signs in with TLS-SRP, reports the connection and binds a
// request to the TLS session.
func TestClientSRP(t *testing.T) {
	t.Parallel()

	inner, err := mockca.NewTransient()
	if err != nil {
		t.Fatal(err)
	}
	ca := &challengeCA{MockCA: inner}
	addr := newSRPServer(t, ca, "device-42", "s3cret")

	key := mustGenerateECPrivateKey(t)
	var users []string
	client := &est.Client{
		Host:        addr,
		SRPUsername: "device-42",
		SRPPassword: "s3cret",
		SigningKey:  key,
		OnConnect: func(conn net.Conn) {
			if c, ok := conn.(*srptls.Conn); ok {
				users = append(users, c.ConnectionState().SRPUsername)
			}
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	if _, err := client.CACerts(ctx); err != nil {
		t.Fatalf("CACerts: %v", err)
	}
	csr := mustCreateCertificateRequest(t, key, "device-42", nil)
	if _, err := client.Enroll(ctx, csr); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if _, err := client.Reenroll(ctx, csr); err != nil {
		t.Fatalf("Reenroll without a client certificate: %v", err)
	}
	if len(users) != 3 || users[0] != "device-42" {
		t.Errorf("OnConnect saw %v", users)
	}
	if len(ca.challenge) != 1 || !ca.challenge[0] {
		t.Errorf("challenge password in the requests: %v, want it in the one enrollment", ca.challenge)
	}
}

// TestClientSRPWrongPassword checks that a wrong password fails the handshake.
func TestClientSRPWrongPassword(t *testing.T) {
	t.Parallel()

	inner, err := mockca.NewTransient()
	if err != nil {
		t.Fatal(err)
	}
	addr := newSRPServer(t, inner, "device-42", "s3cret")
	client := &est.Client{Host: addr, SRPUsername: "device-42", SRPPassword: "wrong"}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, err := client.CACerts(ctx); !errors.Is(err, srptls.ErrWrongPassword) {
		t.Errorf("CACerts with a wrong password: %v", err)
	}
}
