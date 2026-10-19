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
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	est "github.com/misiektoja/go-pki-est"
	"github.com/misiektoja/go-pki-est/internal/basiclogger"
	"github.com/misiektoja/go-pki-est/internal/mockca"
)

// renewalCA records what Reenroll receives and delegates issuing to the mock CA.
type renewalCA struct {
	*mockca.MockCA
	mu       sync.Mutex
	called   bool
	cert     *x509.Certificate
	username string
}

// Reenroll records the renewed certificate and the TLS-SRP username, then issues a certificate.
func (ca *renewalCA) Reenroll(ctx context.Context, cert *x509.Certificate, csr *x509.CertificateRequest, aps string, r *http.Request) (*x509.Certificate, error) {
	ca.mu.Lock()
	ca.called, ca.cert, ca.username = true, cert, est.SRPUsernameFromContext(ctx)
	ca.mu.Unlock()
	return ca.MockCA.Reenroll(ctx, cert, csr, aps, r)
}

// newRenewalCA returns a renewalCA backed by a transient mock CA.
func newRenewalCA(t *testing.T) *renewalCA {
	t.Helper()

	ca, err := mockca.NewTransient()
	if err != nil {
		t.Fatalf("failed to create mock CA: %v", err)
	}
	return &renewalCA{MockCA: ca}
}

// withSRPLogin wraps h so every request carries username as its TLS-SRP login.
func withSRPLogin(h http.Handler, username string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(est.WithSRPUsername(r.Context(), username)))
	})
}

// TestSRPRenewal checks that /simplereenroll accepts a TLS-SRP login without a client certificate.
func TestSRPRenewal(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name     string
		username string
		status   int
	}{
		{name: "SRPLogin", username: "device-1", status: http.StatusOK},
		{name: "NoLogin", status: http.StatusForbidden},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ca := newRenewalCA(t)
			var hookUsername string
			h := withSRPLogin(newHookRouter(t, est.ServerConfig{
				CA: ca,
				CheckBasicAuth: func(ctx context.Context, r *http.Request, aps, username, password string) error {
					hookUsername = est.SRPUsernameFromContext(ctx)
					return nil
				},
			}), tc.username)

			w := serve(h, http.MethodPost, reenrollEndpoint, mimeTypePKCS10, mustMakeBase64CSR(t, "Device"))

			if w.Code != tc.status {
				t.Fatalf("got status %d, want %d: %s", w.Code, tc.status, w.Body.String())
			}
			if hookUsername != tc.username {
				t.Errorf("CheckBasicAuth got TLS-SRP username %q, want %q", hookUsername, tc.username)
			}
			if ca.called != (tc.status == http.StatusOK) {
				t.Fatalf("Reenroll called %t, want %t", ca.called, tc.status == http.StatusOK)
			}
			if ca.called && (ca.cert != nil || ca.username != tc.username) {
				t.Errorf("Reenroll got certificate %v and username %q, want no certificate and %q", ca.cert != nil, ca.username, tc.username)
			}
		})
	}
}

// TestSRPRenewalWithCertificate checks that a client certificate is still compared with the
// request when the request also carries a TLS-SRP login.
func TestSRPRenewalWithCertificate(t *testing.T) {
	t.Parallel()

	ca := newRenewalCA(t)
	csr := mustCreateCertificateRequest(t, mustGenerateECPrivateKey(t), "Device", nil)
	cert, err := ca.Enroll(context.Background(), csr, "", nil)
	if err != nil {
		t.Fatalf("failed to issue client certificate: %v", err)
	}
	h := withSRPLogin(newHookRouter(t, est.ServerConfig{CA: ca}), "device-1")

	testcases := []struct {
		name   string
		cn     string
		status int
	}{
		{name: "SameSubject", cn: "Device", status: http.StatusOK},
		{name: "ChangedSubject", cn: "Other", status: http.StatusForbidden},
	}

	for _, tc := range testcases {
		body := mustMakeBase64CSR(t, tc.cn)
		req := httptest.NewRequest(http.MethodPost, reenrollEndpoint, bytes.NewReader(body))
		req.Header.Set(typeHeader, mimeTypePKCS10)
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		if w.Code != tc.status {
			t.Fatalf("%s: got status %d, want %d: %s", tc.name, w.Code, tc.status, w.Body.String())
		}
	}
	if !ca.called || ca.cert == nil || !bytes.Equal(ca.cert.Raw, cert.Raw) {
		t.Errorf("Reenroll did not receive the client certificate")
	}
}

// TestSRPUsernameFromContext checks that an empty username leaves the context without a login.
func TestSRPUsernameFromContext(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	if got := est.SRPUsernameFromContext(est.WithSRPUsername(ctx, "")); got != "" {
		t.Errorf("got username %q for an empty login", got)
	}
	if got := est.SRPUsernameFromContext(est.WithSRPUsername(ctx, "device-1")); got != "device-1" {
		t.Errorf("got username %q, want %q", got, "device-1")
	}
	if est.WithSRPUsername(ctx, "") != ctx {
		t.Errorf("an empty username changed the context")
	}
}

// TestSRPRequestLogScheme checks that requests over TLS-SRP are logged as https.
func TestSRPRequestLogScheme(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	h := withSRPLogin(newHookRouter(t, est.ServerConfig{Logger: basiclogger.New(&buf)}), "device-1")
	serve(h, http.MethodGet, cacertsEndpoint, "", nil)

	if want := "https://example.com" + cacertsEndpoint; !strings.Contains(buf.String(), want) {
		t.Errorf("log does not contain %q: %s", want, buf.String())
	}
}
