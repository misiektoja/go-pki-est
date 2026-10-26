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
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	est "github.com/misiektoja/go-pki-est"
)

// checkTestPassword accepts the password xyzzy and, like a hook that also signs clients in by
// certificate, requests without credentials.
func checkTestPassword(ctx context.Context, r *http.Request, aps, username, password string) error {
	if username == "" || password == "xyzzy" {
		return nil
	}
	return errors.New("wrong password")
}

// checkTestToken accepts the bearer token tok-123.
func checkTestToken(ctx context.Context, r *http.Request, aps, token string) error {
	if token == "tok-123" {
		return nil
	}
	return errors.New("wrong token")
}

// newPasswordRenewalRequest returns a /simplereenroll request for cn without a client certificate.
func newPasswordRenewalRequest(t *testing.T, cn, username, password string) *http.Request {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, reenrollEndpoint, bytes.NewReader(mustMakeBase64CSR(t, cn)))
	req.Header.Set(typeHeader, mimeTypePKCS10)
	if username != "" {
		req.SetBasicAuth(username, password)
	}
	return req
}

// TestPasswordRenewal checks which /simplereenroll requests without a client certificate
// PasswordRenewal accepts. A bearer token signs in only through CheckBearerToken. Without that
// hook, CheckBasicAuth sees the request without credentials and must not unlock the renewal by
// accepting them, as a hook that also signs clients in by certificate does.
func TestPasswordRenewal(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name      string
		enabled   bool
		username  string
		password  string
		token     string
		noTokens  bool
		status    int
		basicSeen bool
	}{
		{name: "Accepted", enabled: true, username: "device-1", password: "xyzzy", status: http.StatusOK, basicSeen: true},
		{name: "Disabled", username: "device-1", password: "xyzzy", status: http.StatusForbidden, basicSeen: true},
		{name: "NoCredentials", enabled: true, status: http.StatusForbidden, basicSeen: true},
		{name: "WrongPassword", enabled: true, username: "device-1", password: "wrong", status: http.StatusUnauthorized, basicSeen: true},
		{name: "BearerToken", enabled: true, token: "tok-123", status: http.StatusOK},
		{name: "BearerTokenDisabled", token: "tok-123", status: http.StatusForbidden},
		{name: "WrongToken", enabled: true, token: "wrong", status: http.StatusUnauthorized},
		{name: "BearerTokenUnchecked", enabled: true, token: "tok-123", noTokens: true, status: http.StatusForbidden, basicSeen: true},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ca := newRenewalCA(t)
			var basicSeen bool
			var gotUser, gotPassword string
			cfg := est.ServerConfig{
				CA: ca,
				CheckBasicAuth: func(ctx context.Context, r *http.Request, aps, username, password string) error {
					basicSeen, gotUser, gotPassword = true, username, password
					return checkTestPassword(ctx, r, aps, username, password)
				},
				PasswordRenewal: tc.enabled,
			}
			if !tc.noTokens {
				cfg.CheckBearerToken = checkTestToken
			}
			h := newHookRouter(t, cfg)

			req := newPasswordRenewalRequest(t, "Device", tc.username, tc.password)
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)

			if w.Code != tc.status {
				t.Fatalf("got status %d, want %d: %s", w.Code, tc.status, w.Body.String())
			}
			if ca.called != (tc.status == http.StatusOK) {
				t.Fatalf("Reenroll called %t, want %t", ca.called, tc.status == http.StatusOK)
			}
			if ca.called && ca.cert != nil {
				t.Errorf("Reenroll got a certificate, want none")
			}
			if basicSeen != tc.basicSeen {
				t.Errorf("CheckBasicAuth called %t, want %t", basicSeen, tc.basicSeen)
			}
			if tc.token != "" && (gotUser != "" || gotPassword != "") {
				t.Errorf("CheckBasicAuth got credentials %q/%q for a bearer token request", gotUser, gotPassword)
			}
		})
	}
}

// TestPasswordRenewalWithCertificate checks that a client certificate is still compared with
// the request when PasswordRenewal is set and the request carries a password.
func TestPasswordRenewalWithCertificate(t *testing.T) {
	t.Parallel()

	ca := newRenewalCA(t)
	csr := mustCreateCertificateRequest(t, mustGenerateECPrivateKey(t), "Device", nil)
	cert, err := ca.Enroll(context.Background(), csr, "", nil)
	if err != nil {
		t.Fatalf("failed to issue client certificate: %v", err)
	}
	h := newHookRouter(t, est.ServerConfig{CA: ca, CheckBasicAuth: checkTestPassword, PasswordRenewal: true})

	testcases := []struct {
		name   string
		cn     string
		status int
	}{
		{name: "SameSubject", cn: "Device", status: http.StatusOK},
		{name: "ChangedSubject", cn: "Other", status: http.StatusForbidden},
	}

	for _, tc := range testcases {
		req := newPasswordRenewalRequest(t, tc.cn, "device-1", "xyzzy")
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

// TestPasswordRenewalRequiresCredentialCheck checks that NewRouter refuses PasswordRenewal when
// nothing checks a password or a token and accepts it with either hook.
func TestPasswordRenewalRequiresCredentialCheck(t *testing.T) {
	t.Parallel()

	if _, err := est.NewRouter(&est.ServerConfig{CA: newRenewalCA(t), PasswordRenewal: true}); err == nil {
		t.Fatal("NewRouter accepted PasswordRenewal without CheckBasicAuth or CheckBearerToken")
	}
	if _, err := est.NewRouter(&est.ServerConfig{CA: newRenewalCA(t), PasswordRenewal: true, CheckBasicAuth: checkTestPassword}); err != nil {
		t.Fatalf("NewRouter refused PasswordRenewal with CheckBasicAuth: %v", err)
	}
	if _, err := est.NewRouter(&est.ServerConfig{CA: newRenewalCA(t), PasswordRenewal: true, CheckBearerToken: checkTestToken}); err != nil {
		t.Fatalf("NewRouter refused PasswordRenewal with CheckBearerToken: %v", err)
	}
}

// TestClientPasswordRenewal checks that Client.Reenroll renews with a password or a bearer token
// alone over TLS.
func TestClientPasswordRenewal(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name     string
		username string
		password string
		token    string
	}{
		{name: "Password", username: "device-1", password: "xyzzy"},
		{name: "BearerToken", token: "tok-123"},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ca := newRenewalCA(t)
			client := newHookClient(t, newHookRouter(t, est.ServerConfig{
				CA:               ca,
				CheckBasicAuth:   checkTestPassword,
				CheckBearerToken: checkTestToken,
				PasswordRenewal:  true,
			}))
			client.Username, client.Password, client.BearerToken = tc.username, tc.password, tc.token

			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()
			if _, err := client.Reenroll(ctx, mustCreateCertificateRequest(t, mustGenerateECPrivateKey(t), "Device", nil)); err != nil {
				t.Fatalf("failed to renew: %v", err)
			}
			if !ca.called || ca.cert != nil {
				t.Errorf("Reenroll called %t with certificate %t, want a call without certificate", ca.called, ca.cert != nil)
			}
		})
	}
}

// TestVerifyClientCertificate checks that the client certificate hook replaces the check against
// the CA certificates on /simplereenroll and that the Subject comparison still runs first.
func TestVerifyClientCertificate(t *testing.T) {
	t.Parallel()

	// A self-signed certificate does not chain to the mock CA, so only the hook can accept it.
	key := mustGenerateECPrivateKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "Device"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("failed to create client certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse client certificate: %v", err)
	}

	testcases := []struct {
		name     string
		hook     func(err error) func(context.Context, *http.Request, string, *x509.Certificate) error
		hookErr  error
		cn       string
		status   int
		hookSeen bool
	}{
		{name: "NoHook", cn: "Device", status: http.StatusForbidden},
		{name: "Accepted", hook: verifyClientHook, cn: "Device", status: http.StatusOK, hookSeen: true},
		{name: "Refused", hook: verifyClientHook, hookErr: errors.New("unknown certificate"), cn: "Device", status: http.StatusForbidden, hookSeen: true},
		{name: "HostStatus", hook: verifyClientHook, hookErr: statusError{status: http.StatusServiceUnavailable, retry: 5}, cn: "Device", status: http.StatusServiceUnavailable, hookSeen: true},
		{name: "ChangedSubject", hook: verifyClientHook, cn: "Other", status: http.StatusForbidden},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ca := newRenewalCA(t)
			var seen *x509.Certificate
			cfg := est.ServerConfig{CA: ca}
			if tc.hook != nil {
				check := tc.hook(tc.hookErr)
				cfg.VerifyClientCertificate = func(ctx context.Context, r *http.Request, aps string, c *x509.Certificate) error {
					seen = c
					return check(ctx, r, aps, c)
				}
			}
			req := newPasswordRenewalRequest(t, tc.cn, "", "")
			req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
			w := httptest.NewRecorder()
			newHookRouter(t, cfg).ServeHTTP(w, req)

			if w.Code != tc.status {
				t.Fatalf("got status %d, want %d: %s", w.Code, tc.status, w.Body.String())
			}
			if tc.hookSeen != (seen != nil) {
				t.Fatalf("hook called: %t, want %t", seen != nil, tc.hookSeen)
			}
			if seen != nil && !seen.Equal(cert) {
				t.Errorf("hook received another certificate")
			}
			if tc.status == http.StatusOK && (!ca.called || !ca.cert.Equal(cert)) {
				t.Errorf("Reenroll did not receive the client certificate")
			}
			if tc.status == http.StatusServiceUnavailable && w.Header().Get("Retry-After") != "5" {
				t.Errorf("got Retry-After %q, want 5", w.Header().Get("Retry-After"))
			}
		})
	}
}

// verifyClientHook returns a client certificate hook that answers err.
func verifyClientHook(err error) func(context.Context, *http.Request, string, *x509.Certificate) error {
	return func(context.Context, *http.Request, string, *x509.Certificate) error { return err }
}
