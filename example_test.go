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

// The documentation site includes the code between the "--8<--" markers, so the code it shows is
// compiled and, for examples with an Output comment, run by go test.

package est_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"

	srptls "github.com/misiektoja/go-tls-srp"

	est "github.com/misiektoja/go-pki-est"
)

// exampleCA is a minimal in-memory CA with a self-signed root that signs every certificate.
type exampleCA struct {
	root *x509.Certificate
	key  crypto.Signer
}

// newExampleCA creates an exampleCA with a new P-256 root.
func newExampleCA() (*exampleCA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Example EST CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &exampleCA{root: root, key: key}, nil
}

// --8<-- [start:ca]
// caError is an error with an HTTP status. The server sends its status, message and Retry-After
// value to the client.
type caError struct {
	status     int
	msg        string
	retryAfter int
}

// Error returns the message sent to the client.
func (e caError) Error() string { return e.msg }

// StatusCode returns the HTTP status of the response.
func (e caError) StatusCode() int { return e.status }

// RetryAfter returns the Retry-After value in seconds, or 0 for none.
func (e caError) RetryAfter() int { return e.retryAfter }

// CACerts returns the certificates clients use as trust anchors.
func (ca *exampleCA) CACerts(ctx context.Context, aps string, r *http.Request) ([]*x509.Certificate, error) {
	return []*x509.Certificate{ca.root}, nil
}

// CSRAttrs asks clients for a P-384 key, using the example of RFC 7030 section 4.5.2.
func (ca *exampleCA) CSRAttrs(ctx context.Context, aps string, r *http.Request) (est.CSRAttrs, error) {
	return est.CSRAttrs{
		Attributes: []est.Attribute{{
			Type:   asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1},
			Values: est.AttributeValueSET{asn1.ObjectIdentifier{1, 3, 132, 0, 34}},
		}},
	}, nil
}

// Enroll issues a certificate for the key in the request.
func (ca *exampleCA) Enroll(ctx context.Context, csr *x509.CertificateRequest, aps string, r *http.Request) (*x509.Certificate, error) {
	return ca.issue(csr, csr.PublicKey)
}

// Reenroll renews a certificate. cert is nil when the client signed in with TLS-SRP or, with
// PasswordRenewal, with a password or bearer token instead of the certificate being renewed.
func (ca *exampleCA) Reenroll(ctx context.Context, cert *x509.Certificate, csr *x509.CertificateRequest, aps string, r *http.Request) (*x509.Certificate, error) {
	if cert == nil {
		// Any client can name any subject in a CSR, so the renewal is tied to the signed-in user.
		user := est.SRPUsernameFromContext(ctx)
		if user == "" {
			user, _, _ = r.BasicAuth()
		}
		if user == "" || csr.Subject.CommonName != user {
			return nil, caError{status: http.StatusForbidden, msg: "renewal is limited to the signed-in user"}
		}
	}
	return ca.issue(csr, csr.PublicKey)
}

// ServerKeyGen generates a key for the client and returns it unencrypted as PKCS #8.
func (ca *exampleCA) ServerKeyGen(ctx context.Context, csr *x509.CertificateRequest, aps string, r *http.Request) (*x509.Certificate, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	// The server ignores the key and the signature of the request, so only its names are used.
	cert, err := ca.issue(csr, key.Public())
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return cert, der, nil
}

// TPMEnroll refuses TPM enrollment, which this CA does not offer.
func (ca *exampleCA) TPMEnroll(ctx context.Context, csr *x509.CertificateRequest, ekcerts []*x509.Certificate, ekPub, akPub []byte, aps string, r *http.Request) ([]byte, []byte, []byte, error) {
	return nil, nil, nil, caError{status: http.StatusNotImplemented, msg: "TPM enrollment is not offered"}
}

// --8<-- [end:ca]

// issue signs a certificate for pub with the Subject and SubjectAltName of csr. It copies both
// unchanged, because a renewal request must repeat them byte for byte.
func (ca *exampleCA) issue(csr *x509.CertificateRequest, pub crypto.PublicKey) (*x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		RawSubject:   csr.RawSubject,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(12 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	for _, ext := range csr.Extensions {
		if ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
			tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, ext)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.root, pub, ca.key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// startExampleServer serves the router for cfg over TLS on a local port. Clients may present a
// certificate that chains to the example CA root.
func startExampleServer(ca *exampleCA, cfg *est.ServerConfig) (*httptest.Server, error) {
	cfg.CA = ca
	router, err := est.NewRouter(cfg)
	if err != nil {
		return nil, err
	}
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(ca.root)
	srv := httptest.NewUnstartedServer(router)
	srv.TLS = &tls.Config{ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: clientCAs}
	srv.StartTLS()
	return srv, nil
}

// exampleClient returns a client for srv that trusts the test server certificate.
func exampleClient(srv *httptest.Server) *est.Client {
	anchor := x509.NewCertPool()
	anchor.AddCert(srv.Certificate())
	return &est.Client{Host: srv.Listener.Addr().String(), ExplicitAnchor: anchor}
}

// newCSR returns a certificate request for key with the given common name.
func newCSR(key crypto.Signer, commonName string) (*x509.CertificateRequest, error) {
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}}, key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificateRequest(der)
}

// ExampleNewRouter serves EST in front of a CA. The listener requests a client certificate without
// requiring one, so the same port serves first enrollments with a password and renewals with the
// certificate being renewed.
func ExampleNewRouter() {
	ca, err := newExampleCA()
	if err != nil {
		log.Fatal(err)
	}

	// --8<-- [start:router]
	// One-time enrollment passwords, as an operator would issue them.
	passwords := map[string]string{"device-1": "one-time-secret"}

	router, err := est.NewRouter(&est.ServerConfig{
		CA:        ca,
		RateLimit: 50,
		CheckBasicAuth: func(ctx context.Context, r *http.Request, aps, username, password string) error {
			// A client certificate that crypto/tls verified needs no password.
			if r.TLS != nil && len(r.TLS.VerifiedChains) > 0 {
				return nil
			}
			want, ok := passwords[username]
			if !ok || subtle.ConstantTimeCompare([]byte(password), []byte(want)) != 1 {
				return errors.New("unknown user or wrong password")
			}
			return nil
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(ca.root)

	srv := &http.Server{
		Addr:    ":8443",
		Handler: router,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ClientAuth: tls.VerifyClientCertIfGiven,
			ClientCAs:  clientCAs,
		},
		ReadHeaderTimeout: 30 * time.Second,
	}
	log.Fatal(srv.ListenAndServeTLS("server-chain.pem", "server-key.pem"))
	// --8<-- [end:router]
}

// ExampleClient fetches the CA certificates, enrolls a new key and renews the certificate over a
// connection that the certificate being renewed authenticates.
func ExampleClient() {
	ca, err := newExampleCA()
	if err != nil {
		log.Fatal(err)
	}
	srv, err := startExampleServer(ca, &est.ServerConfig{})
	if err != nil {
		log.Fatal(err)
	}
	anchor := x509.NewCertPool()
	anchor.AddCert(srv.Certificate())
	host := srv.Listener.Addr().String()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

	// --8<-- [start:client-enroll]
	client := &est.Client{
		Host:           host,
		ExplicitAnchor: anchor,
	}

	cacerts, err := client.CACerts(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("CA:", cacerts[0].Subject.CommonName)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "device-1"},
		DNSNames: []string{"device-1.example.com"},
	}, key)
	if err != nil {
		log.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		log.Fatal(err)
	}

	cert, err := client.Enroll(ctx, csr)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("enrolled:", cert.Subject.CommonName, cert.DNSNames)
	// --8<-- [end:client-enroll]

	// --8<-- [start:client-reenroll]
	// The certificate being renewed authenticates the TLS connection.
	client.Certificates = []*x509.Certificate{cert}
	client.PrivateKey = key

	// The request repeats the Subject and SubjectAltName of the certificate.
	der, err = x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		RawSubject: cert.RawSubject,
		DNSNames:   cert.DNSNames,
	}, key)
	if err != nil {
		log.Fatal(err)
	}
	csr, err = x509.ParseCertificateRequest(der)
	if err != nil {
		log.Fatal(err)
	}

	renewed, err := client.Reenroll(ctx, csr)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("renewed:", renewed.Subject.CommonName, renewed.SerialNumber.Cmp(cert.SerialNumber) != 0)
	// --8<-- [end:client-reenroll]

	cancel()
	srv.Close()

	// Output:
	// CA: Example EST CA
	// enrolled: device-1 [device-1.example.com]
	// renewed: device-1 true
}

// ExampleClient_CSRAttrs asks the server which attributes it wants in a request.
func ExampleClient_CSRAttrs() {
	ca, err := newExampleCA()
	if err != nil {
		log.Fatal(err)
	}
	srv, err := startExampleServer(ca, &est.ServerConfig{})
	if err != nil {
		log.Fatal(err)
	}
	client := exampleClient(srv)
	ctx := context.Background()

	// --8<-- [start:csrattrs]
	attrs, err := client.CSRAttrs(ctx)
	if err != nil {
		log.Fatal(err)
	}
	for _, oid := range attrs.OIDs {
		fmt.Println("OID:", oid)
	}
	for _, attr := range attrs.Attributes {
		fmt.Println("attribute:", attr.Type, attr.Values)
	}
	// --8<-- [end:csrattrs]

	srv.Close()

	// Output:
	// attribute: 1.2.840.10045.2.1 [1.3.132.0.34]
}

// ExampleClient_ServerKeyGen asks the server to generate the private key.
func ExampleClient_ServerKeyGen() {
	ca, err := newExampleCA()
	if err != nil {
		log.Fatal(err)
	}
	srv, err := startExampleServer(ca, &est.ServerConfig{})
	if err != nil {
		log.Fatal(err)
	}
	client := exampleClient(srv)
	ctx := context.Background()

	// --8<-- [start:serverkeygen]
	// The request carries the names. The server ignores its key, so a throwaway key signs it.
	throwaway, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	csr, err := newCSR(throwaway, "device-2")
	if err != nil {
		log.Fatal(err)
	}

	cert, keyDER, err := client.ServerKeyGen(ctx, csr)
	if err != nil {
		log.Fatal(err)
	}
	// Without additional encryption the key is PKCS #8.
	key, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("certificate: %s\nkey: %T\n", cert.Subject.CommonName, key)
	// --8<-- [end:serverkeygen]

	srv.Close()

	// Output:
	// certificate: device-2
	// key: *ecdsa.PrivateKey
}

// ExampleServerConfig_passwordRenewal renews a certificate with HTTP Basic credentials instead of
// a TLS client certificate.
func ExampleServerConfig_passwordRenewal() {
	ca, err := newExampleCA()
	if err != nil {
		log.Fatal(err)
	}
	passwords := map[string]string{"device-3": "renewal-secret"}

	// --8<-- [start:password-renewal-server]
	cfg := &est.ServerConfig{
		CheckBasicAuth: func(ctx context.Context, r *http.Request, aps, username, password string) error {
			want, ok := passwords[username]
			if !ok || subtle.ConstantTimeCompare([]byte(password), []byte(want)) != 1 {
				return errors.New("unknown user or wrong password")
			}
			return nil
		},
		PasswordRenewal: true,
	}
	// --8<-- [end:password-renewal-server]
	srv, err := startExampleServer(ca, cfg)
	if err != nil {
		log.Fatal(err)
	}
	client := exampleClient(srv)
	ctx := context.Background()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	// --8<-- [start:password-renewal-client]
	client.Username = "device-3"
	client.Password = "renewal-secret"

	csr, err := newCSR(key, "device-3")
	if err != nil {
		log.Fatal(err)
	}
	renewed, err := client.Reenroll(ctx, csr)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("renewed without a client certificate:", renewed.Subject.CommonName)

	// The CA refuses a request that names another subject.
	other, err := newCSR(key, "device-4")
	if err != nil {
		log.Fatal(err)
	}
	_, err = client.Reenroll(ctx, other)
	fmt.Println(strings.TrimSpace(err.Error()))
	// --8<-- [end:password-renewal-client]

	srv.Close()

	// Output:
	// renewed without a client certificate: device-3
	// 403 renewal is limited to the signed-in user
}

// srpConnKey is the request context key of the TLS-SRP connection.
type srpConnKey struct{}

// ExampleWithSRPUsername serves EST over TLS-SRP and enrolls and renews with a username and
// password instead of certificates.
func ExampleWithSRPUsername() {
	ca, err := newExampleCA()
	if err != nil {
		log.Fatal(err)
	}

	// --8<-- [start:srp-server]
	// A real host stores the salt and verifier when it registers the device, never the password.
	group, err := srptls.GroupByBits(3072)
	if err != nil {
		log.Fatal(err)
	}
	salt, err := srptls.NewSalt(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	verifier, err := srptls.NewVerifier(group, []byte("device-5"), []byte("srp-secret"), salt)
	if err != nil {
		log.Fatal(err)
	}

	ln, err := srptls.Listen("tcp", "127.0.0.1:0", &srptls.Config{
		GetVerifier: func(info *srptls.ClientHelloInfo) (*srptls.Verifier, error) {
			if info.Username != "device-5" {
				return nil, srptls.ErrUnknownUsername
			}
			return verifier, nil
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	router, err := est.NewRouter(&est.ServerConfig{
		CA: ca,
		CheckBasicAuth: func(ctx context.Context, r *http.Request, aps, username, password string) error {
			if est.SRPUsernameFromContext(ctx) == "" {
				return errors.New("sign in with TLS-SRP")
			}
			return nil
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	srv := &http.Server{
		// net/http sets Request.TLS only for crypto/tls, so the handler reads the TLS-SRP
		// connection from the context and passes the username to the router.
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, ok := r.Context().Value(srpConnKey{}).(*srptls.Conn)
			if !ok {
				http.Error(w, "no TLS-SRP connection", http.StatusInternalServerError)
				return
			}
			ctx := est.WithSRPUsername(r.Context(), conn.ConnectionState().SRPUsername)
			router.ServeHTTP(w, r.WithContext(ctx))
		}),
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, srpConnKey{}, c)
		},
		// net/http logs handshake failures only for crypto/tls. Handshake returns the stored
		// error of a failed handshake.
		ConnState: func(c net.Conn, state http.ConnState) {
			conn, ok := c.(*srptls.Conn)
			if !ok || state != http.StateClosed || conn.ConnectionState().HandshakeComplete {
				return
			}
			if err := conn.Handshake(); err != nil {
				log.Printf("TLS-SRP handshake from %s failed: %v", c.RemoteAddr(), err)
			}
		},
		// The handshake runs in the first read, so this also bounds it.
		ReadHeaderTimeout: 30 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	// --8<-- [end:srp-server]

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	csr, err := newCSR(key, "device-5")
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()

	// --8<-- [start:srp-client]
	client := &est.Client{
		Host:        ln.Addr().String(),
		SRPUsername: "device-5",
		SRPPassword: "srp-secret",
	}

	cert, err := client.Enroll(ctx, csr)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("enrolled:", cert.Subject.CommonName)

	// The password signs the client in, so no client certificate is needed.
	renewed, err := client.Reenroll(ctx, csr)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("renewed:", renewed.Subject.CommonName)
	// --8<-- [end:srp-client]

	_ = srv.Close()

	// Output:
	// enrolled: device-5
	// renewed: device-5
}

// approvalCA defers every enrollment until an operator approves it.
type approvalCA struct {
	*exampleCA
}

// Enroll answers 202 Accepted and asks the client to retry in ten minutes.
func (ca approvalCA) Enroll(ctx context.Context, csr *x509.CertificateRequest, aps string, r *http.Request) (*x509.Certificate, error) {
	return nil, caError{status: http.StatusAccepted, msg: "waiting for approval", retryAfter: 600}
}

// ExampleError reads the status and the Retry-After value of a deferred enrollment.
func ExampleError() {
	ca, err := newExampleCA()
	if err != nil {
		log.Fatal(err)
	}
	router, err := est.NewRouter(&est.ServerConfig{CA: approvalCA{ca}})
	if err != nil {
		log.Fatal(err)
	}
	srv := httptest.NewTLSServer(router)
	client := exampleClient(srv)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	csr, err := newCSR(key, "device-6")
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()

	// --8<-- [start:error]
	_, err = client.Enroll(ctx, csr)
	if estErr, ok := errors.AsType[est.Error](err); ok {
		fmt.Println("status:", estErr.StatusCode())
		fmt.Println("retry after:", estErr.RetryAfter())
		fmt.Println("message:", strings.TrimSpace(estErr.Error()))
	}
	// --8<-- [end:error]

	srv.Close()

	// Output:
	// status: 202
	// retry after: 600
	// message: 202 waiting for approval
}

// --8<-- [start:refusals]
// printRefusals prints each request the server refuses without asking the CA.
type printRefusals struct{}

// RecordRefusal prints the operation, the status and the reason.
func (printRefusals) RecordRefusal(ctx context.Context, refusal est.Refusal) error {
	fmt.Printf("refused %s: %d %s\n", refusal.Operation, refusal.Status, refusal.Reason)
	return nil
}

// --8<-- [end:refusals]

// ExampleRefusalRecorder records a renewal that the server refuses because the client sent no
// certificate.
func ExampleRefusalRecorder() {
	ca, err := newExampleCA()
	if err != nil {
		log.Fatal(err)
	}
	srv, err := startExampleServer(ca, &est.ServerConfig{Refusals: printRefusals{}})
	if err != nil {
		log.Fatal(err)
	}
	client := exampleClient(srv)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	csr, err := newCSR(key, "device-7")
	if err != nil {
		log.Fatal(err)
	}

	if _, err := client.Reenroll(context.Background(), csr); err != nil {
		fmt.Println("client:", strings.TrimSpace(err.Error()))
	}

	srv.Close()

	// Output:
	// refused simplereenroll: 403 client certificate must be provided for /simplereenroll
	// client: 403 client certificate must be provided for /simplereenroll
}

// ExampleClient_hooks traces each request and reports the TLS version of each connection.
func ExampleClient_hooks() {
	ca, err := newExampleCA()
	if err != nil {
		log.Fatal(err)
	}
	srv, err := startExampleServer(ca, &est.ServerConfig{})
	if err != nil {
		log.Fatal(err)
	}
	client := exampleClient(srv)

	// --8<-- [start:hooks]
	client.OnConnect = func(conn net.Conn) {
		if c, ok := conn.(*tls.Conn); ok {
			fmt.Println("connected with", tls.VersionName(c.ConnectionState().Version))
		}
	}
	client.WrapTransport = func(next http.RoundTripper) http.RoundTripper {
		return roundTripFunc(func(r *http.Request) (*http.Response, error) {
			resp, err := next.RoundTrip(r)
			if err == nil {
				fmt.Println(r.Method, r.URL.Path, resp.Status)
			}
			return resp, err
		})
	}
	// --8<-- [end:hooks]

	if _, err := client.CACerts(context.Background()); err != nil {
		log.Fatal(err)
	}

	srv.Close()

	// Output:
	// connected with TLS 1.3
	// GET /.well-known/est/cacerts 200 OK
}

// roundTripFunc adapts a function to http.RoundTripper.
type roundTripFunc func(*http.Request) (*http.Response, error)

// RoundTrip calls f.
func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// ExampleClient_proxy configures a client that reaches the server through an HTTP proxy and signs
// in with a bearer token. It is compiled but not run.
func ExampleClient_proxy() {
	// --8<-- [start:proxy]
	proxyURL, err := url.Parse("http://proxy-user:proxy-secret@proxy.example.com:3128")
	if err != nil {
		log.Fatal(err)
	}
	client := &est.Client{
		Host:        "est.example.com:8443",
		Proxy:       http.ProxyURL(proxyURL),
		BearerToken: "token-from-the-identity-provider",
	}
	// --8<-- [end:proxy]
	_ = client
}

// ExampleClient_mldsa enrolls an ML-DSA-65 key and renews the certificate over TLS 1.3, which
// accepts an ML-DSA client certificate.
func ExampleClient_mldsa() {
	ca, err := newExampleCA()
	if err != nil {
		log.Fatal(err)
	}
	srv, err := startExampleServer(ca, &est.ServerConfig{})
	if err != nil {
		log.Fatal(err)
	}
	client := exampleClient(srv)
	ctx := context.Background()

	// --8<-- [start:mldsa]
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		log.Fatal(err)
	}
	csr, err := newCSR(key, "device-8")
	if err != nil {
		log.Fatal(err)
	}
	cert, err := client.Enroll(ctx, csr)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("enrolled: %s with %T\n", cert.Subject.CommonName, cert.PublicKey)

	// The ML-DSA certificate authenticates the renewal.
	client.Certificates = []*x509.Certificate{cert}
	client.PrivateKey = key
	client.OnConnect = func(conn net.Conn) {
		fmt.Println("renewing over", tls.VersionName(conn.(*tls.Conn).ConnectionState().Version))
	}
	renewed, err := client.Reenroll(ctx, csr)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("renewed:", renewed.Subject.CommonName)
	// --8<-- [end:mldsa]

	srv.Close()

	// Output:
	// enrolled: device-8 with *mldsa.PublicKey
	// renewing over TLS 1.3
	// renewed: device-8
}
