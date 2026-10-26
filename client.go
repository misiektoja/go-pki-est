/*
Copyright (c) 2020 GMO GlobalSign, Inc.

Licensed under the MIT License (the "License"); you may not use this file except
in compliance with the License. You may obtain a copy of the License at

https://opensource.org/licenses/MIT

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package est

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	srptls "github.com/misiektoja/go-tls-srp"
	"github.com/smallstep/scep/x509util"
)

const (
	tcpProtocol string = "tcp"
)

// Client is an EST client implementing the Enrollment over Secure Transport
// protocol as defined in RFC7030.
//
// All EST client operations will return an error object implementing Error
// when the EST server returns any status other than 200 OK. The status code,
// description and, if applicable, retry-after seconds can be extracted from
// that object. In order to make the retry-after seconds available through
// this mechanism, note that a 202 Accepted response to enroll and reenroll
// operations is returned as an error for this purpose, even though 2** status
// codes indicate success.
type Client struct {
	// Host is the host:path of the EST server excluding any URL path
	// component, e.g. est.server.com:8443
	Host string

	// AdditionalPathSegment is an optional label for EST servers to provide
	// service for multiple CAs. See RFC7030 3.2.2.
	AdditionalPathSegment string

	// ExplicitAnchor is the optional Explicit TA database. See RFC7030 3.6.1.
	ExplicitAnchor *x509.CertPool

	// ImplicitAnchor is an optional Implicit TA database. If nil, the system
	// certificate pool will be used. See RFC7030 3.6.2.
	ImplicitAnchor *x509.CertPool

	// Certificates are the client certificates to present to the EST server
	// during the handshake. If more than one certificate is provided, they
	// should be provided in order, with the end-entity certificate first, and
	// the root CA (or last intermediate CA) certificate last.
	Certificates []*x509.Certificate

	// PrivateKey is the private key associated with the end-entity TLS
	// certificate. Any object implementing crypto.Signer may be used, to
	// support private keys resident on a hardware security module (HSM),
	// Trusted Platform Module (TPM) or other hardware device.
	PrivateKey interface{}

	// SigningKey is an optional private key to use for signing CSRs during initial enrollment.
	//
	// If not set, the challenge password field will not be included in the CSR.
	SigningKey interface{}

	// AdditionalHeaders are additional HTTP headers to include with the
	// request to the EST server.
	AdditionalHeaders map[string]string

	// HostHeader overrides the default Host header for the HTTP request to the
	// EST server, and is mostly useful for testing.
	HostHeader string

	// Username is an optional HTTP Basic Authentication username.
	Username string

	// Password is an optional HTTP Basic Authentication password.
	Password string

	// BearerToken is an optional HTTP Bearer authentication token (RFC
	// 6750). It is sent as "Authorization: Bearer <token>" when Username is
	// empty, so Basic authentication takes precedence.
	BearerToken string

	// DisableKeepAlives disables HTTP keep-alives if set.
	DisableKeepAlives bool

	// Proxy returns the proxy for the connection to the EST server, as
	// http.Transport.Proxy does, or nil for a direct connection. If Proxy
	// is nil, http.ProxyFromEnvironment applies, so the HTTPS_PROXY and
	// NO_PROXY environment variables choose the proxy. The client reaches
	// the server through an http or https proxy with a CONNECT tunnel, so
	// the TLS handshake, OnConnect and the tls-unique value work as without
	// a proxy. The user information of the proxy URL is sent as Basic
	// Proxy-Authorization. An https proxy is checked against the system
	// roots.
	Proxy func(*http.Request) (*url.URL, error)

	// InsecureSkipVerify controls whether the client verifies the EST server's
	// certificate chain and host name. If true, the client accepts any
	// certificate presented by the server and any host name in that certificate.
	// In this mode, TLS is susceptible to man-in-the-middle attacks. This should
	// be used only for testing. If used to obtain the CA certificates from an
	// otherwise untrusted EST server, those certificates must be manually
	// verified in some out-of-band manner before any further EST operations with
	// that server are performed.
	InsecureSkipVerify bool

	// WrapTransport, if set, wraps the HTTP transport of every request. The
	// wrapper sees each request and response, for example to record a
	// protocol trace, and must pass every request on to the transport it
	// wraps. The transport it wraps already bounds response bodies with
	// MaxResponseBody.
	WrapTransport func(http.RoundTripper) http.RoundTripper

	// OnConnect, if set, is called with the connection of each operation
	// after the TLS handshake and before the request is sent. The connection
	// is a *tls.Conn, or a *srptls.Conn with TLS-SRP. OnConnect must not read
	// from, write to or close it.
	OnConnect func(net.Conn)

	// AllowCertificateChain accepts an enroll, reenroll or serverkeygen
	// response that carries CA certificates besides the issued certificate.
	// RFC 7030 section 4.2.3 allows only the issued certificate, but some
	// servers add its chain. The client then returns the one certificate
	// that issued none of the others.
	AllowCertificateChain bool

	// MaxResponseBody bounds the size of a response body in bytes, including
	// an error message and all parts of a multipart response. A larger
	// response fails the operation. If zero, 1 MiB is used. A chain of large
	// post-quantum CA certificates can exceed that, such as SLH-DSA-SHA2-256f
	// certificates at about 50 KB each in base64. A negative value fails
	// every operation.
	MaxResponseBody int64

	// SRPUsername, if set, signs in with TLS-SRP (RFC 5054) as this user
	// with SRPPassword, as RFC 7030 section 3.3.3 allows. The password also
	// authenticates the server, so ExplicitAnchor, ImplicitAnchor,
	// InsecureSkipVerify and Certificates are not used. TLS-SRP runs over
	// TLS 1.2 only. OnConnect then receives a *srptls.Conn from
	// github.com/misiektoja/go-tls-srp.
	SRPUsername string

	// SRPPassword is the TLS-SRP password of SRPUsername.
	SRPPassword string

	// SRPMinGroupBits is the size of the smallest SRP group the client
	// accepts from the server. If zero, 2048 bits.
	SRPMinGroupBits int
}

// clientConn is the connection of one operation.
type clientConn struct {
	net.Conn
	// tlsUnique is the tls-unique value of the connection. It is nil for
	// TLS 1.3, which has none.
	tlsUnique []byte
}

// Client constants.
const (
	estVersion = "v1.3.1"
	userAgent  = "go-pki-est EST client " + estVersion + " github.com/misiektoja/go-pki-est"

	defaultMaxResponseBody = 1 << 20
)

// CACerts requests a copy of the current CA certificates.
func (c *Client) CACerts(ctx context.Context) ([]*x509.Certificate, error) {
	req, err := c.newRequest(ctx, http.MethodGet, cacertsEndpoint, "", "", mimeTypePKCS7, nil)
	if err != nil {
		return nil, err
	}

	httpc, conn, err := c.makeHTTPClient(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	resp, err := httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute HTTP request: %w", err)
	}
	defer consumeAndClose(resp)

	if err := checkResponseError(resp); err != nil {
		return nil, err
	}

	if err := verifyResponseType(resp, mimeTypePKCS7); err != nil {
		return nil, err
	}

	return readCertsResponse(resp.Body)
}

// CSRAttrs requests a list of CA-desired CSR attributes.
func (c *Client) CSRAttrs(ctx context.Context) (CSRAttrs, error) {
	req, err := c.newRequest(ctx, http.MethodGet, csrattrsEndpoint, "", "", mimeTypeCSRAttrs, nil)
	if err != nil {
		return CSRAttrs{}, err
	}

	httpc, conn, err := c.makeHTTPClient(ctx)
	if err != nil {
		return CSRAttrs{}, err
	}
	defer func() { _ = conn.Close() }()

	resp, err := httpc.Do(req)
	if err != nil {
		return CSRAttrs{}, fmt.Errorf("failed to execute HTTP request: %w", err)
	}
	defer consumeAndClose(resp)

	if err := checkResponseError(resp); err != nil {
		// Per RFC7030 section 4.5.2, an HTTP response code of 204 or 404
		// indicates that a CSR attributes response is not available, and that
		// this is functionally equivalent to returning an empty SEQUENCE
		// indicating that the server has no specific additional information
		// it desires in a client certification request. Therefore we do not
		// treat these two response codes as errors, and we just return an
		// empty CSR attributes object.
		if estErr, ok := errors.AsType[Error](err); ok && (estErr.StatusCode() == http.StatusNotFound ||
			estErr.StatusCode() == http.StatusNoContent) {
			return CSRAttrs{}, nil
		}

		return CSRAttrs{}, err
	}

	if err := verifyResponseType(resp, mimeTypeCSRAttrs); err != nil {
		return CSRAttrs{}, err
	}

	return readCSRAttrsResponse(resp.Body)
}

// Enroll requests a new certificate.
func (c *Client) Enroll(ctx context.Context, r *x509.CertificateRequest) (*x509.Certificate, error) {
	return c.enrollCommon(ctx, r, false)
}

// Reenroll renews an existing certificate.
func (c *Client) Reenroll(ctx context.Context, r *x509.CertificateRequest) (*x509.Certificate, error) {
	return c.enrollCommon(ctx, r, true)
}

// Enroll requests a new certificate.
func (c *Client) enrollCommon(ctx context.Context, r *x509.CertificateRequest, renew bool) (*x509.Certificate, error) {
	var endpoint = enrollEndpoint
	if renew {
		endpoint = reenrollEndpoint
	}

	httpc, conn, err := c.makeHTTPClient(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	// RFC 7030 section 3.5 recommends including the tls-unique value in the
	// CSR challenge password. It is not available with TLS 1.3.
	// See https://pkg.go.dev/crypto/tls#ConnectionState.TLSUnique.
	crBs := r.Raw
	if tlsu := conn.tlsUnique; tlsu != nil && c.SigningKey != nil {
		crBs, err = c.addChallengePassword(r.Raw, base64.StdEncoding.EncodeToString(tlsu))
		if err != nil {
			return nil, err
		}
	}

	// A *bytes.Reader body lets the request carry its Content-Length. Some EST servers, such as
	// the libest example server, cannot read a chunked body.
	reqBody := bytes.NewReader(base64Encode(crBs))
	req, err := c.newRequest(ctx, http.MethodPost, endpoint, mimeTypePKCS10, encodingTypeBase64, mimeTypePKCS7, reqBody)
	if err != nil {
		return nil, err
	}

	resp, err := httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute HTTP request: %w", err)
	}
	defer consumeAndClose(resp)

	if err := checkResponseError(resp); err != nil {
		return nil, err
	}

	if err := verifyResponseType(resp, mimeTypePKCS7); err != nil {
		return nil, err
	}

	return readCertResponse(resp.Body, c.AllowCertificateChain)
}

// ServerKeyGen requests a new certificate and a server-generated private key.
func (c *Client) ServerKeyGen(ctx context.Context, r *x509.CertificateRequest) (*x509.Certificate, []byte, error) {
	reqBody := bytes.NewReader(base64Encode(r.Raw))

	req, err := c.newRequest(ctx, http.MethodPost, serverkeygenEndpoint,
		mimeTypePKCS10, encodingTypeBase64, mimeTypeMultipart, reqBody)
	if err != nil {
		return nil, nil, err
	}

	httpc, conn, err := c.makeHTTPClient(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = conn.Close() }()

	resp, err := httpc.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to execute HTTP request: %w", err)
	}
	defer consumeAndClose(resp)

	if err := checkResponseError(resp); err != nil {
		return nil, nil, err
	}

	// Ensure overall content-type is as expected.
	mediaType, params, err := mime.ParseMediaType(resp.Header.Get(contentTypeHeader))
	if err != nil {
		return nil, nil, fmt.Errorf("missing or malformed %s header: %w", contentTypeHeader, err)
	} else if !strings.HasPrefix(mediaType, mimeTypeMultipart) {
		return nil, nil, fmt.Errorf("unexpected %s: %s", contentTypeHeader, mediaType)
	}

	mpr := multipart.NewReader(resp.Body, params[mimeParamBoundary])

	var cert *x509.Certificate
	var key []byte

	// Process all the parts.
	var numParts = 2
	for i := 1; ; i++ {
		// First, break if there are no more parts in the response.
		part, err := mpr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, nil, fmt.Errorf("failed to read HTTP response part: %w", readError(resp, err))
		}
		defer func() { _ = part.Close() }()

		// Return with error if there are more parts than we expect.
		if i > numParts {
			return nil, nil, fmt.Errorf("more than %d parts in HTTP response", numParts)
		}

		// Process based on the part's content-type. Per RFC7030 4.4.2, if
		// additional encryption is not being employed, the private key data
		// must be placed in an application/pkcs8 part. Otherwise, it must
		// be placed in an application/pkcs7-mime part with an smime-type
		// parameter of "server-generated-key". The certificate response
		// matches that for /simpleenroll and /simplereenroll, namely an
		// application/pkcs7-mime part with an smime-type parameter of
		// "certs-only" (RFC7040 4.2.3).
		mediaType, params, err := mime.ParseMediaType(part.Header.Get(contentTypeHeader))
		if err != nil {
			return nil, nil, fmt.Errorf("missing or malformed %s header: %w", contentTypeHeader, err)
		}

		switch {
		case strings.HasPrefix(mediaType, mimeTypePKCS8):
			key, err = readAllBase64Response(part)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to read HTTP response part: %w", err)
			}

		case strings.HasPrefix(mediaType, mimeTypePKCS7):
			t := params[mimeParamSMIMEType]

			switch t {
			case paramValueGenKey:
				key, err = readAllBase64Response(part)
				if err != nil {
					return nil, nil, fmt.Errorf("failed to read HTTP response part: %w", err)
				}

			case paramValueCertsOnly:
				cert, err = readCertResponse(part, c.AllowCertificateChain)
				if err != nil {
					return nil, nil, err
				}

			default:
				return nil, nil, fmt.Errorf("unexpected %s: %s", mimeParamSMIMEType, t)

			}

		default:
			return nil, nil, fmt.Errorf("unexpected %s: %s", contentTypeHeader, mediaType)
		}
	}

	// Ensure both parts were returned.
	if cert == nil {
		return nil, nil, errors.New("no certificate returned")
	} else if key == nil {
		return nil, nil, errors.New("no private key returned")
	}

	return cert, key, nil
}

// TPMEnroll requests a certificate using the TPM 2.0 privacy preserving
// protocol for distributing credentials for keys on a TPM.
func (c *Client) TPMEnroll(
	ctx context.Context,
	r *x509.CertificateRequest,
	ekCerts []*x509.Certificate,
	ekPub []byte,
	akPub []byte,
) ([]byte, []byte, []byte, error) {
	buf, contentType, err := encodeMultiPart(
		tpmEnrollBoundary,
		[]multipartPart{
			{contentType: mimeTypePKCS10, data: r},
			{contentType: mimeTypePKCS7CertsOnly, data: ekCerts},
			{contentType: mimeTypeOctetStream, data: ekPub},
			{contentType: mimeTypeOctetStream, data: akPub},
		},
		true,
	)
	if err != nil {
		return nil, nil, nil, err
	}

	req, err := c.newRequest(ctx, http.MethodPost, tpmenrollEndpoint,
		contentType, "", mimeTypeMultipart, buf)
	if err != nil {
		return nil, nil, nil, err
	}

	httpc, conn, err := c.makeHTTPClient(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	defer func() { _ = conn.Close() }()

	resp, err := httpc.Do(req)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to execute HTTP request: %w", err)
	}
	defer consumeAndClose(resp)

	if err := checkResponseError(resp); err != nil {
		return nil, nil, nil, err
	}

	// Ensure overall content-type is as expected.
	mediaType, params, err := mime.ParseMediaType(resp.Header.Get(contentTypeHeader))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("missing or malformed %s header: %w", contentTypeHeader, err)
	} else if !strings.HasPrefix(mediaType, mimeTypeMultipart) {
		return nil, nil, nil, fmt.Errorf("unexpected %s: %s", contentTypeHeader, mediaType)
	}

	mpr := multipart.NewReader(resp.Body, params[mimeParamBoundary])

	var credBlob []byte
	var encSeed []byte
	var cred []byte

	var parts = []struct {
		ctype string
		data  *[]byte
	}{
		{mimeTypeOctetStream, &credBlob},
		{mimeTypeOctetStream, &encSeed},
		{mimeTypePKCS7, &cred},
	}

	// Process all the parts.
	var numParts = 3
	for i := 1; ; i++ {
		// First, break if there are no more parts in the response.
		part, err := mpr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to get next HTTP response part: %w", readError(resp, err))
		}
		defer func() { _ = part.Close() }()

		// Return with error if there are more parts than we expect.
		if i > numParts {
			return nil, nil, nil, fmt.Errorf("more than %d parts in HTTP response", numParts)
		}

		// Check content-transfer-encoding is as expected, and read the part
		// body.
		if err := verifyPartTypeResponse(part, parts[i-1].ctype); err != nil {
			return nil, nil, nil, err
		}

		*parts[i-1].data, err = readAllBase64Response(part)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to read HTTP response part: %w", err)
		}
	}

	return credBlob, encSeed, cred, nil
}

// newRequest builds an HTTP request for an EST operation.
func (c *Client) newRequest(
	ctx context.Context,
	method, endpoint string,
	contentType, transferEncoding string,
	accepts string,
	body io.Reader,
) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.uri(endpoint), body)
	if err != nil {
		return nil, fmt.Errorf("failed to make new HTTP request: %w", err)
	}

	req.Close = c.DisableKeepAlives
	req.Header.Set(userAgentHeader, userAgent)
	if accepts != "" {
		req.Header.Set(acceptHeader, accepts)
	}
	if contentType != "" {
		req.Header.Set(contentTypeHeader, contentType)
	}
	if transferEncoding != "" {
		req.Header.Set(transferEncodingHeader, transferEncoding)
	}

	if c.HostHeader != "" {
		req.Host = c.HostHeader
	}

	switch {
	case c.Username != "":
		req.SetBasicAuth(c.Username, c.Password)
	case c.BearerToken != "":
		req.Header.Set("Authorization", "Bearer "+c.BearerToken)
	}

	for k, v := range c.AdditionalHeaders {
		req.Header.Add(k, v)
	}

	return req, err
}

// addChallengePassword returns a new CSR based on the input csr.
// The challenge password corresponds to the tls-unique value base64 encoded (only in TLS 1.2)
func (c *Client) addChallengePassword(csr []byte, challengePassword string) ([]byte, error) {
	if challengePassword == "" {
		return csr, nil
	}

	stdCsr, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		return nil, err
	}

	// Rebuild extensionRequest from Extensions to preserve critical values.
	cr := x509util.CertificateRequest{
		RawSubject:         stdCsr.RawSubject,
		ExtraExtensions:    stdCsr.Extensions,
		SignatureAlgorithm: stdCsr.SignatureAlgorithm,
		ChallengePassword:  challengePassword,
	}
	for _, attr := range stdCsr.Attributes {
		if !attr.Type.Equal(oidExtensionRequest) {
			cr.Attributes = append(cr.Attributes, attr)
		}
	}
	crBs, err := x509util.CreateCertificateRequest(rand.Reader, &cr, c.SigningKey)
	return crBs, err
}

// checkResponseError returns nil if the HTTP response status code is 200 OK,
// otherwise it returns an error object implementing est.Error. In order to
// parse the Retry-After header and return a value, note that 202 Accepted
// is treated as an error for this purpose. A body that cannot be read still
// yields an est.Error with the response status, so callers can act on it.
// Control characters in the message other than newline and tab are escaped,
// so a server cannot send terminal escape sequences to whoever prints it.
func checkResponseError(r *http.Response) error {
	if r.StatusCode == http.StatusOK {
		return nil
	}

	// Attempt to extract human-readable error message from the HTTP
	// response body, if the content type permits or if it is not set.
	// RFC7030 states in section 4.2.3 for enroll and reenroll operations,
	// and in 4.4.2 for server key generation operations, that if the
	// content-type is not set, the response data MUST be a plaintext
	// human-readable error message. No such requirements are stipulated
	// for any of the other operations, but we here make the same assumptions.
	//
	// TODO(paul): Section 4.2.3 permits an application/pkcs-mime simple PKI
	// response also to be used to convey an error response for enroll and
	// reenroll operations.
	var msg string
	mediaType, _, err := mime.ParseMediaType(r.Header.Get(contentTypeHeader))
	if err == nil || r.Header.Get(contentTypeHeader) == "" {
		switch mediaType {
		case "", mimeTypeTextPlain, mimeTypeJSON, mimeTypeProblemJSON:
			data, err := io.ReadAll(r.Body)
			switch {
			case err != nil:
				msg = fmt.Sprintf("%s (failed to read response body: %v)",
					http.StatusText(r.StatusCode), err)
			case len(data) > 0:
				msg = escapeControls(string(data))
			default:
				msg = http.StatusText(r.StatusCode)
			}

		default:
			msg = fmt.Sprintf("%s (%s)",
				http.StatusText(r.StatusCode), mediaType)
		}
	}

	// Parse Retry-After header if present. Per RFC7231 7.1.3, the value
	// of a Retry-After header may be either an HTTP-date or a number of
	// seconds to delay after the response is received.
	var retryAfter int
	if secs := r.Header.Get(retryAfterHeader); secs != "" {
		retryAfter, err = strconv.Atoi(secs)
		if err != nil {
			if t, err := parseHTTPTime(secs); err == nil {
				retryAfter = int(time.Until(t).Seconds())
			}
		}

		if retryAfter < 0 {
			retryAfter = 0
		}
	}

	return &estError{
		status:     r.StatusCode,
		desc:       msg,
		retryAfter: retryAfter,
	}
}

// escapeControls returns s with every control character other than newline
// and tab in the Go escape form, such as \x1b, so text a server sent can be
// printed without acting on a terminal.
func escapeControls(s string) string {
	if !strings.ContainsFunc(s, isUnsafeControl) {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if isUnsafeControl(r) {
			b.WriteString(fmt.Sprintf("\\x%02x", r))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// isUnsafeControl reports whether r is a control character that may act on a
// terminal: every C0 and C1 control and DEL except newline and tab.
func isUnsafeControl(r rune) bool {
	return unicode.IsControl(r) && r != '\n' && r != '\t'
}

// uri builds an EST URI for the specified endpoint, using the optional
// additional path segment if appropriate.
func (c *Client) uri(endpoint string) string {
	var builder strings.Builder

	builder.WriteString("https://")
	builder.WriteString(c.Host)
	builder.WriteString(estPathPrefix)

	if c.AdditionalPathSegment != "" {
		builder.WriteRune('/')
		builder.WriteString(c.AdditionalPathSegment)
	}

	builder.WriteString(endpoint)

	return builder.String()
}

// makeHTTPClient makes and configures an HTTP client for connecting to an
// EST server. It also returns the TLS connection, which the caller must close.
// The client refuses redirects and bounds response bodies with
// MaxResponseBody before WrapTransport sees them.
func (c *Client) makeHTTPClient(ctx context.Context) (*http.Client, *clientConn, error) {
	maxBody := int64(defaultMaxResponseBody)
	switch {
	case c.MaxResponseBody < 0:
		return nil, nil, errors.New("MaxResponseBody must not be negative")
	case c.MaxResponseBody > 0:
		maxBody = c.MaxResponseBody
	}

	conn, err := c.dial(ctx)
	if err != nil {
		return nil, nil, err
	}

	if c.OnConnect != nil {
		c.OnConnect(conn.Conn)
	}

	var transport http.RoundTripper = &boundResponses{
		next: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return conn.Conn, nil
			},
			DisableKeepAlives: c.DisableKeepAlives,
		},
		max: maxBody,
	}
	if c.WrapTransport != nil {
		transport = c.WrapTransport(transport)
	}

	return &http.Client{Transport: transport, CheckRedirect: refuseRedirect}, conn, nil
}

// refuseRedirect makes http.Client return a 3xx response instead of following
// it. RFC 7030 section 3.2.1 allows only redirects within the same origin and
// the client already holds a connection to the one server it was configured
// with. Following a redirect would also send the request's credentials to the
// new location, in cleartext for an http URL.
func refuseRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

// dial connects to the EST server, through a proxy when one applies, and
// completes the TLS handshake, with TLS-SRP when SRPUsername is set.
func (c *Client) dial(ctx context.Context) (*clientConn, error) {
	raw, err := c.dialTCP(ctx)
	if err != nil {
		return nil, err
	}
	if c.SRPUsername != "" {
		return c.handshakeSRP(ctx, raw)
	}
	return c.handshakeTLS(ctx, raw)
}

// dialTCP opens the TCP connection to the EST server, through a CONNECT
// tunnel when Proxy or the environment names a proxy.
func (c *Client) dialTCP(ctx context.Context) (net.Conn, error) {
	proxyURL, err := c.proxyURL(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to choose a proxy: %w", err)
	}
	if proxyURL == nil {
		return (&net.Dialer{}).DialContext(ctx, tcpProtocol, c.Host)
	}
	return dialThroughProxy(ctx, proxyURL, c.Host)
}

// proxyURL returns the proxy for the EST server, or nil for a direct
// connection.
func (c *Client) proxyURL(ctx context.Context) (*url.URL, error) {
	proxy := c.Proxy
	if proxy == nil {
		proxy = http.ProxyFromEnvironment
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.uri(""), nil)
	if err != nil {
		return nil, err
	}
	return proxy(req)
}

// dialThroughProxy connects to proxyURL and asks it for a CONNECT tunnel to
// target. An https proxy is reached over TLS and checked against the system
// roots. The user information of proxyURL is sent as Basic
// Proxy-Authorization.
func dialThroughProxy(ctx context.Context, proxyURL *url.URL, target string) (net.Conn, error) {
	var (
		addr string
		conn net.Conn
		err  error
	)
	switch proxyURL.Scheme {
	case "http":
		addr = withDefaultPort(proxyURL.Host, "80")
		conn, err = (&net.Dialer{}).DialContext(ctx, tcpProtocol, addr)
	case "https":
		addr = withDefaultPort(proxyURL.Host, "443")
		dialer := &tls.Dialer{Config: &tls.Config{MinVersion: tls.VersionTLS12}}
		conn, err = dialer.DialContext(ctx, tcpProtocol, addr)
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q, want http or https", proxyURL.Scheme)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to connect to proxy %s: %w", addr, err)
	}

	// A canceled context closes the connection, which ends the exchange.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: target},
		Host:   target,
		Header: http.Header{},
	}
	if user := proxyURL.User; user != nil {
		password, _ := user.Password()
		credentials := base64.StdEncoding.EncodeToString([]byte(user.Username() + ":" + password))
		req.Header.Set("Proxy-Authorization", "Basic "+credentials)
	}
	// fail closes the connection and reports the step that failed, or the
	// canceled context that closed the connection.
	fail := func(step string, err error) (net.Conn, error) {
		_ = conn.Close()
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, fmt.Errorf("failed to %s proxy %s: %w", step, addr, err)
	}
	if err := req.Write(conn); err != nil {
		return fail("send CONNECT to", err)
	}
	// The tunnel data follows the response headers, so the body is never read or closed.
	resp, err := http.ReadResponse(bufio.NewReader(conn), req) //nolint:bodyclose
	if err != nil {
		return fail("read the CONNECT response of", err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		return nil, fmt.Errorf("proxy %s refused the tunnel to %s: %s", addr, target, resp.Status)
	}
	if err := ctx.Err(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// withDefaultPort adds port to addr when it names no port.
func withDefaultPort(addr, port string) string {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return net.JoinHostPort(addr, port)
	}
	return addr
}

// serverName returns the host of Host without the port, for the TLS server
// name.
func (c *Client) serverName() string {
	host, _, err := net.SplitHostPort(c.Host)
	if err != nil {
		return c.Host
	}
	return host
}

// handshakeTLS completes the TLS handshake with the EST server on raw and
// closes raw when it fails.
func (c *Client) handshakeTLS(ctx context.Context, raw net.Conn) (*clientConn, error) {
	var rootCAs *x509.CertPool
	if c.ExplicitAnchor != nil {
		rootCAs = c.ExplicitAnchor
	} else if c.ImplicitAnchor != nil {
		rootCAs = c.ImplicitAnchor
	}

	var tlsCerts []tls.Certificate
	if len(c.Certificates) > 0 && c.PrivateKey != nil {
		tlsCerts = []tls.Certificate{{PrivateKey: c.PrivateKey, Leaf: c.Certificates[0]}}
		for i := range c.Certificates {
			tlsCerts[0].Certificate = append(tlsCerts[0].Certificate, c.Certificates[i].Raw)
		}
	}

	tlsClientConfig := &tls.Config{
		RootCAs:      rootCAs,
		Certificates: tlsCerts,
		ServerName:   c.serverName(),
		//nolint:gosec // G402: the caller opts in to fetch /cacerts for out-of-band verification, as the field documents.
		InsecureSkipVerify: c.InsecureSkipVerify,
	}

	conn := tls.Client(raw, tlsClientConfig)
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &clientConn{Conn: conn, tlsUnique: conn.ConnectionState().TLSUnique}, nil
}

// handshakeSRP signs in with TLS-SRP on raw and closes raw when it fails.
func (c *Client) handshakeSRP(ctx context.Context, raw net.Conn) (*clientConn, error) {
	conn := srptls.Client(raw, &srptls.Config{
		Username:     c.SRPUsername,
		Password:     c.SRPPassword,
		ServerName:   c.serverName(),
		MinGroupBits: c.SRPMinGroupBits,
	})
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &clientConn{Conn: conn, tlsUnique: conn.ConnectionState().TLSUnique}, nil
}
