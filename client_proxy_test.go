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
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	est "github.com/misiektoja/go-pki-est"
	"github.com/misiektoja/go-pki-est/internal/mockca"
)

// testProxy is an HTTP proxy that tunnels CONNECT requests and records them.
type testProxy struct {
	mu      sync.Mutex
	targets []string
	auth    []string
	// refuse answers every CONNECT with 403 Forbidden.
	refuse bool
	// hang leaves every CONNECT unanswered until stopped is closed.
	hang    bool
	stopped chan struct{}
}

// newTestProxy starts a proxy and returns it with its URL, which carries userinfo.
func newTestProxy(t *testing.T, userinfo *url.Userinfo) (*testProxy, *url.URL) {
	t.Helper()
	p := &testProxy{stopped: make(chan struct{})}
	srv := httptest.NewServer(p)
	t.Cleanup(func() {
		close(p.stopped)
		srv.Close()
	})
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	u.User = userinfo
	return p, u
}

// configure changes the behaviour of the proxy before a test uses it.
func (p *testProxy) configure(refuse, hang bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.refuse, p.hang = refuse, hang
}

// connects returns the CONNECT targets and Proxy-Authorization values seen so far.
func (p *testProxy) connects() (targets, auth []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.targets...), append([]string(nil), p.auth...)
}

// ServeHTTP tunnels a CONNECT request to its target.
func (p *testProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "only CONNECT is served", http.StatusMethodNotAllowed)
		return
	}
	p.mu.Lock()
	p.targets = append(p.targets, r.Host)
	p.auth = append(p.auth, r.Header.Get("Proxy-Authorization"))
	refuse, hang := p.refuse, p.hang
	p.mu.Unlock()
	switch {
	case hang:
		<-p.stopped
		return
	case refuse:
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	upstream, err := net.DialTimeout("tcp", r.Host, testTimeout)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer func() { _ = upstream.Close() }()
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "the connection cannot be hijacked", http.StatusInternalServerError)
		return
	}
	client, _, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer func() { _ = client.Close() }()
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		return
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.Copy(upstream, client)
		closeWrite(upstream)
	}()
	_, _ = io.Copy(client, upstream)
	closeWrite(client)
	<-done
}

// closeWrite half-closes a TCP connection, so the other side reads EOF.
func closeWrite(conn net.Conn) {
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

// TestClientProxy checks that the client tunnels through the proxy of Proxy with CONNECT, sends
// the credentials of the proxy URL and still sees the TLS connection of each operation.
func TestClientProxy(t *testing.T) {
	t.Parallel()

	srv, newClient := newTestServer(t)
	defer srv.Close()
	proxy, proxyURL := newTestProxy(t, url.UserPassword("device", "s3cret"))

	client := newClient()
	client.Proxy = http.ProxyURL(proxyURL)
	tlsConns := 0
	client.OnConnect = func(conn net.Conn) {
		if _, ok := conn.(*tls.Conn); ok {
			tlsConns++
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	if _, err := client.CACerts(ctx); err != nil {
		t.Fatalf("CACerts through the proxy: %v", err)
	}
	if _, err := client.CSRAttrs(ctx); err != nil {
		t.Fatalf("CSRAttrs through the proxy: %v", err)
	}

	targets, auth := proxy.connects()
	if len(targets) != 2 || targets[0] != client.Host || targets[1] != client.Host {
		t.Errorf("CONNECT targets %v, want %s twice", targets, client.Host)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("device:s3cret"))
	for _, got := range auth {
		if got != want {
			t.Errorf("Proxy-Authorization %q, want %q", got, want)
		}
	}
	if tlsConns != 2 {
		t.Errorf("OnConnect saw %d TLS connections, want 2", tlsConns)
	}
}

// TestClientProxySRP checks that TLS-SRP signs in through a proxy tunnel.
func TestClientProxySRP(t *testing.T) {
	t.Parallel()

	ca, err := mockca.NewTransient()
	if err != nil {
		t.Fatal(err)
	}
	addr := newSRPServer(t, ca, "device-42", "s3cret")
	proxy, proxyURL := newTestProxy(t, nil)

	client := &est.Client{Host: addr, SRPUsername: "device-42", SRPPassword: "s3cret", Proxy: http.ProxyURL(proxyURL)}
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	certs, err := client.CACerts(ctx)
	if err != nil {
		t.Fatalf("CACerts over TLS-SRP through the proxy: %v", err)
	}
	if len(certs) == 0 {
		t.Error("no CA certificates")
	}
	if targets, _ := proxy.connects(); len(targets) != 1 || targets[0] != addr {
		t.Errorf("CONNECT targets %v, want %s", targets, addr)
	}
}

// TestClientProxyDirect checks that a Proxy function that names no proxy connects directly.
func TestClientProxyDirect(t *testing.T) {
	t.Parallel()

	srv, newClient := newTestServer(t)
	defer srv.Close()
	client := newClient()
	client.Proxy = func(*http.Request) (*url.URL, error) { return nil, nil }
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	if _, err := client.CACerts(ctx); err != nil {
		t.Fatalf("CACerts without a proxy: %v", err)
	}
}

// TestClientProxyErrors checks the errors for a proxy that refuses the tunnel, cannot be reached
// or has an unsupported scheme, and for a Proxy function that fails.
func TestClientProxyErrors(t *testing.T) {
	t.Parallel()

	srv, newClient := newTestServer(t)
	defer srv.Close()
	refusing, refusingURL := newTestProxy(t, nil)
	refusing.configure(true, false)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	downURL := &url.URL{Scheme: "http", Host: ln.Addr().String()}
	_ = ln.Close()

	for name, tt := range map[string]struct {
		proxy func(*http.Request) (*url.URL, error)
		want  string
	}{
		"refused":     {http.ProxyURL(refusingURL), "refused the tunnel"},
		"unreachable": {http.ProxyURL(downURL), "failed to connect to proxy"},
		"scheme":      {http.ProxyURL(&url.URL{Scheme: "socks5", Host: "127.0.0.1:1080"}), "unsupported proxy scheme"},
		"chooser": {func(*http.Request) (*url.URL, error) {
			return nil, errors.New("no proxy today")
		}, "failed to choose a proxy"},
	} {
		t.Run(name, func(t *testing.T) {
			client := newClient()
			client.Proxy = tt.proxy
			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()
			if _, err := client.CACerts(ctx); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

// TestClientProxyCanceled checks that a context deadline ends a CONNECT exchange that the proxy
// never answers.
func TestClientProxyCanceled(t *testing.T) {
	t.Parallel()

	srv, newClient := newTestServer(t)
	defer srv.Close()
	proxy, proxyURL := newTestProxy(t, nil)
	proxy.configure(false, true)

	client := newClient()
	client.Proxy = http.ProxyURL(proxyURL)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := client.CACerts(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error = %v, want the context deadline", err)
	}
	if elapsed := time.Since(start); elapsed > testTimeout/2 {
		t.Errorf("CACerts took %s, want a prompt return", elapsed)
	}
}
