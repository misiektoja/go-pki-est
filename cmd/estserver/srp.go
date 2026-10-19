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
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	srptls "github.com/misiektoja/go-tls-srp"

	est "github.com/misiektoja/go-pki-est"
)

// srpHandshakeTimeout limits how long a client may take to send its request
// headers. The TLS-SRP handshake runs in the first read, so it is included.
const srpHandshakeTimeout = 30 * time.Second

// srpDefaultGroupBits is the group of simulated users when the verifier file
// has no users.
const srpDefaultGroupBits = 3072

// opensslSRPBase64 is the digit alphabet of the base64 encoding OpenSSL uses
// for SRP verifiers, salts and group parameters.
const opensslSRPBase64 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./"

// srpConnKey is the request context key of the TLS-SRP connection.
type srpConnKey struct{}

// srpVerifiers holds the users of a verifier file and the group used to
// simulate unknown users.
type srpVerifiers struct {
	users     map[string]*srptls.Verifier
	simulated *srptls.Group
}

// decodeSRPBase64 decodes a value in OpenSSL's SRP base64 encoding. OpenSSL
// reads the value as a big-endian number, so leading zero bytes are dropped.
func decodeSRPBase64(s string) ([]byte, error) {
	// OpenSSL pads the text on the left to a multiple of four characters and
	// refuses one that needs three padding characters.
	if s == "" || len(s)%4 == 1 {
		return nil, errors.New("invalid length")
	}
	n := new(big.Int)
	for _, ch := range s {
		i := strings.IndexRune(opensslSRPBase64, ch)
		if i < 0 {
			return nil, fmt.Errorf("invalid character %q", ch)
		}
		n.Lsh(n, 6).Or(n, big.NewInt(int64(i)))
	}
	return n.Bytes(), nil
}

// readSRPVerifiers reads an OpenSSL srpvfile, as written by "openssl srp".
// Each line has six tab-separated fields: type, verifier, salt, username,
// group and info. Type V is a user and R a revoked user, which is skipped.
// Type I defines a group whose name V lines can use in place of one of the
// RFC 5054 group sizes. Only the RFC 5054 groups are accepted.
func readSRPVerifiers(r io.Reader) (*srpVerifiers, error) {
	groups := map[string]*srptls.Group{}
	users := map[string]*srptls.Verifier{}
	count := map[*srptls.Group]int{}

	scanner := bufio.NewScanner(r)
	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSuffix(scanner.Text(), "\r")
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		f := strings.Split(text, "\t")
		if len(f) != 6 {
			return nil, fmt.Errorf("line %d: got %d fields, want 6", line, len(f))
		}
		switch f[0] {
		case "R":
			continue

		case "I":
			n, err := decodeSRPBase64(f[1])
			if err != nil {
				return nil, fmt.Errorf("line %d: group prime: %w", line, err)
			}
			g, err := decodeSRPBase64(f[2])
			if err != nil {
				return nil, fmt.Errorf("line %d: group generator: %w", line, err)
			}
			group, err := srptls.GroupByParameters(n, g)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", line, err)
			}
			groups[f[3]] = group

		case "V":
			group, ok := groups[f[4]]
			if !ok {
				bits, err := strconv.Atoi(f[4])
				if err != nil {
					return nil, fmt.Errorf("line %d: unknown group %q", line, f[4])
				}
				if group, err = srptls.GroupByBits(bits); err != nil {
					return nil, fmt.Errorf("line %d: %w", line, err)
				}
			}
			value, err := decodeSRPBase64(f[1])
			if err != nil {
				return nil, fmt.Errorf("line %d: verifier: %w", line, err)
			}
			salt, err := decodeSRPBase64(f[2])
			if err != nil {
				return nil, fmt.Errorf("line %d: salt: %w", line, err)
			}
			v := &srptls.Verifier{Group: group, Salt: salt, Value: value}
			if err := v.Validate(); err != nil {
				return nil, fmt.Errorf("line %d: %w", line, err)
			}
			if _, dup := users[f[3]]; dup {
				return nil, fmt.Errorf("line %d: user %q is listed twice", line, f[3])
			}
			users[f[3]] = v
			count[group]++

		default:
			return nil, fmt.Errorf("line %d: unknown entry type %q", line, f[0])
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Unknown users get the group most users have, so their group does not
	// give them away. A tie goes to the larger group.
	simulated, err := srptls.GroupByBits(srpDefaultGroupBits)
	if err != nil {
		return nil, err
	}
	best := 0
	for group, n := range count {
		if n > best || (n == best && group.Bits() > simulated.Bits()) {
			simulated, best = group, n
		}
	}

	return &srpVerifiers{users: users, simulated: simulated}, nil
}

// newSRPConfig returns the TLS-SRP configuration for c. Without an unknown
// user seed, an unknown username fails the handshake with an
// unknown_psk_identity alert. With a seed, it fails like a wrong password.
func newSRPConfig(c *tlsSRPConfig) (*srptls.Config, error) {
	f, err := os.Open(c.VerifierFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	verifiers, err := readSRPVerifiers(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", c.VerifierFile, err)
	}

	seed := []byte(c.UnknownUserSeed)
	return &srptls.Config{
		GetVerifier: func(info *srptls.ClientHelloInfo) (*srptls.Verifier, error) {
			if v, ok := verifiers.users[info.Username]; ok {
				return v, nil
			}
			if len(seed) == 0 {
				return nil, srptls.ErrUnknownUsername
			}
			return srptls.SimulatedVerifier(seed, verifiers.simulated, []byte(info.Username)), nil
		},
	}, nil
}

// withSRPUsername passes the username of the request's TLS-SRP connection to
// the EST router.
func withSRPUsername(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, ok := r.Context().Value(srpConnKey{}).(*srptls.Conn); ok {
			r = r.WithContext(est.WithSRPUsername(r.Context(), c.ConnectionState().SRPUsername))
		}
		h.ServeHTTP(w, r)
	})
}

// listenSRP starts serving h over TLS-SRP as configured by c. It returns the
// server so the caller can close it.
func listenSRP(c *tlsSRPConfig, h http.Handler, logger est.Logger) (*http.Server, error) {
	if c.ListenAddr == "" || c.VerifierFile == "" {
		return nil, errors.New("tls_srp needs listen_address and verifier_file")
	}
	srpCfg, err := newSRPConfig(c)
	if err != nil {
		return nil, err
	}
	ln, err := srptls.Listen("tcp", c.ListenAddr, srpCfg)
	if err != nil {
		return nil, err
	}

	s := &http.Server{
		Handler:           withSRPUsername(h),
		ReadHeaderTimeout: srpHandshakeTimeout,
		// net/http sets Request.TLS only for crypto/tls connections, so the
		// handler reads the TLS-SRP state from the connection instead.
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			return context.WithValue(ctx, srpConnKey{}, conn)
		},
		// net/http does not report handshake failures of other TLS stacks.
		ConnState: func(conn net.Conn, state http.ConnState) {
			tc, ok := conn.(*srptls.Conn)
			if !ok || state != http.StateClosed || tc.ConnectionState().HandshakeComplete {
				return
			}
			if err := tc.Handshake(); err != nil {
				logger.Infof("TLS-SRP handshake from %s failed: %v", conn.RemoteAddr(), err)
			}
		},
	}

	go func() {
		if err := s.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("failed to serve TLS-SRP: %v", err)
		}
	}()

	return s, nil
}
