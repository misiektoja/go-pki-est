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
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	srptls "github.com/misiektoja/go-tls-srp"

	est "github.com/misiektoja/go-pki-est"
)

// encodeSRPBase64 encodes b as OpenSSL's t_tob64 does. It pads b on the left
// to a multiple of three bytes and removes one leading digit per padding byte.
func encodeSRPBase64(b []byte) string {
	lead := (3 - len(b)%3) % 3
	padded := append(make([]byte, lead), b...)
	return base64.NewEncoding(opensslSRPBase64).WithPadding(base64.NoPadding).EncodeToString(padded)[lead:]
}

// TestReadSRPVerifiersOpenSSL checks that verifiers written by OpenSSL match
// verifiers computed from the same password and salt.
func TestReadSRPVerifiersOpenSSL(t *testing.T) {
	f, err := os.Open(filepath.Join("testdata", "srpvfile"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	verifiers, err := readSRPVerifiers(f)
	if err != nil {
		t.Fatalf("failed to read verifiers: %v", err)
	}

	want := map[string]int{"alice": 1536, "bob": 2048, "dave": 1536}
	if len(verifiers.users) != len(want) {
		t.Fatalf("got %d users, want %d", len(verifiers.users), len(want))
	}
	for user, bits := range want {
		v, ok := verifiers.users[user]
		if !ok {
			t.Fatalf("user %s is missing", user)
		}
		if v.Group.Bits() != bits {
			t.Errorf("%s: got group %d, want %d", user, v.Group.Bits(), bits)
		}
		computed, err := srptls.NewVerifier(v.Group, []byte(user), []byte(user+"-password"), v.Salt)
		if err != nil {
			t.Fatalf("%s: %v", user, err)
		}
		if !bytes.Equal(computed.Value, v.Value) {
			t.Errorf("%s: verifier from the file does not match the password", user)
		}
	}
	if _, ok := verifiers.users["carol"]; ok {
		t.Errorf("revoked user carol was loaded")
	}
	if verifiers.simulated.Bits() != 1536 {
		t.Errorf("got simulated group %d, want 1536, the group of most users", verifiers.simulated.Bits())
	}
}

// TestReadSRPVerifiers checks group entries and the refusal of malformed files.
func TestReadSRPVerifiers(t *testing.T) {
	group, err := srptls.GroupByBits(2048)
	if err != nil {
		t.Fatal(err)
	}
	salt := []byte{1, 2, 3, 4}
	v, err := srptls.NewVerifier(group, []byte("erin"), []byte("erin-password"), salt)
	if err != nil {
		t.Fatal(err)
	}
	user := func(gn string) string {
		return strings.Join([]string{"V", encodeSRPBase64(v.Value), encodeSRPBase64(salt), "erin", gn, ""}, "\t")
	}
	index := strings.Join([]string{"I", encodeSRPBase64(group.N()), encodeSRPBase64(group.Generator()), "custom", "", ""}, "\t")

	testcases := []struct {
		name string
		file string
		err  string
	}{
		{name: "GroupEntry", file: index + "\n" + user("custom") + "\n"},
		{name: "CommentsAndCRLF", file: "# users\r\n\r\n" + user("2048") + "\r\n"},
		{name: "Empty", file: ""},
		{name: "UnknownGroup", file: user("2047"), err: "line 1: "},
		{name: "UndefinedGroupName", file: user("custom"), err: "unknown group"},
		{name: "Duplicate", file: user("2048") + "\n" + user("2048"), err: "listed twice"},
		{name: "FieldCount", file: "V\tabc", err: "got 2 fields"},
		{name: "EntryType", file: strings.Replace(user("2048"), "V", "X", 1), err: "unknown entry type"},
		{name: "BadCharacter", file: strings.Replace(user("2048"), "\t", "\t!", 1), err: "invalid character"},
	}

	for _, tc := range testcases {
		got, err := readSRPVerifiers(strings.NewReader(tc.file))
		if tc.err != "" {
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("%s: got error %v, want one containing %q", tc.name, err, tc.err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if tc.name == "Empty" {
			if len(got.users) != 0 || got.simulated.Bits() != srpDefaultGroupBits {
				t.Errorf("%s: got %d users and simulated group %d", tc.name, len(got.users), got.simulated.Bits())
			}
			continue
		}
		if e, ok := got.users["erin"]; !ok || e.Group != group || !bytes.Equal(e.Value, v.Value) || !bytes.Equal(e.Salt, salt) {
			t.Errorf("%s: user erin was not read correctly", tc.name)
		}
	}
}

// TestDecodeSRPBase64 checks the lengths OpenSSL refuses and the dropping of
// leading zero bytes.
func TestDecodeSRPBase64(t *testing.T) {
	for _, s := range []string{"", "0", "01234"} {
		if _, err := decodeSRPBase64(s); err == nil {
			t.Errorf("%q: got no error", s)
		}
	}
	got, err := decodeSRPBase64("00/")
	if err != nil || !bytes.Equal(got, []byte{63}) {
		t.Errorf("got %x, %v, want 3f", got, err)
	}
}

// TestNewSRPConfigUnknownUser checks how an unknown username is answered with
// and without a seed.
func TestNewSRPConfigUnknownUser(t *testing.T) {
	path := filepath.Join("testdata", "srpvfile")

	refusing, err := newSRPConfig(&tlsSRPConfig{VerifierFile: path})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := refusing.GetVerifier(&srptls.ClientHelloInfo{Username: "nobody"}); !errors.Is(err, srptls.ErrUnknownUsername) {
		t.Errorf("without a seed got %v, want ErrUnknownUsername", err)
	}
	if v, err := refusing.GetVerifier(&srptls.ClientHelloInfo{Username: "alice"}); err != nil || v == nil {
		t.Errorf("alice: got %v, %v", v, err)
	}

	simulating, err := newSRPConfig(&tlsSRPConfig{VerifierFile: path, UnknownUserSeed: "seed"})
	if err != nil {
		t.Fatal(err)
	}
	v, err := simulating.GetVerifier(&srptls.ClientHelloInfo{Username: "nobody"})
	if err != nil || v == nil || v.Group.Bits() != 1536 {
		t.Fatalf("with a seed got %v, %v, want a simulated 1536-bit verifier", v, err)
	}
	again, _ := simulating.GetVerifier(&srptls.ClientHelloInfo{Username: "nobody"})
	if !bytes.Equal(v.Salt, again.Salt) {
		t.Errorf("the simulated salt changed between handshakes")
	}

	if _, err := newSRPConfig(&tlsSRPConfig{VerifierFile: filepath.Join("testdata", "missing")}); err == nil {
		t.Errorf("a missing verifier file gave no error")
	}
}

// TestWithSRPUsername checks that requests without a TLS-SRP connection pass
// through without a username.
func TestWithSRPUsername(t *testing.T) {
	var got string
	h := withSRPUsername(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = est.SRPUsernameFromContext(r.Context())
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(context.Background())
	h.ServeHTTP(httptest.NewRecorder(), req)
	if got != "" {
		t.Errorf("got username %q without a TLS-SRP connection", got)
	}
}

// TestListenSRPConfig checks that the listener needs an address and a verifier file.
func TestListenSRPConfig(t *testing.T) {
	for _, c := range []*tlsSRPConfig{
		{VerifierFile: filepath.Join("testdata", "srpvfile")},
		{ListenAddr: "127.0.0.1:0"},
	} {
		if s, err := listenSRP(c, http.NotFoundHandler(), nil); err == nil {
			s.Close()
			t.Errorf("%+v: got no error", *c)
		}
	}
}
