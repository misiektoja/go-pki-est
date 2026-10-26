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

package main

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestMaybeRedirectPermissions checks overwrites and Unix file permissions.
func TestMaybeRedirectPermissions(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		old  os.FileMode
		perm os.FileMode
		want os.FileMode
	}{
		{name: "Private", old: 0644, perm: 0600, want: 0600},
		{name: "PrivateGroupReadable", old: 0640, perm: 0600, want: 0600},
		{name: "Public", old: 0644, perm: 0666, want: 0644},
		{name: "KeepRestricted", old: 0600, perm: 0666, want: 0600},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			filename := filepath.Join(t.TempDir(), "out.pem")
			if err := os.WriteFile(filename, []byte("old contents"), 0600); err != nil {
				t.Fatalf("failed to write file: %v", err)
			}
			if err := os.Chmod(filename, tc.old); err != nil {
				t.Fatalf("failed to set file permissions: %v", err)
			}

			out, closeFunc, err := maybeRedirect(nil, filename, tc.perm)
			if err != nil {
				t.Fatalf("failed to open output file: %v", err)
			}
			defer closeFunc()

			fi, err := os.Stat(filename)
			if err != nil {
				t.Fatalf("failed to stat file: %v", err)
			}
			if runtime.GOOS != "windows" && fi.Mode().Perm() != tc.want {
				t.Fatalf("got permissions %v, want %v", fi.Mode().Perm(), tc.want)
			}
			if _, err := io.WriteString(out, "new"); err != nil {
				t.Fatalf("failed to write output: %v", err)
			}
			data, err := os.ReadFile(filename)
			if err != nil {
				t.Fatalf("failed to read output: %v", err)
			}
			if string(data) != "new" {
				t.Fatalf("got output %q, want %q", data, "new")
			}
		})
	}
}

// TestMaybeRedirectRefusesSymlink checks that a symbolic link is not followed, so a link planted
// in a shared directory cannot redirect a private key or certificate to another file.
func TestMaybeRedirectRefusesSymlink(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	target := filepath.Join(dir, "target.pem")
	if err := os.WriteFile(target, []byte("old contents"), 0644); err != nil {
		t.Fatalf("failed to write target: %v", err)
	}
	link := filepath.Join(dir, "link.pem")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create a symbolic link: %v", err)
	}

	_, closeFunc, err := maybeRedirect(nil, link, 0600)
	if err == nil {
		closeFunc()
		t.Fatal("opened the output through a symbolic link")
	}
	if !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("got error %q, want one naming the symbolic link", err)
	}

	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("failed to read target: %v", err)
	}
	if string(data) != "old contents" {
		t.Errorf("target holds %q, want its old contents", data)
	}
	fi, err := os.Stat(target)
	if err != nil {
		t.Fatalf("failed to stat target: %v", err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0644 {
		t.Errorf("target permissions changed to %v", fi.Mode().Perm())
	}
}

// TestMaybeRedirectDevice checks that output can still be redirected to a device.
func TestMaybeRedirectDevice(t *testing.T) {
	t.Parallel()

	out, closeFunc, err := maybeRedirect(nil, os.DevNull, 0600)
	if err != nil {
		t.Fatalf("failed to open null device: %v", err)
	}
	defer closeFunc()
	if _, err := io.WriteString(out, "key"); err != nil {
		t.Fatalf("failed to write to null device: %v", err)
	}
}
