package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func noServe(t *testing.T) func() {
	return func() { t.Fatal("serve called") }
}

func TestVersionFlag(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := run([]string{"--version"}, &out, &errOut, noServe(t)); err != nil {
		t.Fatalf("run(--version) = %v", err)
	}
	if got := out.String(); !strings.HasPrefix(got, name+" ") {
		t.Fatalf("version output %q does not start with %q", got, name+" ")
	}
}

func TestNoArgumentsServes(t *testing.T) {
	var out, errOut bytes.Buffer
	served := false
	if err := run(nil, &out, &errOut, func() { served = true }); err != nil {
		t.Fatalf("run() = %v", err)
	}
	if !served {
		t.Fatal("run() did not serve the plugin")
	}
}

func TestUnexpectedArguments(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := run([]string{"serve"}, &out, &errOut, noServe(t)); err == nil {
		t.Fatal("run(serve) succeeded")
	}
	if err := run([]string{"install"}, &out, &errOut, noServe(t)); err == nil {
		t.Fatal("run(install) without a directory succeeded")
	}
}

func TestInstall(t *testing.T) {
	dir := t.TempDir()
	// An older copy is replaced.
	if err := os.WriteFile(filepath.Join(dir, name), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if err := run([]string{"install", dir}, &out, &errOut, noServe(t)); err != nil {
		t.Fatalf("run(install) = %v", err)
	}
	dst := filepath.Join(dir, name)
	st, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if mode := st.Mode().Perm(); mode != 0o755 {
		t.Fatalf("mode = %o, want 755", mode)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("the installed file is not a copy of the executable")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("%d entries in the directory, want 1", len(entries))
	}
	if !strings.Contains(out.String(), dst) {
		t.Fatalf("output %q does not name %s", out.String(), dst)
	}
}

func TestInstallMissingDirectory(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := run([]string{"install", filepath.Join(t.TempDir(), "none")}, &out, &errOut, noServe(t)); err == nil {
		t.Fatal("install into a missing directory succeeded")
	}
}
