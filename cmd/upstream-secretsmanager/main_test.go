package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestVersionFlag(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := run([]string{"--version"}, &out, &errOut); err != nil {
		t.Fatalf("run(--version) = %v", err)
	}
	if got := out.String(); !strings.HasPrefix(got, name+" ") {
		t.Fatalf("version output %q does not start with %q", got, name+" ")
	}
}

func TestNoFlagsIsNotImplemented(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := run(nil, &out, &errOut); !errors.Is(err, errNotImplemented) {
		t.Fatalf("run() = %v, want errNotImplemented", err)
	}
}
