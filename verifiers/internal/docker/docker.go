// Package docker drives the local Docker daemon through the docker CLI for
// the verifier tests: throwaway networks and containers, removed when the test
// ends. Nothing here talks to anything but the local daemon.
package docker

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Prefix starts the name of every network, container and cluster the tests
// create, so a leftover is easy to find and remove (`docker ps -a | grep susm-`).
const Prefix = "susm-"

// Run runs `docker args...` and returns its combined output.
func Run(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return strings.TrimSpace(out.String()), err
}

// RunStdin runs `docker args...` with the file at path as its standard input.
func RunStdin(ctx context.Context, path string, args ...string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	cmd := exec.CommandContext(ctx, "docker", args...)
	var out bytes.Buffer
	cmd.Stdin, cmd.Stdout, cmd.Stderr = f, &out, &out
	err = cmd.Run()
	return strings.TrimSpace(out.String()), err
}

// Must runs docker and fails the test on an error.
func Must(t testing.TB, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	out, err := Run(ctx, args...)
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

// Require fails the test when there is no Docker daemon to talk to.
func Require(t testing.TB) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if out, err := Run(ctx, "version", "--format", "{{.Server.Version}}"); err != nil {
		t.Fatalf("these tests need a local Docker daemon: %v %s", err, out)
	}
	// The docker CLI wants a writable config directory.
	if os.Getenv("DOCKER_CONFIG") == "" {
		t.Setenv("DOCKER_CONFIG", t.TempDir())
	}
}

// Name is a unique name with the test prefix.
func Name(kind string) string {
	return fmt.Sprintf("%s%s-%d", Prefix, kind, time.Now().UnixNano()%1_000_000_000)
}

// Network creates a network removed at the end of the test.
func Network(t testing.TB) string {
	t.Helper()
	name := Name("net")
	Must(t, "network", "create", name)
	t.Cleanup(func() { _, _ = Run(context.Background(), "network", "rm", name) })
	return name
}

// Start runs a detached container (`docker run -d --name <name> args...`)
// that is removed at the end of the test, its logs printed first when the
// test failed.
func Start(t testing.TB, name string, args ...string) {
	t.Helper()
	Must(t, append([]string{"run", "-d", "--name", name}, args...)...)
	t.Cleanup(func() {
		if t.Failed() {
			logs, _ := Run(context.Background(), "logs", "--tail", "60", name)
			t.Logf("logs of %s:\n%s", name, logs)
		}
		_, _ = Run(context.Background(), "rm", "-f", "-v", name)
	})
}

// Once runs a container to completion (`docker run --rm args...`) and
// returns its output and error.
func Once(ctx context.Context, args ...string) (string, error) {
	return Run(ctx, append([]string{"run", "--rm"}, args...)...)
}

// WaitFor polls fn every second until it returns nil or the timeout passes.
func WaitFor(t testing.TB, what string, timeout time.Duration, fn func() error) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		err := fn()
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("waiting for %s: %v", what, err)
		}
		time.Sleep(time.Second)
	}
}

// LastLine is the last non-empty line of s that contains any of the keys,
// or the last non-empty line when none does: the error line of a client's
// output.
func LastLine(s string, keys ...string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		for _, k := range keys {
			if strings.Contains(lines[i], k) {
				return strings.TrimSpace(lines[i])
			}
		}
	}
	if len(lines) == 0 {
		return ""
	}
	return strings.TrimSpace(lines[len(lines)-1])
}
