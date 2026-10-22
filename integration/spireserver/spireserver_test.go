// Package spireserver_test runs a real SPIRE server (the release pinned in
// MODULE.bazel) with the plugin as its external UpstreamAuthority, reading
// the intermediate CA from an in-process fake Secrets Manager through the
// plugin's `endpoint` setting, and checks that the server's bundle holds the
// root and its X.509 authority chains to it. Nothing leaves the machine.
package spireserver_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bazelbuild/rules_go/go/runfiles"

	"github.com/bpalermo/spire-upstream-secretsmanager/internal/fakesm"
	"github.com/bpalermo/spire-upstream-secretsmanager/internal/testpki"
)

var (
	spireServer = flag.String("spire_server", "", "runfiles path (rlocationpath) of the spire-server binary")
	pluginBin   = flag.String("plugin", "", "runfiles path (rlocationpath) of the upstream-secretsmanager binary")
)

const secretID = "arn:aws:secretsmanager:us-east-1:111122223333:secret:example"

const serverConf = `
server {
  bind_address = "127.0.0.1"
  bind_port    = "%d"
  socket_path  = "%s"
  trust_domain = "example.org"
  data_dir     = "%s"
  log_level    = "DEBUG"
  ca_ttl       = "2h"
}

plugins {
  DataStore "sql" {
    plugin_data {
      database_type     = "sqlite3"
      connection_string = "%s"
    }
  }

  KeyManager "memory" {
    plugin_data {}
  }

  NodeAttestor "join_token" {
    plugin_data {}
  }

  UpstreamAuthority "secretsmanager" {
    plugin_cmd      = "%s"
    plugin_checksum = "%s"
    plugin_data {
      region      = "us-east-1"
      endpoint    = "%s"
      secret_id   = "%s"
      cache_path  = "%s"
      root_sha256 = "%s"
    }
  }
}
`

func rlocation(t *testing.T, p string) string {
	t.Helper()
	if p == "" {
		t.Fatal("--spire_server and --plugin are required")
	}
	a, err := runfiles.Rlocation(p)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func sha256File(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func TestSPIREServerUsesThePlugin(t *testing.T) {
	server, plugin := rlocation(t, *spireServer), rlocation(t, *pluginBin)

	p := testpki.New(t, testpki.Options{Middle: 1})
	sm := fakesm.New(map[string]string{secretID: p.V1(t)})
	defer sm.Close()

	dir := t.TempDir()
	// A Unix socket path must be short; the test's own directory may not be.
	sockDir, err := os.MkdirTemp("/tmp", "spire")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	socket := filepath.Join(sockDir, "api.sock")
	cachePath := filepath.Join(dir, "cache", "intermediate.json")
	rootSum := sha256.Sum256(p.Root.Cert.Raw)

	conf := filepath.Join(dir, "server.conf")
	if err := os.WriteFile(conf, fmt.Appendf(nil, serverConf,
		freePort(t), socket, filepath.Join(dir, "data"), filepath.Join(dir, "datastore.sqlite3"),
		plugin, sha256File(t, plugin), sm.URL, secretID, cachePath, hex.EncodeToString(rootSum[:]),
	), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	var logs bytes.Buffer
	cmd := exec.CommandContext(ctx, server, "run", "-config", conf)
	cmd.Env = awsEnv()
	cmd.Stdout = &logs
	cmd.Stderr = &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if t.Failed() || testing.Verbose() {
			t.Logf("spire-server output:\n%s", logs.String())
		}
	})

	waitHealthy(ctx, t, server, socket)

	out, err := exec.CommandContext(ctx, server, "bundle", "show", "-socketPath", socket, "-format", "pem").CombinedOutput()
	if err != nil {
		t.Fatalf("bundle show: %v\n%s", err, out)
	}
	bundle := parsePEM(t, out)
	if len(bundle) != 1 || !bundle[0].Equal(p.Root.Cert) {
		t.Fatalf("bundle has %d certificates; want only the upstream root\n%s", len(bundle), out)
	}

	// An X509-SVID the server mints chains to the root through its CA and
	// the intermediate from Secrets Manager.
	svidDir := filepath.Join(dir, "svid")
	if err := os.Mkdir(svidDir, 0o700); err != nil {
		t.Fatal(err)
	}
	out, err = exec.CommandContext(ctx, server, "x509", "mint", "-socketPath", socket,
		"-spiffeID", "spiffe://example.org/test", "-write", svidDir).CombinedOutput()
	if err != nil {
		t.Fatalf("x509 mint: %v\n%s", err, out)
	}
	svid, err := os.ReadFile(filepath.Join(svidDir, "svid.pem"))
	if err != nil {
		t.Fatal(err)
	}
	verifyChain(t, parsePEM(t, svid), p)

	if reqs := sm.Requests(); len(reqs) == 0 || reqs[0].SecretID != secretID || reqs[0].VersionStage != "AWSCURRENT" {
		t.Fatalf("Secrets Manager requests = %+v", reqs)
	}
	if st, err := os.Stat(cachePath); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("cache: %v, %v", st, err)
	}
}

// awsEnv is the environment of the SPIRE server, and so of the plugin: static
// placeholder credentials, and nothing of the machine's AWS configuration.
func awsEnv() []string {
	env := []string{
		"AWS_ACCESS_KEY_ID=AKIAEXAMPLE",
		"AWS_SECRET_ACCESS_KEY=example",
		"AWS_CONFIG_FILE=/dev/null",
		"AWS_SHARED_CREDENTIALS_FILE=/dev/null",
		"AWS_EC2_METADATA_DISABLED=true",
	}
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "AWS_") {
			env = append(env, kv)
		}
	}
	return env
}

// waitHealthy waits until the server answers healthcheck, which it does once
// its CA is prepared, so after the first mint.
func waitHealthy(ctx context.Context, t *testing.T, server, socket string) {
	t.Helper()
	var out []byte
	for ctx.Err() == nil {
		var err error
		out, err = exec.CommandContext(ctx, server, "healthcheck", "-socketPath", socket).CombinedOutput()
		if err == nil {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("spire-server never became healthy: %s", out)
}

// verifyChain checks that chain (an SVID followed by its intermediates)
// verifies to the PKI's root and goes through its intermediate.
func verifyChain(t *testing.T, chain []*x509.Certificate, p *testpki.PKI) {
	t.Helper()
	if len(chain) < 2 {
		t.Fatalf("SVID chain has %d certificates", len(chain))
	}
	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}
	roots := x509.NewCertPool()
	roots.AddCert(p.Root.Cert)
	paths, err := chain[0].Verify(x509.VerifyOptions{Intermediates: intermediates, Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil {
		t.Fatalf("SVID does not verify to the root: %v", err)
	}
	for _, c := range paths[0] {
		if c.Equal(p.Intermediate.Cert) {
			return
		}
	}
	t.Fatal("SVID chain does not go through the intermediate from Secrets Manager")
}

func parsePEM(t *testing.T, b []byte) []*x509.Certificate {
	t.Helper()
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, b = pem.Decode(b)
		if block == nil {
			return certs
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		certs = append(certs, c)
	}
}
