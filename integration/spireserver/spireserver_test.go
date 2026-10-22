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
	"encoding/json"
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

	now := time.Now()
	p := testpki.New(t, testpki.Options{Now: now, Middle: 1})
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

	conf := filepath.Join(dir, "server.conf")
	if err := os.WriteFile(conf, fmt.Appendf(nil, serverConf,
		freePort(t), socket, filepath.Join(dir, "data"), filepath.Join(dir, "datastore.sqlite3"),
		plugin, sha256File(t, plugin), sm.URL, secretID, cachePath, p.PinHex(),
	), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	s := &spire{t: t, ctx: ctx, bin: server, conf: conf, socket: socket, dir: dir}

	// 1. Start, mint from Secrets Manager.
	s.start()
	bundle := parsePEM(t, s.run("bundle", "show", "-format", "pem"))
	if len(bundle) != 1 || !bundle[0].Equal(p.Root.Cert) {
		t.Fatalf("bundle has %d certificates; want only the upstream root", len(bundle))
	}
	verifyChain(t, s.mintSVID(), p.Root.Cert, p.Intermediate.Cert)
	if reqs := sm.Requests(); len(reqs) == 0 || reqs[0].SecretID != secretID || reqs[0].VersionStage != "AWSCURRENT" {
		t.Fatalf("Secrets Manager requests = %+v", reqs)
	}
	if st, err := os.Stat(cachePath); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("cache: %v, %v", st, err)
	}

	// 2. Rotate the intermediate in Secrets Manager and make SPIRE prepare
	// its next CA: the new intermediate signs it.
	next := testpki.Issue(t, &p.Middle[0], testpki.Template("Test Intermediate CA 2", now.Add(-time.Minute), now.Add(90*24*time.Hour), true))
	f := p.V1Fields(t)
	f["cert"] = testpki.CertPEM(next.Cert)
	f["key"] = testpki.KeyPEM(t, next.Key)
	sm.Set(secretID, testpki.Encode(t, f))
	before := len(sm.Requests())
	var prepared struct {
		PreparedAuthority struct {
			UpstreamAuthoritySubjectKeyID string `json:"upstream_authority_subject_key_id"`
		} `json:"prepared_authority"`
	}
	out := s.run("localauthority", "x509", "prepare", "-output", "json")
	if err := json.Unmarshal(out, &prepared); err != nil {
		t.Fatalf("localauthority x509 prepare: %v\n%s", err, out)
	}
	if got, want := prepared.PreparedAuthority.UpstreamAuthoritySubjectKeyID, hex.EncodeToString(next.Cert.SubjectKeyId); got != want {
		t.Fatalf("prepared CA's upstream authority is %s, want the new intermediate %s\n%s", got, want, out)
	}
	if len(sm.Requests()) <= before {
		t.Fatal("prepare did not read Secrets Manager")
	}

	// 3. Restart with Secrets Manager gone: the server starts, and mints
	// with the cached (new) intermediate.
	s.stop()
	sm.Close()
	s.start()
	verifyChain(t, s.mintSVID(), p.Root.Cert, next.Cert)
	if !strings.Contains(s.logs.String(), "using the cached copy") {
		t.Fatal("the restarted server did not fall back to the cache")
	}
}

// spire runs a SPIRE server and its CLI.
type spire struct {
	t                 *testing.T
	ctx               context.Context
	bin, conf, socket string
	dir               string
	cmd               *exec.Cmd
	logs              bytes.Buffer
	svids             int
}

func (s *spire) start() {
	s.t.Helper()
	s.logs.Reset()
	s.cmd = exec.CommandContext(s.ctx, s.bin, "run", "-config", s.conf)
	s.cmd.Env = awsEnv()
	s.cmd.Stdout = &s.logs
	s.cmd.Stderr = &s.logs
	if err := s.cmd.Start(); err != nil {
		s.t.Fatal(err)
	}
	cmd := s.cmd
	s.t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	s.t.Cleanup(func() {
		if cmd == s.cmd && (s.t.Failed() || testing.Verbose()) {
			s.t.Logf("spire-server output:\n%s", s.logs.String())
		}
	})
	waitHealthy(s.ctx, s.t, s.bin, s.socket)
}

func (s *spire) stop() {
	s.t.Helper()
	if s.t.Failed() || testing.Verbose() {
		s.t.Logf("spire-server output:\n%s", s.logs.String())
	}
	_ = s.cmd.Process.Signal(os.Interrupt)
	_ = s.cmd.Wait()
}

// run runs a spire-server CLI command against the server.
func (s *spire) run(args ...string) []byte {
	s.t.Helper()
	args = append(args, "-socketPath", s.socket)
	out, err := exec.CommandContext(s.ctx, s.bin, args...).CombinedOutput()
	if err != nil {
		s.t.Fatalf("spire-server %v: %v\n%s", args, err, out)
	}
	return out
}

// mintSVID mints an X509-SVID and returns it with its intermediates.
func (s *spire) mintSVID() []*x509.Certificate {
	s.t.Helper()
	s.svids++
	dir := filepath.Join(s.dir, fmt.Sprintf("svid%d", s.svids))
	if err := os.Mkdir(dir, 0o700); err != nil {
		s.t.Fatal(err)
	}
	s.run("x509", "mint", "-spiffeID", "spiffe://example.org/test", "-write", dir)
	b, err := os.ReadFile(filepath.Join(dir, "svid.pem"))
	if err != nil {
		s.t.Fatal(err)
	}
	return parsePEM(s.t, b)
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
// verifies to root and goes through intermediate.
func verifyChain(t *testing.T, chain []*x509.Certificate, root, intermediate *x509.Certificate) {
	t.Helper()
	if len(chain) < 2 {
		t.Fatalf("SVID chain has %d certificates", len(chain))
	}
	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	paths, err := chain[0].Verify(x509.VerifyOptions{Intermediates: intermediates, Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil {
		t.Fatalf("SVID does not verify to the root: %v", err)
	}
	for _, c := range paths[0] {
		if c.Equal(intermediate) {
			return
		}
	}
	t.Fatalf("SVID chain does not go through %q", intermediate.Subject)
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
