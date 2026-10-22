// Package spiretest runs a real SPIRE server (the release pinned in
// MODULE.bazel) with the plugin as its external UpstreamAuthority, and its
// CLI, for the tests under //integration. Nothing leaves the machine: the
// server binds to loopback, and the plugin reads an in-process fake Secrets
// Manager through its `endpoint` setting.
package spiretest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bazelbuild/rules_go/go/runfiles"
)

// TrustDomain is the server's trust domain.
const TrustDomain = "example.org"

const serverConf = `
server {
  bind_address = "127.0.0.1"
  bind_port    = "%d"
  socket_path  = "%s"
  trust_domain = "` + TrustDomain + `"
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
%s
    }
  }
}
`

// Rlocation resolves a runfiles path (an rlocationpath from the BUILD file).
func Rlocation(t testing.TB, p string) string {
	t.Helper()
	if p == "" {
		t.Fatal("a runfiles path flag is missing (see the test's BUILD file)")
	}
	a, err := runfiles.Rlocation(p)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// PluginData is the plugin_data block of the plugin: each key = "value", in
// the order given.
func PluginData(kv ...string) string {
	if len(kv)%2 != 0 {
		panic("spiretest.PluginData: odd number of arguments")
	}
	var b strings.Builder
	for i := 0; i < len(kv); i += 2 {
		fmt.Fprintf(&b, "      %s = %q\n", kv[i], kv[i+1])
	}
	return b.String()
}

// Server is a SPIRE server and its CLI.
type Server struct {
	t                 testing.TB
	ctx               context.Context
	bin, conf, socket string
	dir               string
	cmd               *exec.Cmd
	logs              bytes.Buffer
	svids             int
}

// New writes the configuration of a server that runs plugin with
// pluginData (see [PluginData]) under a new temporary directory. Start it
// with [Server.Start].
func New(ctx context.Context, t testing.TB, server, plugin, pluginData string) *Server {
	t.Helper()
	dir := t.TempDir()
	// A Unix socket path must be short; the test's own directory may not be.
	sockDir, err := os.MkdirTemp("/tmp", "spire")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	socket := filepath.Join(sockDir, "api.sock")
	conf := filepath.Join(dir, "server.conf")
	if err := os.WriteFile(conf, fmt.Appendf(nil, serverConf,
		freePort(t), socket, filepath.Join(dir, "data"), filepath.Join(dir, "datastore.sqlite3"),
		plugin, sha256File(t, plugin), pluginData,
	), 0o600); err != nil {
		t.Fatal(err)
	}
	return &Server{t: t, ctx: ctx, bin: server, conf: conf, socket: socket, dir: dir}
}

// Dir is the server's temporary directory, for the files a test gives the
// plugin (its cache).
func (s *Server) Dir() string { return s.dir }

// Logs is what the server, and the plugin through it, logged since the last
// start.
func (s *Server) Logs() string { return s.logs.String() }

// Start starts the server and waits until it is healthy, which it is once
// its first CA is minted by the plugin.
func (s *Server) Start() {
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
	s.waitHealthy()
}

// Stop stops the server.
func (s *Server) Stop() {
	s.t.Helper()
	if s.t.Failed() || testing.Verbose() {
		s.t.Logf("spire-server output:\n%s", s.logs.String())
	}
	_ = s.cmd.Process.Signal(os.Interrupt)
	_ = s.cmd.Wait()
}

// Run runs a spire-server CLI command against the server.
func (s *Server) Run(args ...string) []byte {
	s.t.Helper()
	args = append(args, "-socketPath", s.socket)
	out, err := exec.CommandContext(s.ctx, s.bin, args...).CombinedOutput()
	if err != nil {
		s.t.Fatalf("spire-server %v: %v\n%s", args, err, out)
	}
	return out
}

// Bundle is the server's X.509 trust bundle.
func (s *Server) Bundle() []*x509.Certificate {
	s.t.Helper()
	return ParsePEM(s.t, s.Run("bundle", "show", "-format", "pem"))
}

// MintSVID mints an X509-SVID and returns it followed by its intermediates.
func (s *Server) MintSVID() []*x509.Certificate {
	s.t.Helper()
	s.svids++
	dir := filepath.Join(s.dir, fmt.Sprintf("svid%d", s.svids))
	if err := os.Mkdir(dir, 0o700); err != nil {
		s.t.Fatal(err)
	}
	s.Run("x509", "mint", "-spiffeID", "spiffe://"+TrustDomain+"/test", "-write", dir)
	b, err := os.ReadFile(filepath.Join(dir, "svid.pem"))
	if err != nil {
		s.t.Fatal(err)
	}
	return ParsePEM(s.t, b)
}

// Prepared is what `localauthority x509 prepare` reports of the CA it
// prepared.
type Prepared struct {
	// AuthorityID identifies the prepared CA, for `localauthority x509
	// activate`.
	AuthorityID string `json:"authority_id"`
	// UpstreamAuthoritySubjectKeyID is the hex SubjectKeyId of the
	// certificate that signed it: the plugin's intermediate CA.
	UpstreamAuthoritySubjectKeyID string `json:"upstream_authority_subject_key_id"`
}

// PrepareX509 makes the server prepare its next X.509 CA, which asks the
// plugin to sign it.
func (s *Server) PrepareX509() Prepared {
	s.t.Helper()
	var out struct {
		PreparedAuthority Prepared `json:"prepared_authority"`
	}
	b := s.Run("localauthority", "x509", "prepare", "-output", "json")
	if err := json.Unmarshal(b, &out); err != nil {
		s.t.Fatalf("localauthority x509 prepare: %v\n%s", err, b)
	}
	return out.PreparedAuthority
}

// ActivateX509 makes the prepared X.509 CA authorityID the one that signs.
func (s *Server) ActivateX509(authorityID string) {
	s.t.Helper()
	s.Run("localauthority", "x509", "activate", "-authorityID", authorityID)
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

// waitHealthy waits until the server answers healthcheck.
func (s *Server) waitHealthy() {
	s.t.Helper()
	var out []byte
	for s.ctx.Err() == nil {
		var err error
		out, err = exec.CommandContext(s.ctx, s.bin, "healthcheck", "-socketPath", s.socket).CombinedOutput()
		if err == nil {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	s.t.Fatalf("spire-server never became healthy: %s", out)
}

// VerifyChain checks that chain (an SVID followed by its intermediates)
// verifies to root and goes through intermediate.
func VerifyChain(t testing.TB, chain []*x509.Certificate, root, intermediate *x509.Certificate) {
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

// ParsePEM parses every CERTIFICATE block of b.
func ParsePEM(t testing.TB, b []byte) []*x509.Certificate {
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

// RootSHA256 is the SHA-256 of a root's DER, as root_sha256 takes it.
func RootSHA256(root *x509.Certificate) string {
	sum := sha256.Sum256(root.Raw)
	return hex.EncodeToString(sum[:])
}

func sha256File(t testing.TB, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func freePort(t testing.TB) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}
