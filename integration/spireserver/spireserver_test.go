// Package spireserver_test runs a real SPIRE server (the release pinned in
// MODULE.bazel) with the plugin as its external UpstreamAuthority, reading
// the intermediate CA from an in-process fake Secrets Manager through the
// plugin's `endpoint` setting, and checks that the server's bundle holds the
// root and its X.509 authority chains to it. Nothing leaves the machine.
package spireserver_test

import (
	"context"
	"encoding/hex"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bpalermo/spire-upstream-secretsmanager/internal/fakesm"
	"github.com/bpalermo/spire-upstream-secretsmanager/internal/spiretest"
	"github.com/bpalermo/spire-upstream-secretsmanager/internal/testpki"
)

var (
	spireServer = flag.String("spire_server", "", "runfiles path (rlocationpath) of the spire-server binary")
	pluginBin   = flag.String("plugin", "", "runfiles path (rlocationpath) of the upstream-secretsmanager binary")
)

const secretID = "arn:aws:secretsmanager:us-east-1:111122223333:secret:example"

func TestSPIREServerUsesThePlugin(t *testing.T) {
	server, plugin := spiretest.Rlocation(t, *spireServer), spiretest.Rlocation(t, *pluginBin)

	now := time.Now()
	p := testpki.New(t, testpki.Options{Now: now, Middle: 1})
	sm := fakesm.New(map[string]string{secretID: p.V1(t)})
	defer sm.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cachePath := filepath.Join(t.TempDir(), "cache", "intermediate.json")
	s := spiretest.New(ctx, t, server, plugin, spiretest.PluginData(
		"region", "us-east-1",
		"endpoint", sm.URL,
		"secret_id", secretID,
		"cache_path", cachePath,
		"root_sha256", p.PinHex(),
	))

	// 1. Start, mint from Secrets Manager.
	s.Start()
	bundle := s.Bundle()
	if len(bundle) != 1 || !bundle[0].Equal(p.Root.Cert) {
		t.Fatalf("bundle has %d certificates; want only the upstream root", len(bundle))
	}
	spiretest.VerifyChain(t, s.MintSVID(), p.Root.Cert, p.Intermediate.Cert)
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
	if got, want := s.PrepareX509().UpstreamAuthoritySubjectKeyID, hex.EncodeToString(next.Cert.SubjectKeyId); got != want {
		t.Fatalf("prepared CA's upstream authority is %s, want the new intermediate %s", got, want)
	}
	if len(sm.Requests()) <= before {
		t.Fatal("prepare did not read Secrets Manager")
	}

	// 3. Restart with Secrets Manager gone: the server starts, and mints
	// with the cached (new) intermediate.
	s.Stop()
	sm.Close()
	s.Start()
	spiretest.VerifyChain(t, s.MintSVID(), p.Root.Cert, next.Cert)
	if !strings.Contains(s.Logs(), "using the cached copy") {
		t.Fatal("the restarted server did not fall back to the cache")
	}
}
