// Package e2e_test runs the three components of this repository together,
// with nothing but fakes for AWS: the rotator's rotation code (package
// rotation, with a KMS key held by internal/kmsfake) rotates an intermediate
// CA into a fake Secrets Manager (internal/fakesm), in the intermediate-ca/v1
// format; then a real SPIRE server (the release pinned in MODULE.bazel), with
// the plugin as its UpstreamAuthority, mints from that secret, and its SVIDs
// chain to the KMS root through the rotated intermediate; then a second
// rotation is picked up by the CA SPIRE prepares next. Both the rotator and
// the plugin talk to the fake through real AWS SDK clients. Nothing leaves
// the machine.
package e2e_test

import (
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"

	"github.com/bpalermo/spire-upstream-secretsmanager/config"
	"github.com/bpalermo/spire-upstream-secretsmanager/intermediateca"
	"github.com/bpalermo/spire-upstream-secretsmanager/internal/fakesm"
	"github.com/bpalermo/spire-upstream-secretsmanager/internal/kmsfake"
	"github.com/bpalermo/spire-upstream-secretsmanager/internal/spiretest"
	"github.com/bpalermo/spire-upstream-secretsmanager/internal/testpki"
	"github.com/bpalermo/spire-upstream-secretsmanager/kmssigner"
	"github.com/bpalermo/spire-upstream-secretsmanager/rotation"
)

var (
	spireServer = flag.String("spire_server", "", "runfiles path (rlocationpath) of the spire-server binary")
	pluginBin   = flag.String("plugin", "", "runfiles path (rlocationpath) of the upstream-secretsmanager binary")
)

const (
	keyID    = "alias/example-root"
	secretID = "arn:aws:secretsmanager:us-east-1:111122223333:secret:example-intermediate-AbCdEf"
)

func TestRotateThenMint(t *testing.T) {
	server, plugin := spiretest.Rlocation(t, *spireServer), spiretest.Rlocation(t, *pluginBin)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// The root: a self-signed certificate of the KMS key, whose private half
	// only the fake KMS holds.
	root := testpki.NewRoot(t, testpki.NewKey(t, elliptic.P384()), 10*365*24*time.Hour)
	kms := kmsfake.New(keyID, root.Key)

	// Secrets Manager, with the secret as an operator creates it before its
	// first rotation: a placeholder AWSCURRENT value.
	sm := fakesm.New(map[string]string{secretID: "{}"})
	defer sm.Close()
	client := secretsmanager.New(secretsmanager.Options{
		Region:       "us-east-1",
		BaseEndpoint: aws.String(sm.URL),
		Credentials:  credentials.NewStaticCredentialsProvider("AKIAEXAMPLE", "example", ""),
	})

	// The rotator, as the Lambda builds it from its configuration.
	doc, err := json.Marshal(map[string]any{
		"kms_key_id":       keyID,
		"root_certificate": root.PEM(),
		"secrets": map[string]any{secretID: map[string]any{
			"subject":  map[string]any{"common_name": "Example Intermediate CA", "organization": []string{"Example"}},
			"validity": "2160h",
			// SPIRE's own CA is a CA below the intermediate.
			"max_path_len": 1,
			"name_constraints": map[string]any{
				"permitted_uri_domains": []string{spiretest.TrustDomain},
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(doc)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := kmssigner.New(ctx, kms, keyID, cfg.SigningAlgorithm, cfg.Root.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	rotator := &rotation.Rotator{
		SecretsManager: client,
		Config:         cfg,
		Signer:         signer,
		Logger:         slog.New(slog.NewJSONHandler(io.Discard, nil)),
	}
	// rotate runs one rotation as Secrets Manager does, and returns the
	// intermediate CA it made AWSCURRENT.
	rotate := func() *intermediateca.Bundle {
		t.Helper()
		token := sm.StartRotation(secretID)
		for _, step := range []string{rotation.StepCreate, rotation.StepSet, rotation.StepTest, rotation.StepFinish} {
			if err := rotator.Handle(ctx, rotation.Event{SecretID: secretID, ClientRequestToken: token, Step: step}); err != nil {
				t.Fatalf("rotation %s: %v", step, err)
			}
		}
		out, err := client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String(secretID)})
		if err != nil {
			t.Fatal(err)
		}
		if got := aws.ToString(out.VersionId); got != token {
			t.Fatalf("AWSCURRENT is version %s, want the rotation's %s", got, token)
		}
		b, err := intermediateca.Decode([]byte(aws.ToString(out.SecretString)))
		if err != nil {
			t.Fatalf("the rotated secret: %v", err)
		}
		if !b.Root.Equal(root.Cert) {
			t.Fatal("the rotated secret's root is not the KMS root")
		}
		return b
	}

	// 1. The first rotation, then SPIRE mints from it.
	first := rotate()
	if kms.Signs() == 0 {
		t.Fatal("the rotation did not sign with KMS")
	}
	s := spiretest.New(ctx, t, server, plugin, spiretest.PluginData(
		"region", "us-east-1",
		"endpoint", sm.URL,
		"secret_id", secretID,
		"cache_path", filepath.Join(t.TempDir(), "intermediate.json"),
		"root_sha256", spiretest.RootSHA256(root.Cert),
	))
	s.Start()
	defer s.Stop()
	if bundle := s.Bundle(); len(bundle) != 1 || !bundle[0].Equal(root.Cert) {
		t.Fatalf("bundle has %d certificates; want only the KMS root", len(bundle))
	}
	spiretest.VerifyChain(t, s.MintSVID(), root.Cert, first.Cert)

	// 2. A second rotation. The CA SPIRE prepares next is signed by the new
	// intermediate, and once active its SVIDs chain through it.
	second := rotate()
	if second.Cert.Equal(first.Cert) || second.Cert.SerialNumber.Cmp(first.Cert.SerialNumber) == 0 {
		t.Fatal("the second rotation issued the same intermediate")
	}
	prepared := s.PrepareX509()
	if got, want := prepared.UpstreamAuthoritySubjectKeyID, hex.EncodeToString(second.Cert.SubjectKeyId); got != want {
		t.Fatalf("the prepared CA's upstream authority is %s, want the second intermediate %s", got, want)
	}
	s.ActivateX509(prepared.AuthorityID)
	svid := s.MintSVID()
	spiretest.VerifyChain(t, svid, root.Cert, second.Cert)
	if !isSignedBy(svid, second.Cert) {
		t.Fatal("the SVID's CA is not signed by the second intermediate")
	}
}

// isSignedBy reports whether one of chain's intermediates is signed by ca.
func isSignedBy(chain []*x509.Certificate, ca *x509.Certificate) bool {
	for _, c := range chain[1:] {
		if c.CheckSignatureFrom(ca) == nil {
			return true
		}
	}
	return false
}
