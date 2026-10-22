package secret_test

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/bpalermo/spire-upstream-secretsmanager/internal/testpki"
	"github.com/bpalermo/spire-upstream-secretsmanager/pkg/secret"
)

func validate(a *secret.Authority) error {
	return a.Validate(secret.ValidateOptions{Now: time.Now(), MinRemaining: time.Hour})
}

func TestParseV1(t *testing.T) {
	for _, middle := range []int{0, 2} {
		p := testpki.New(t, testpki.Options{Middle: middle})
		a, err := secret.ParseV1([]byte(p.V1(t)))
		if err != nil {
			t.Fatalf("middle=%d: ParseV1: %v", middle, err)
		}
		if err := validate(a); err != nil {
			t.Fatalf("middle=%d: Validate: %v", middle, err)
		}
		if !a.Cert.Equal(p.Intermediate.Cert) || !a.Root.Equal(p.Root.Cert) || len(a.Chain) != middle {
			t.Fatalf("middle=%d: parsed the wrong certificates", middle)
		}
		up := a.UpstreamChain()
		if len(up) != middle+1 || !up[0].Equal(p.Intermediate.Cert) {
			t.Fatalf("middle=%d: UpstreamChain has %d certificates", middle, len(up))
		}
	}
}

func TestParseV1IgnoresUnknownFields(t *testing.T) {
	p := testpki.New(t, testpki.Options{})
	f := p.V1Fields(t)
	f["comment"] = "extra"
	if _, err := secret.ParseV1([]byte(testpki.Encode(t, f))); err != nil {
		t.Fatalf("ParseV1: %v", err)
	}
}

func TestParseV1Rejects(t *testing.T) {
	p := testpki.New(t, testpki.Options{})
	other := testpki.New(t, testpki.Options{})
	for name, edit := range map[string]func(map[string]string){
		"unknown format": func(f map[string]string) { f["format"] = "intermediate-ca/v2" },
		"no format":      func(f map[string]string) { delete(f, "format") },
		"two certs":      func(f map[string]string) { f["cert"] += testpki.CertPEM(p.Root.Cert) },
		"no root":        func(f map[string]string) { f["root"] = "" },
		"bad chain":      func(f map[string]string) { f["chain"] = "garbage" },
		"key not PKCS#8": func(f map[string]string) { f["key"] = strings.ReplaceAll(f["key"], "PRIVATE KEY", "EC PRIVATE KEY") },
		"key is a cert":  func(f map[string]string) { f["key"] = testpki.CertPEM(p.Root.Cert) },
		"other root key": func(f map[string]string) { f["key"] = testpki.KeyPEM(t, other.Intermediate.Key) },
	} {
		t.Run(name, func(t *testing.T) {
			f := p.V1Fields(t)
			edit(f)
			a, err := secret.ParseV1([]byte(testpki.Encode(t, f)))
			if err == nil {
				err = validate(a)
			}
			if err == nil {
				t.Fatal("accepted")
			}
		})
	}
	if _, err := secret.ParseV1([]byte("not json")); err == nil {
		t.Fatal("accepted a non-JSON secret")
	}
}

func TestValidateKeyMismatch(t *testing.T) {
	p := testpki.New(t, testpki.Options{})
	f := p.V1Fields(t)
	f["key"] = testpki.KeyPEM(t, p.Root.Key)
	a, err := secret.ParseV1([]byte(testpki.Encode(t, f)))
	if err != nil {
		t.Fatal(err)
	}
	if err := validate(a); err == nil || !strings.Contains(err.Error(), "do not match") {
		t.Fatalf("Validate = %v, want a key mismatch", err)
	}
}

func TestValidateNotVerifyingToRoot(t *testing.T) {
	p := testpki.New(t, testpki.Options{Middle: 1})
	other := testpki.New(t, testpki.Options{})
	for name, edit := range map[string]func(map[string]string){
		"other root":    func(f map[string]string) { f["root"] = testpki.CertPEM(other.Root.Cert) },
		"chain missing": func(f map[string]string) { f["chain"] = "" },
		"wrong chain":   func(f map[string]string) { f["chain"] = testpki.CertPEM(other.Intermediate.Cert) },
	} {
		t.Run(name, func(t *testing.T) {
			f := p.V1Fields(t)
			edit(f)
			a, err := secret.ParseV1([]byte(testpki.Encode(t, f)))
			if err != nil {
				t.Fatal(err)
			}
			if err := validate(a); err == nil || !strings.Contains(err.Error(), "does not verify") {
				t.Fatalf("Validate = %v, want a verification failure", err)
			}
		})
	}
}

func TestValidateNotCA(t *testing.T) {
	p := testpki.New(t, testpki.Options{IntermediateNotCA: true})
	a, err := secret.ParseV1([]byte(p.V1(t)))
	if err != nil {
		t.Fatal(err)
	}
	if err := validate(a); err == nil || !strings.Contains(err.Error(), "not a CA") {
		t.Fatalf("Validate = %v, want not a CA", err)
	}
}

func TestValidateRootPin(t *testing.T) {
	p := testpki.New(t, testpki.Options{})
	a, err := secret.ParseV1([]byte(p.V1(t)))
	if err != nil {
		t.Fatal(err)
	}
	good := sha256.Sum256(p.Root.Cert.Raw)
	if err := a.Validate(secret.ValidateOptions{Now: time.Now(), RootSHA256: good[:]}); err != nil {
		t.Fatalf("Validate with the right pin: %v", err)
	}
	other := testpki.New(t, testpki.Options{})
	bad := sha256.Sum256(other.Root.Cert.Raw)
	if err := a.Validate(secret.ValidateOptions{Now: time.Now(), RootSHA256: bad[:]}); err == nil || !strings.Contains(err.Error(), "root_sha256") {
		t.Fatalf("Validate with another root's pin = %v, want a pin mismatch", err)
	}
}

func TestValidateMinRemaining(t *testing.T) {
	now := time.Now()
	p := testpki.New(t, testpki.Options{Now: now, IntermediateTTL: 2 * time.Hour})
	a, err := secret.ParseV1([]byte(p.V1(t)))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Validate(secret.ValidateOptions{Now: now, MinRemaining: time.Hour}); err != nil {
		t.Fatalf("1h59m left, min 1h: %v", err)
	}
	if err := a.Validate(secret.ValidateOptions{Now: now, MinRemaining: 3 * time.Hour}); err == nil || !strings.Contains(err.Error(), "min_remaining") {
		t.Fatalf("1h59m left, min 3h = %v, want rejected", err)
	}
	if err := a.Validate(secret.ValidateOptions{Now: now.Add(3 * time.Hour)}); err == nil {
		t.Fatal("expired certificate accepted")
	}
}

func TestMarshalV1RoundTrip(t *testing.T) {
	p := testpki.New(t, testpki.Options{Middle: 1})
	a, err := secret.ParseV1([]byte(p.V1(t)))
	if err != nil {
		t.Fatal(err)
	}
	b, err := a.MarshalV1()
	if err != nil {
		t.Fatal(err)
	}
	again, err := secret.ParseV1(b)
	if err != nil {
		t.Fatalf("ParseV1(MarshalV1()): %v", err)
	}
	if err := validate(again); err != nil {
		t.Fatal(err)
	}
	if !again.Cert.Equal(a.Cert) || !again.Root.Equal(a.Root) || len(again.Chain) != 1 || !again.Chain[0].Equal(a.Chain[0]) {
		t.Fatal("round trip changed the certificates")
	}
}

func TestAWSSecretLayout(t *testing.T) {
	now := time.Now()
	p := testpki.New(t, testpki.Options{Middle: 1})
	other := testpki.New(t, testpki.Options{})
	key := testpki.KeyPEM(t, p.Intermediate.Key)

	t.Run("cert, chain and bundle", func(t *testing.T) {
		// The bundle holds an unrelated root as well; the right one is picked.
		a, err := secret.ParseAWSSecretLayout(
			testpki.CertPEM(p.Intermediate.Cert, p.Middle[0].Cert), key,
			testpki.CertPEM(other.Root.Cert, p.Root.Cert), now)
		if err != nil {
			t.Fatal(err)
		}
		if err := validate(a); err != nil {
			t.Fatal(err)
		}
		if !a.Root.Equal(p.Root.Cert) || len(a.Chain) != 1 {
			t.Fatal("wrong root or chain")
		}
	})

	t.Run("bundle that is not the root", func(t *testing.T) {
		_, err := secret.ParseAWSSecretLayout(testpki.CertPEM(p.Intermediate.Cert, p.Middle[0].Cert), key, testpki.CertPEM(other.Root.Cert), now)
		if err == nil {
			t.Fatal("accepted")
		}
	})

	t.Run("no bundle and self-signed", func(t *testing.T) {
		a, err := secret.ParseAWSSecretLayout(testpki.CertPEM(p.Root.Cert), testpki.KeyPEM(t, p.Root.Key), "", now)
		if err != nil {
			t.Fatal(err)
		}
		if err := validate(a); err != nil {
			t.Fatal(err)
		}
		if !a.SelfSigned() || a.UpstreamChain() != nil {
			t.Fatal("a self-signed CA must be its own root and add nothing to the chain")
		}
	})

	t.Run("no bundle and a chain", func(t *testing.T) {
		_, err := secret.ParseAWSSecretLayout(testpki.CertPEM(p.Intermediate.Cert, p.Middle[0].Cert), key, "", now)
		if err == nil || !strings.Contains(err.Error(), "only self-signed") {
			t.Fatalf("err = %v, want the self-signed rule", err)
		}
	})

	t.Run("no bundle and one cert that is not self-signed", func(t *testing.T) {
		_, err := secret.ParseAWSSecretLayout(testpki.CertPEM(p.Intermediate.Cert), key, "", now)
		if err == nil || !strings.Contains(err.Error(), "only self-signed") {
			t.Fatalf("err = %v, want the self-signed rule", err)
		}
	})

	t.Run("SEC 1 key", func(t *testing.T) {
		der, err := x509.MarshalECPrivateKey(p.Root.Key.(*ecdsa.PrivateKey))
		if err != nil {
			t.Fatal(err)
		}
		sec1 := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
		a, err := secret.ParseAWSSecretLayout(testpki.CertPEM(p.Root.Cert), sec1, "", now)
		if err != nil {
			t.Fatal(err)
		}
		if err := validate(a); err != nil {
			t.Fatal(err)
		}
	})
}
