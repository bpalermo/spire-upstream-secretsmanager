package secret_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/bpalermo/spire-upstream-secretsmanager/intermediateca"
	"github.com/bpalermo/spire-upstream-secretsmanager/internal/testpki"
	"github.com/bpalermo/spire-upstream-secretsmanager/secret"
)

var td = spiffeid.RequireTrustDomainFromString("example.org")

// opts validates at now for example.org with a's own root pinned.
func opts(a *secret.Authority, now time.Time) secret.ValidateOptions {
	return secret.ValidateOptions{
		Now:          now,
		MinRemaining: time.Hour,
		RootPins:     [][32]byte{intermediateca.RootSHA256(&a.Bundle)},
		TrustDomain:  td,
	}
}

func validate(a *secret.Authority) error {
	return a.Validate(opts(a, time.Now()))
}

func parse(t *testing.T, s string) *secret.Authority {
	t.Helper()
	a, err := secret.ParseV1([]byte(s), time.Now())
	if err != nil {
		t.Fatalf("ParseV1: %v", err)
	}
	return a
}

func TestParseV1(t *testing.T) {
	for _, middle := range []int{0, 2} {
		p := testpki.New(t, testpki.Options{Middle: middle})
		a := parse(t, p.V1(t))
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
		if a.Raw == nil || a.Raw.GetCert() == "" {
			t.Fatalf("middle=%d: no raw secret kept", middle)
		}
	}
}

// The format puts the chain in no order; SPIRE receives it ordered from the
// intermediate's issuer towards the root.
func TestParseV1OrdersTheChain(t *testing.T) {
	p := testpki.New(t, testpki.Options{Middle: 3})
	f := p.V1Fields(t)
	f["chain"] = testpki.CertPEM(p.Middle[1].Cert, p.Middle[0].Cert, p.Middle[2].Cert)
	a := parse(t, testpki.Encode(t, f))
	want := p.ChainCerts()
	got := a.UpstreamChain()[1:]
	if len(got) != len(want) {
		t.Fatalf("chain has %d certificates, want %d", len(got), len(want))
	}
	for i, c := range got {
		if !c.Equal(want[i]) {
			t.Fatalf("chain[%d] is %q, want %q", i, c.Subject, want[i].Subject)
		}
	}
}

func TestParseV1IgnoresUnknownFields(t *testing.T) {
	p := testpki.New(t, testpki.Options{})
	f := p.V1Fields(t)
	f["comment"] = "extra"
	parse(t, testpki.Encode(t, f))
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
			if _, err := secret.ParseV1([]byte(testpki.Encode(t, f)), time.Now()); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	if _, err := secret.ParseV1([]byte("not json"), time.Now()); !errors.Is(err, intermediateca.ErrInvalid) {
		t.Fatalf("a non-JSON secret: %v, want ErrInvalid", err)
	}
}

func TestParseV1KeyMismatch(t *testing.T) {
	p := testpki.New(t, testpki.Options{})
	f := p.V1Fields(t)
	f["key"] = testpki.KeyPEM(t, p.Root.Key)
	if _, err := secret.ParseV1([]byte(testpki.Encode(t, f)), time.Now()); !errors.Is(err, intermediateca.ErrKeyMismatch) {
		t.Fatalf("ParseV1 = %v, want a key mismatch", err)
	}
}

func TestParseV1NotVerifyingToRoot(t *testing.T) {
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
			if _, err := secret.ParseV1([]byte(testpki.Encode(t, f)), time.Now()); !errors.Is(err, intermediateca.ErrChain) {
				t.Fatalf("ParseV1 = %v, want a verification failure", err)
			}
		})
	}
}

func TestParseV1NotCA(t *testing.T) {
	p := testpki.New(t, testpki.Options{IntermediateNotCA: true})
	if _, err := secret.ParseV1([]byte(p.V1(t)), time.Now()); !errors.Is(err, intermediateca.ErrNotCA) {
		t.Fatalf("ParseV1 = %v, want not a CA", err)
	}
}

func TestParseV1Expired(t *testing.T) {
	now := time.Now()
	p := testpki.New(t, testpki.Options{Now: now, IntermediateTTL: 2 * time.Hour})
	if _, err := secret.ParseV1([]byte(p.V1(t)), now.Add(3*time.Hour)); !errors.Is(err, intermediateca.ErrExpired) {
		t.Fatalf("ParseV1 = %v, want expired", err)
	}
}

// The format admits any key that can sign; SPIRE's upstream CAs are ECDSA or
// RSA.
func TestParseV1RefusesEd25519(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := testpki.Template("Ed25519 CA", time.Now().Add(-time.Minute), time.Now().Add(24*time.Hour), true)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	doc := testpki.Encode(t, map[string]string{
		"format": "intermediate-ca/v1",
		"cert":   testpki.CertPEM(cert),
		"key":    testpki.KeyPEM(t, key),
		"root":   testpki.CertPEM(cert),
	})
	if _, err := secret.ParseV1([]byte(doc), time.Now()); err == nil || !strings.Contains(err.Error(), "unsupported private key type") {
		t.Fatalf("ParseV1 = %v, want the key type refused", err)
	}
}

func TestValidateRootPin(t *testing.T) {
	p := testpki.New(t, testpki.Options{})
	other := testpki.New(t, testpki.Options{})
	a := parse(t, p.V1(t))
	o := opts(a, time.Now())
	o.RootPins = [][32]byte{other.Pin(), p.Pin()}
	if err := a.Validate(o); err != nil {
		t.Fatalf("Validate with the pin second in the list: %v", err)
	}
	o.RootPins = [][32]byte{other.Pin()}
	if err := a.Validate(o); err == nil || !strings.Contains(err.Error(), "root_sha256") || !strings.Contains(err.Error(), p.PinHex()) {
		t.Fatalf("Validate with another root's pin = %v, want a pin mismatch naming the root", err)
	}
	o.RootPins = nil
	if err := a.Validate(o); err == nil || !strings.Contains(err.Error(), "no root_sha256") {
		t.Fatalf("Validate without a pin = %v, want refused", err)
	}
}

func TestValidateProbe(t *testing.T) {
	for name, tc := range map[string]struct {
		o    testpki.Options
		want string // empty: valid
	}{
		"no constraints": {o: testpki.Options{}},
		"production shape": {o: testpki.Options{
			Root: testpki.PathLen(2),
			Intermediate: testpki.All(testpki.PathLen(1),
				testpki.URIConstraints([]string{"example.org"}, []string{".example.org"})),
		}},
		"intermediate pathlen 0": {
			o:    testpki.Options{Intermediate: testpki.PathLen(0)},
			want: "would be rejected by SPIRE",
		},
		"root pathlen 1 with a middle CA": {
			o:    testpki.Options{Root: testpki.PathLen(1), Middle: 1},
			want: "would be rejected by SPIRE",
		},
		"trust domain excluded": {
			o:    testpki.Options{Intermediate: testpki.URIConstraints(nil, []string{"example.org"})},
			want: "would be rejected by SPIRE",
		},
		"other trust domain permitted": {
			o:    testpki.Options{Intermediate: testpki.URIConstraints([]string{"other.example.org"}, nil)},
			want: "would be rejected by SPIRE",
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := testpki.New(t, tc.o)
			err := validate(parse(t, p.V1(t)))
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("Validate: %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("Validate = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestValidateRequiresTrustDomain(t *testing.T) {
	p := testpki.New(t, testpki.Options{})
	a := parse(t, p.V1(t))
	o := opts(a, time.Now())
	o.TrustDomain = spiffeid.TrustDomain{}
	if err := a.Validate(o); err == nil {
		t.Fatal("validated without a trust domain")
	}
}

func TestValidateIncomplete(t *testing.T) {
	if err := (&secret.Authority{}).Validate(secret.ValidateOptions{}); err == nil {
		t.Fatal("validated an empty authority")
	}
}

func TestValidateMinRemaining(t *testing.T) {
	now := time.Now()
	p := testpki.New(t, testpki.Options{Now: now, IntermediateTTL: 2 * time.Hour})
	a := parse(t, p.V1(t))
	if err := a.Validate(withMin(opts(a, now), time.Hour)); err != nil {
		t.Fatalf("1h59m left, min 1h: %v", err)
	}
	if err := a.Validate(withMin(opts(a, now), 3*time.Hour)); err == nil || !strings.Contains(err.Error(), "min_remaining") {
		t.Fatalf("1h59m left, min 3h = %v, want rejected", err)
	}
	if err := a.Validate(withMin(opts(a, now.Add(3*time.Hour)), 0)); err == nil {
		t.Fatal("expired certificate accepted")
	}
}

func withMin(o secret.ValidateOptions, d time.Duration) secret.ValidateOptions {
	o.MinRemaining = d
	return o
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
		// The whole bundle is published.
		if roots := a.UpstreamRoots(); len(roots) != 2 || !roots[0].Equal(other.Root.Cert) || !roots[1].Equal(p.Root.Cert) {
			t.Fatalf("upstream roots: %d", len(roots))
		}
		if len(a.ExtraRoots()) != 2 {
			t.Fatal("the bundle is not reported as extra roots")
		}
		// It is held in the shared format too, for the cache.
		if a.Raw == nil || a.Raw.GetFormat() != intermediateca.Format {
			t.Fatal("no raw secret")
		}
	})

	t.Run("cert file ending with the root", func(t *testing.T) {
		a, err := secret.ParseAWSSecretLayout(
			testpki.CertPEM(p.Intermediate.Cert, p.Middle[0].Cert, p.Root.Cert), key,
			testpki.CertPEM(p.Root.Cert), now)
		if err != nil {
			t.Fatal(err)
		}
		if len(a.Chain) != 1 || !a.Chain[0].Equal(p.Middle[0].Cert) {
			t.Fatalf("chain has %d certificates, want the middle CA", len(a.Chain))
		}
	})

	t.Run("bundle that is not the root", func(t *testing.T) {
		_, err := secret.ParseAWSSecretLayout(testpki.CertPEM(p.Intermediate.Cert, p.Middle[0].Cert), key, testpki.CertPEM(other.Root.Cert), now)
		if err == nil {
			t.Fatal("accepted")
		}
	})

	t.Run("key of another certificate", func(t *testing.T) {
		_, err := secret.ParseAWSSecretLayout(testpki.CertPEM(p.Intermediate.Cert, p.Middle[0].Cert),
			testpki.KeyPEM(t, other.Intermediate.Key), testpki.CertPEM(p.Root.Cert), now)
		if !errors.Is(err, intermediateca.ErrKeyMismatch) {
			t.Fatalf("err = %v, want a key mismatch", err)
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
		if !a.SelfSigned() || a.UpstreamChain() != nil || a.ExtraRoots() != nil {
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

	t.Run("bad key", func(t *testing.T) {
		for _, k := range []string{"", "garbage", testpki.CertPEM(p.Root.Cert), key + key} {
			if _, err := secret.ParseAWSSecretLayout(testpki.CertPEM(p.Root.Cert), k, "", now); err == nil {
				t.Fatalf("key %.20q accepted", k)
			}
		}
	})
}
