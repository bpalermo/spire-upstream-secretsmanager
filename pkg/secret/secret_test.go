package secret_test

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/bpalermo/spire-upstream-secretsmanager/internal/testpki"
	"github.com/bpalermo/spire-upstream-secretsmanager/pkg/secret"
)

var td = spiffeid.RequireTrustDomainFromString("example.org")

// opts validates at now for example.org with a's own root pinned.
func opts(a *secret.Authority, now time.Time) secret.ValidateOptions {
	pin := secret.RootSHA256(a.Root)
	return secret.ValidateOptions{Now: now, MinRemaining: time.Hour, RootPins: [][]byte{pin[:]}, TrustDomain: td}
}

func validate(a *secret.Authority) error {
	if a == nil || a.Root == nil {
		return a.Validate(secret.ValidateOptions{})
	}
	return a.Validate(opts(a, time.Now()))
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
	other := testpki.New(t, testpki.Options{})
	a, err := secret.ParseV1([]byte(p.V1(t)))
	if err != nil {
		t.Fatal(err)
	}
	o := opts(a, time.Now())
	o.RootPins = [][]byte{other.Pin(), p.Pin()}
	if err := a.Validate(o); err != nil {
		t.Fatalf("Validate with the pin second in the list: %v", err)
	}
	o.RootPins = [][]byte{other.Pin()}
	if err := a.Validate(o); err == nil || !strings.Contains(err.Error(), "root_sha256") {
		t.Fatalf("Validate with another root's pin = %v, want a pin mismatch", err)
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
			a, err := secret.ParseV1([]byte(p.V1(t)))
			if err != nil {
				t.Fatal(err)
			}
			err = validate(a)
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
	a, err := secret.ParseV1([]byte(p.V1(t)))
	if err != nil {
		t.Fatal(err)
	}
	o := opts(a, time.Now())
	o.TrustDomain = spiffeid.TrustDomain{}
	if err := a.Validate(o); err == nil {
		t.Fatal("validated without a trust domain")
	}
}

func TestValidateMinRemaining(t *testing.T) {
	now := time.Now()
	p := testpki.New(t, testpki.Options{Now: now, IntermediateTTL: 2 * time.Hour})
	a, err := secret.ParseV1([]byte(p.V1(t)))
	if err != nil {
		t.Fatal(err)
	}
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
		// The whole bundle is published, and survives the cache encoding.
		if roots := a.UpstreamRoots(); len(roots) != 2 || !roots[0].Equal(other.Root.Cert) || !roots[1].Equal(p.Root.Cert) {
			t.Fatalf("upstream roots: %d", len(roots))
		}
		b, err := a.MarshalV1()
		if err != nil {
			t.Fatal(err)
		}
		cached, err := secret.ParseCache(b)
		if err != nil {
			t.Fatal(err)
		}
		if len(cached.UpstreamRoots()) != 2 || validate(cached) != nil {
			t.Fatal("the cache lost the bundle")
		}
		// A secret cannot smuggle extra roots in through that field.
		fromSecret, err := secret.ParseV1(b)
		if err != nil {
			t.Fatal(err)
		}
		if len(fromSecret.UpstreamRoots()) != 1 {
			t.Fatal("ParseV1 read x_upstream_bundle")
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
