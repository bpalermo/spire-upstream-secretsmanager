package plugin_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	"github.com/spiffe/spire-plugin-sdk/plugintest"
	upstreamauthorityv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/upstreamauthority/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/bpalermo/spire-upstream-secretsmanager/internal/testpki"
	"github.com/bpalermo/spire-upstream-secretsmanager/plugin"
)

const (
	secretID    = "arn:aws:secretsmanager:us-east-1:111122223333:secret:example"
	trustDomain = "example.org"
)

// fakeSecrets is a Secrets Manager that serves SecretStrings from a map and
// counts the calls.
type fakeSecrets struct {
	mu      sync.Mutex
	values  map[string]string
	err     error
	calls   int
	lastReq *secretsmanager.GetSecretValueInput
}

func newFake(values map[string]string) *fakeSecrets {
	return &fakeSecrets{values: values}
}

func (f *fakeSecrets) GetSecretValue(_ context.Context, in *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.lastReq = in
	if f.err != nil {
		return nil, f.err
	}
	v, ok := f.values[*in.SecretId]
	if !ok {
		return nil, fmt.Errorf("ResourceNotFoundException: %s", *in.SecretId)
	}
	return &secretsmanager.GetSecretValueOutput{SecretString: &v}, nil
}

func (f *fakeSecrets) set(id, v string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.values[id] = v
}

func (f *fakeSecrets) fail(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

func (f *fakeSecrets) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// syncBuffer is a log sink safe for the plugin's goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// harness is the plugin served over the SDK's test harness.
type harness struct {
	ua   *upstreamauthorityv1.UpstreamAuthorityPluginClient
	cfg  *configv1.ConfigServiceClient
	log  *syncBuffer
	fake *fakeSecrets
}

func serve(t *testing.T, fake *fakeSecrets) *harness {
	t.Helper()
	return serveWithClock(t, fake, time.Now)
}

func (h *harness) configure(t *testing.T, hcl string) error {
	t.Helper()
	_, err := h.cfg.Configure(context.Background(), &configv1.ConfigureRequest{
		CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: trustDomain},
		HclConfiguration:  hcl,
	})
	return err
}

func (h *harness) mustConfigure(t *testing.T, hcl string) {
	t.Helper()
	if err := h.configure(t, hcl); err != nil {
		t.Fatalf("Configure: %v", err)
	}
}

// mint mints a CA for a CSR with the given URI and preferred TTL.
func (h *harness) mint(t *testing.T, uri string, ttl time.Duration) ([]*x509.Certificate, []*x509.Certificate, error) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{URIs: []*url.URL{u}}, key)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := h.ua.MintX509CAAndSubscribe(context.Background(), &upstreamauthorityv1.MintX509CARequest{
		Csr:          csr,
		PreferredTtl: int32(ttl / time.Second),
	})
	if err != nil {
		return nil, nil, err
	}
	resp, err := stream.Recv()
	if err != nil {
		return nil, nil, err
	}
	return parse(t, resp.X509CaChain), parse(t, resp.UpstreamX509Roots), nil
}

func (h *harness) mustMint(t *testing.T) ([]*x509.Certificate, []*x509.Certificate) {
	t.Helper()
	chain, roots, err := h.mint(t, "spiffe://"+trustDomain, time.Hour)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	return chain, roots
}

type asn1Cert interface{ GetAsn1() []byte }

func parse[T asn1Cert](t *testing.T, certs []T) []*x509.Certificate {
	t.Helper()
	var out []*x509.Certificate
	for _, c := range certs {
		cert, err := x509.ParseCertificate(c.GetAsn1())
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, cert)
	}
	return out
}

// anyPin is a root_sha256 for tests that never get as far as a root.
var anyPin = strings.Repeat("00", 32)

func v1Config(pin, extra string) string {
	return fmt.Sprintf("region = \"us-east-1\"\nsecret_id = %q\nroot_sha256 = %q\n%s", secretID, pin, extra)
}

func cacheConfig(t *testing.T, pin string) (string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cache", "intermediate.json")
	return path, v1Config(pin, fmt.Sprintf("cache_path = %q\n", path))
}

func TestConfigureMakesNoAWSCall(t *testing.T) {
	p := testpki.New(t, testpki.Options{})
	h := serve(t, newFake(map[string]string{secretID: p.V1(t)}))
	path, hcl := cacheConfig(t, p.PinHex())
	h.mustConfigure(t, hcl)
	if n := h.fake.count(); n != 0 {
		t.Fatalf("Configure made %d Secrets Manager calls, want 0", n)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Configure wrote the cache: %v", err)
	}
}

func TestConfigureWithAWSUnreachable(t *testing.T) {
	fake := newFake(nil)
	fake.fail(errors.New("dial tcp: connection refused"))
	h := serve(t, fake)
	h.mustConfigure(t, v1Config(anyPin, ""))
	if n := fake.count(); n != 0 {
		t.Fatalf("Configure made %d calls", n)
	}
}

func TestMintFetchesEveryCall(t *testing.T) {
	p := testpki.New(t, testpki.Options{})
	h := serve(t, newFake(map[string]string{secretID: p.V1(t)}))
	h.mustConfigure(t, v1Config(p.PinHex(), ""))
	for i := 1; i <= 3; i++ {
		h.mustMint(t)
		if n := h.fake.count(); n != i {
			t.Fatalf("after %d mints, %d Secrets Manager calls", i, n)
		}
	}
	if got := *h.fake.lastReq.VersionStage; got != "AWSCURRENT" {
		t.Fatalf("VersionStage = %q, want AWSCURRENT", got)
	}
	if got := *h.fake.lastReq.SecretId; got != secretID {
		t.Fatalf("SecretId = %q", got)
	}
}

func TestResponseChainAndRoots(t *testing.T) {
	p := testpki.New(t, testpki.Options{Middle: 2})
	h := serve(t, newFake(map[string]string{secretID: p.V1(t)}))
	h.mustConfigure(t, v1Config(p.PinHex(), ""))
	chain, roots := h.mustMint(t)

	want := append([]*x509.Certificate{p.Intermediate.Cert}, p.ChainCerts()...)
	if len(chain) != 1+len(want) {
		t.Fatalf("chain has %d certificates, want %d", len(chain), 1+len(want))
	}
	for i, c := range want {
		if !chain[i+1].Equal(c) {
			t.Fatalf("chain[%d] is %q, want %q", i+1, chain[i+1].Subject, c.Subject)
		}
	}
	if len(roots) != 1 || !roots[0].Equal(p.Root.Cert) {
		t.Fatal("roots is not [root]")
	}
	ca := chain[0]
	if !ca.IsCA || len(ca.URIs) != 1 || ca.URIs[0].String() != "spiffe://"+trustDomain {
		t.Fatal("the minted certificate is not the SPIRE CA")
	}
	// The whole response verifies.
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	rootPool := x509.NewCertPool()
	rootPool.AddCert(roots[0])
	if _, err := ca.Verify(x509.VerifyOptions{Intermediates: inter, Roots: rootPool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Fatalf("minted CA does not verify to the root: %v", err)
	}
}

func TestMintedNotAfterCappedAtIntermediate(t *testing.T) {
	p := testpki.New(t, testpki.Options{IntermediateTTL: 3 * time.Hour})
	h := serve(t, newFake(map[string]string{secretID: p.V1(t)}))
	h.mustConfigure(t, v1Config(p.PinHex(), ""))
	chain, _, err := h.mint(t, "spiffe://"+trustDomain, 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !chain[0].NotAfter.Equal(p.Intermediate.Cert.NotAfter) {
		t.Fatalf("NotAfter = %s, want the intermediate's %s", chain[0].NotAfter, p.Intermediate.Cert.NotAfter)
	}
}

func TestWrongTrustDomainCSRRejected(t *testing.T) {
	p := testpki.New(t, testpki.Options{})
	h := serve(t, newFake(map[string]string{secretID: p.V1(t)}))
	h.mustConfigure(t, v1Config(p.PinHex(), ""))
	_, _, err := h.mint(t, "spiffe://other.example.org", time.Hour)
	if status.Code(err) != codes.Internal || !strings.Contains(err.Error(), "trust domain") {
		t.Fatalf("mint = %v, want Internal about the trust domain", err)
	}
}

func TestFetchFailureFallsBackToCache(t *testing.T) {
	p := testpki.New(t, testpki.Options{})
	path, hcl := cacheConfig(t, p.PinHex())

	// A first plugin fetches and writes the cache.
	h1 := serve(t, newFake(map[string]string{secretID: p.V1(t)}))
	h1.mustConfigure(t, hcl)
	h1.mustMint(t)
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("no cache written: %v", err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("cache mode %o", st.Mode().Perm())
	}

	// A second one (a restart) cannot reach AWS and uses the cache.
	fake := newFake(nil)
	fake.fail(errors.New("AccessDeniedException"))
	h2 := serve(t, fake)
	h2.mustConfigure(t, hcl)
	if !strings.Contains(h2.log.String(), "Loaded the cached intermediate CA") {
		t.Fatalf("cache not loaded at Configure:\n%s", h2.log)
	}
	chain, roots := h2.mustMint(t)
	if !chain[1].Equal(p.Intermediate.Cert) || !roots[0].Equal(p.Root.Cert) {
		t.Fatal("did not sign with the cached intermediate")
	}
	if fake.count() != 1 {
		t.Fatalf("%d calls, want 1 (it still tries Secrets Manager)", fake.count())
	}
	if log := h2.log.String(); !strings.Contains(log, "using the cached copy") || !strings.Contains(log, "AccessDeniedException") {
		t.Fatalf("no warning with the reason:\n%s", log)
	}
}

func TestFetchFailureFallsBackToMemory(t *testing.T) {
	p := testpki.New(t, testpki.Options{})
	h := serve(t, newFake(map[string]string{secretID: p.V1(t)}))
	h.mustConfigure(t, v1Config(p.PinHex(), ""))
	h.mustMint(t)
	h.fake.fail(errors.New("timeout"))
	chain, _ := h.mustMint(t)
	if !chain[1].Equal(p.Intermediate.Cert) {
		t.Fatal("did not sign with the last good intermediate")
	}
}

func TestInvalidSecretFallsBackToLastGood(t *testing.T) {
	p := testpki.New(t, testpki.Options{})
	h := serve(t, newFake(map[string]string{secretID: p.V1(t)}))
	h.mustConfigure(t, v1Config(p.PinHex(), ""))
	h.mustMint(t)
	h.fake.set(secretID, `{"format":"intermediate-ca/v9"}`)
	chain, _ := h.mustMint(t)
	if !chain[1].Equal(p.Intermediate.Cert) {
		t.Fatal("did not keep the last good intermediate")
	}
	if !strings.Contains(h.log.String(), "format (string.const)") {
		t.Fatalf("no warning with the reason:\n%s", h.log)
	}
}

func TestFetchFailureWithoutCacheFails(t *testing.T) {
	fake := newFake(nil)
	fake.fail(errors.New("connection refused"))
	h := serve(t, fake)
	_, hcl := cacheConfig(t, anyPin)
	h.mustConfigure(t, hcl)
	_, _, err := h.mint(t, "spiffe://"+trustDomain, time.Hour)
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("mint = %v, want Unavailable with the reason", err)
	}
}

func TestCorruptCacheIgnored(t *testing.T) {
	path, hcl := cacheConfig(t, anyPin)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	fake := newFake(nil)
	fake.fail(errors.New("unreachable"))
	h := serve(t, fake)
	h.mustConfigure(t, hcl)
	if !strings.Contains(h.log.String(), "Ignoring the cached intermediate CA") {
		t.Fatalf("no warning about the corrupt cache:\n%s", h.log)
	}
	if _, _, err := h.mint(t, "spiffe://"+trustDomain, time.Hour); err == nil {
		t.Fatal("minted with a corrupt cache and no Secrets Manager")
	}
}

func TestExpiredCacheIgnored(t *testing.T) {
	// A cache whose intermediate has 30 minutes left, under min_remaining's
	// default of an hour.
	p := testpki.New(t, testpki.Options{Now: time.Now().Add(-time.Hour), IntermediateTTL: 91 * time.Minute})
	_, hcl := cacheConfig(t, p.PinHex())
	h1 := serve(t, newFake(map[string]string{secretID: p.V1(t)}))
	h1.mustConfigure(t, hcl+"min_remaining = \"1m\"\n")
	h1.mustMint(t)

	fake := newFake(nil)
	fake.fail(errors.New("unreachable"))
	h2 := serve(t, fake)
	h2.mustConfigure(t, hcl)
	if !strings.Contains(h2.log.String(), "Ignoring the cached intermediate CA") {
		t.Fatalf("no warning about the expiring cache:\n%s", h2.log)
	}
	if _, _, err := h2.mint(t, "spiffe://"+trustDomain, time.Hour); err == nil {
		t.Fatal("minted with an expiring cache")
	}
}

func TestMinRemaining(t *testing.T) {
	// 30 minutes left.
	p := testpki.New(t, testpki.Options{Now: time.Now().Add(-time.Hour), IntermediateTTL: 91 * time.Minute})
	h := serve(t, newFake(map[string]string{secretID: p.V1(t)}))

	h.mustConfigure(t, v1Config(p.PinHex(), "min_remaining = \"1h\"\n"))
	_, _, err := h.mint(t, "spiffe://"+trustDomain, time.Hour)
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "min_remaining") {
		t.Fatalf("mint = %v, want refused for min_remaining", err)
	}

	h.mustConfigure(t, v1Config(p.PinHex(), "min_remaining = \"10m\"\n"))
	h.mustMint(t)
}

func TestLastGoodBelowMinRemainingNotUsed(t *testing.T) {
	now := time.Now()
	clock := &fakeClock{now: now}
	p := testpki.New(t, testpki.Options{Now: now, IntermediateTTL: 3 * time.Hour})
	fake := newFake(map[string]string{secretID: p.V1(t)})
	h := serveWithClock(t, fake, clock.Now)
	h.mustConfigure(t, v1Config(p.PinHex(), ""))
	h.mustMint(t)

	fake.fail(errors.New("unreachable"))
	clock.set(now.Add(150 * time.Minute)) // 29 minutes left
	if _, _, err := h.mint(t, "spiffe://"+trustDomain, time.Hour); err == nil {
		t.Fatal("used a last good intermediate with less than min_remaining left")
	}
}

func TestRootPinMismatchRefused(t *testing.T) {
	p := testpki.New(t, testpki.Options{})
	other := testpki.New(t, testpki.Options{})
	h := serve(t, newFake(map[string]string{secretID: p.V1(t)}))
	h.mustConfigure(t, v1Config(other.PinHex(), ""))
	_, _, err := h.mint(t, "spiffe://"+trustDomain, time.Hour)
	if err == nil || !strings.Contains(err.Error(), "root_sha256") {
		t.Fatalf("mint = %v, want refused for the root pin", err)
	}

	h.mustConfigure(t, v1Config(strings.ToUpper(p.PinHex()), ""))
	h.mustMint(t)
}

func TestRootPinRequired(t *testing.T) {
	h := serve(t, newFake(nil))
	hcl := fmt.Sprintf("secret_id = %q\n", secretID)
	if err := h.configure(t, hcl); status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "root_sha256") {
		t.Fatalf("Configure without root_sha256 = %v, want InvalidArgument", err)
	}
	if err := h.configure(t, hcl+"root_sha256 = []\n"); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("Configure with an empty root_sha256 list = %v, want InvalidArgument", err)
	}
}

func TestRootPinListStagesARootRotation(t *testing.T) {
	oldPKI := testpki.New(t, testpki.Options{})
	newPKI := testpki.New(t, testpki.Options{})
	h := serve(t, newFake(map[string]string{secretID: oldPKI.V1(t)}))
	h.mustConfigure(t, fmt.Sprintf("secret_id = %q\nroot_sha256 = [%q, %q]\n", secretID, oldPKI.PinHex(), newPKI.PinHex()))
	if _, roots := h.mustMint(t); !roots[0].Equal(oldPKI.Root.Cert) {
		t.Fatal("not the old root")
	}
	if strings.Contains(h.log.String(), "The upstream root changed") {
		t.Fatal("root change reported on the first mint")
	}

	h.fake.set(secretID, newPKI.V1(t))
	if _, roots := h.mustMint(t); !roots[0].Equal(newPKI.Root.Cert) {
		t.Fatal("the new, pinned root was not taken")
	}
	if !strings.Contains(h.log.String(), "[WARN]") || !strings.Contains(h.log.String(), "The upstream root changed") {
		t.Fatalf("no warning about the root change:\n%s", h.log)
	}
}

func TestUnpinnedRootFallsBack(t *testing.T) {
	p := testpki.New(t, testpki.Options{})
	attacker := testpki.New(t, testpki.Options{})
	h := serve(t, newFake(map[string]string{secretID: p.V1(t)}))
	h.mustConfigure(t, v1Config(p.PinHex(), ""))
	h.mustMint(t)
	// Someone who can only PutSecretValue installs their own hierarchy.
	h.fake.set(secretID, attacker.V1(t))
	chain, roots := h.mustMint(t)
	if !chain[1].Equal(p.Intermediate.Cert) || len(roots) != 1 || !roots[0].Equal(p.Root.Cert) {
		t.Fatal("an unpinned root was used")
	}
	if !strings.Contains(h.log.String(), "root_sha256") {
		t.Fatalf("no warning about the pin:\n%s", h.log)
	}
}

func TestUnusableIntermediateKeepsLastGood(t *testing.T) {
	for name, edit := range map[string]func(*x509.Certificate){
		"pathlen 0":              testpki.PathLen(0),
		"trust domain excluded":  testpki.URIConstraints(nil, []string{trustDomain}),
		"other domain permitted": testpki.URIConstraints([]string{"other.example.org"}, nil),
	} {
		t.Run(name, func(t *testing.T) {
			now := time.Now()
			p := testpki.New(t, testpki.Options{Now: now})
			path, hcl := cacheConfig(t, p.PinHex())
			h := serve(t, newFake(map[string]string{secretID: p.V1(t)}))
			h.mustConfigure(t, hcl)
			h.mustMint(t)
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}

			// Same root, but an intermediate SPIRE would reject every CA of.
			tmpl := testpki.Template("Unusable Intermediate CA", now.Add(-time.Minute), now.Add(90*24*time.Hour), true)
			edit(tmpl)
			bad := testpki.Issue(t, &p.Root, tmpl)
			f := p.V1Fields(t)
			f["cert"] = testpki.CertPEM(bad.Cert)
			f["key"] = testpki.KeyPEM(t, bad.Key)
			h.fake.set(secretID, testpki.Encode(t, f))

			chain, _ := h.mustMint(t)
			if !chain[1].Equal(p.Intermediate.Cert) {
				t.Fatal("signed with the unusable intermediate")
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("the unusable intermediate replaced the cache")
			}
			if !strings.Contains(h.log.String(), "would be rejected by SPIRE") {
				t.Fatalf("no warning with the reason:\n%s", h.log)
			}
		})
	}
}

func TestProductionShapedIntermediate(t *testing.T) {
	p := testpki.New(t, testpki.Options{
		Root: testpki.PathLen(2),
		Intermediate: testpki.All(testpki.PathLen(1),
			testpki.URIConstraints([]string{trustDomain}, []string{"." + trustDomain})),
	})
	h := serve(t, newFake(map[string]string{secretID: p.V1(t)}))
	h.mustConfigure(t, v1Config(p.PinHex(), ""))
	chain, _ := h.mustMint(t)
	if !chain[1].Equal(p.Intermediate.Cert) {
		t.Fatal("wrong intermediate")
	}
}

func TestReconfigureKeepsLastGood(t *testing.T) {
	p := testpki.New(t, testpki.Options{})
	h := serve(t, newFake(map[string]string{secretID: p.V1(t)}))
	h.mustConfigure(t, v1Config(p.PinHex(), ""))
	h.mustMint(t)
	h.mustConfigure(t, v1Config(p.PinHex(), "fetch_timeout = \"5s\"\n"))
	h.fake.fail(errors.New("unreachable"))
	chain, _ := h.mustMint(t)
	if !chain[1].Equal(p.Intermediate.Cert) {
		t.Fatal("reconfiguring dropped the last good intermediate")
	}
}

func TestUnknownKeysRejected(t *testing.T) {
	for _, extra := range []string{"root_sha265 = \"x\"\n", "cache = \"/tmp/x\"\n", "plugin_data { x = 1 }\n"} {
		h := serve(t, newFake(nil))
		hcl := v1Config(anyPin, extra)
		if err := h.configure(t, hcl); status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "unknown configuration keys") {
			t.Fatalf("Configure with %q = %v, want unknown keys refused", extra, err)
		}
		resp, err := h.cfg.Validate(context.Background(), &configv1.ValidateRequest{
			CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: trustDomain},
			HclConfiguration:  hcl,
		})
		if err != nil || resp.Valid {
			t.Fatalf("Validate with %q = %v, %v", extra, resp, err)
		}
	}
}

func TestEmergencyRotationPickedUp(t *testing.T) {
	now := time.Now()
	p := testpki.New(t, testpki.Options{Now: now})
	h := serve(t, newFake(map[string]string{secretID: p.V1(t)}))
	h.mustConfigure(t, v1Config(p.PinHex(), ""))
	chain, _ := h.mustMint(t)
	if !chain[1].Equal(p.Intermediate.Cert) {
		t.Fatal("first mint did not use the first intermediate")
	}

	// The secret now holds a new intermediate under the same root.
	next := testpki.Issue(t, &p.Root, testpki.Template("Test Intermediate CA 2", now.Add(-time.Minute), now.Add(90*24*time.Hour), true))
	f := p.V1Fields(t)
	f["cert"] = testpki.CertPEM(next.Cert)
	f["key"] = testpki.KeyPEM(t, next.Key)
	h.fake.set(secretID, testpki.Encode(t, f))

	chain, roots := h.mustMint(t)
	if !chain[1].Equal(next.Cert) {
		t.Fatal("the next mint did not use the new intermediate")
	}
	if err := chain[0].CheckSignatureFrom(next.Cert); err != nil {
		t.Fatalf("minted CA not signed by the new intermediate: %v", err)
	}
	if !roots[0].Equal(p.Root.Cert) {
		t.Fatal("root changed")
	}
}

func TestAWSSecretLayout(t *testing.T) {
	p := testpki.New(t, testpki.Options{Middle: 1})
	other := testpki.New(t, testpki.Options{})
	const (
		certARN   = "arn:aws:secretsmanager:us-east-1:111122223333:secret:example-cert"
		keyARN    = "arn:aws:secretsmanager:us-east-1:111122223333:secret:example-key"
		bundleARN = "arn:aws:secretsmanager:us-east-1:111122223333:secret:example-bundle"
	)
	fake := newFake(map[string]string{
		certARN:   testpki.CertPEM(p.Intermediate.Cert, p.Middle[0].Cert),
		keyARN:    testpki.KeyPEM(t, p.Intermediate.Key),
		bundleARN: testpki.CertPEM(p.Root.Cert, other.Root.Cert),
	})
	h := serve(t, fake)
	h.mustConfigure(t, fmt.Sprintf("cert_file_arn = %q\nkey_file_arn = %q\nbundle_file_arn = %q\nroot_sha256 = %q\n", certARN, keyARN, bundleARN, p.PinHex()))
	if fake.count() != 0 {
		t.Fatal("Configure called AWS")
	}
	chain, roots := h.mustMint(t)
	if fake.count() != 3 {
		t.Fatalf("%d calls, want 3", fake.count())
	}
	if len(chain) != 3 || !chain[1].Equal(p.Intermediate.Cert) || !chain[2].Equal(p.Middle[0].Cert) {
		t.Fatal("wrong chain")
	}
	// The whole bundle is published, as awssecret does.
	if len(roots) != 2 || !roots[0].Equal(p.Root.Cert) || !roots[1].Equal(other.Root.Cert) {
		t.Fatalf("roots: %d certificates, want the bundle", len(roots))
	}
}

func TestAWSSecretLayoutSelfSigned(t *testing.T) {
	p := testpki.New(t, testpki.Options{})
	const (
		certARN = "arn:aws:secretsmanager:us-east-1:111122223333:secret:example-cert"
		keyARN  = "arn:aws:secretsmanager:us-east-1:111122223333:secret:example-key"
	)
	fake := newFake(map[string]string{
		certARN: testpki.CertPEM(p.Root.Cert),
		keyARN:  testpki.KeyPEM(t, p.Root.Key),
	})
	h := serve(t, fake)
	h.mustConfigure(t, fmt.Sprintf("cert_file_arn = %q\nkey_file_arn = %q\nroot_sha256 = %q\n", certARN, keyARN, p.PinHex()))
	chain, roots := h.mustMint(t)
	// As awssecret: the self-signed CA is the root, and only the minted CA
	// is in the chain.
	if len(chain) != 1 || len(roots) != 1 || !roots[0].Equal(p.Root.Cert) {
		t.Fatalf("chain %d, roots %d", len(chain), len(roots))
	}
	if fake.count() != 2 {
		t.Fatalf("%d calls, want 2", fake.count())
	}

	// A chain without a bundle is refused.
	fake.set(certARN, testpki.CertPEM(p.Intermediate.Cert, p.Root.Cert))
	fake.set(keyARN, testpki.KeyPEM(t, p.Intermediate.Key))
	h.mustMint(t) // still the last good one
	if !strings.Contains(h.log.String(), "only self-signed CAs are supported") {
		t.Fatalf("no warning about the self-signed rule:\n%s", h.log)
	}
}

func TestConfigValidation(t *testing.T) {
	for name, hcl := range map[string]string{
		"malformed":            "secret_id = ",
		"nothing":              "region = \"us-east-1\"",
		"both layouts":         v1Config(anyPin, "cert_file_arn = \"a\"\nkey_file_arn = \"b\"\n"),
		"cert without key":     "cert_file_arn = \"a\"",
		"bundle only":          "bundle_file_arn = \"a\"",
		"bad pin":              fmt.Sprintf("secret_id = %q\nroot_sha256 = \"abc\"\n", secretID),
		"bad pin in a list":    fmt.Sprintf("secret_id = %q\nroot_sha256 = [%q, \"abc\"]\n", secretID, anyPin),
		"pin not a string":     fmt.Sprintf("secret_id = %q\nroot_sha256 = 1\n", secretID),
		"bad fetch_timeout":    v1Config(anyPin, "fetch_timeout = \"soon\"\n"),
		"zero fetch_timeout":   v1Config(anyPin, "fetch_timeout = \"0s\"\n"),
		"negative remaining":   v1Config(anyPin, "min_remaining = \"-1h\"\n"),
		"min_remaining string": v1Config(anyPin, "min_remaining = \"1 hour\"\n"),
	} {
		t.Run(name, func(t *testing.T) {
			h := serve(t, newFake(nil))
			if err := h.configure(t, hcl); status.Code(err) != codes.InvalidArgument {
				t.Fatalf("Configure = %v, want InvalidArgument", err)
			}
			resp, err := h.cfg.Validate(context.Background(), &configv1.ValidateRequest{
				CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: trustDomain},
				HclConfiguration:  hcl,
			})
			if err != nil {
				t.Fatal(err)
			}
			if resp.Valid || len(resp.Notes) == 0 {
				t.Fatalf("Validate = %v", resp)
			}
		})
	}

	h := serve(t, newFake(nil))
	_, err := h.cfg.Configure(context.Background(), &configv1.ConfigureRequest{
		CoreConfiguration: &configv1.CoreConfiguration{},
		HclConfiguration:  v1Config(anyPin, ""),
	})
	if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "trust_domain") {
		t.Fatalf("Configure without a trust domain = %v", err)
	}
	resp, err := h.cfg.Validate(context.Background(), &configv1.ValidateRequest{
		CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: trustDomain},
		HclConfiguration:  v1Config(anyPin, "fetch_timeout = \"5s\"\nmin_remaining = \"0s\"\ncache_path = \"/tmp/x\"\nassume_role_arn = \"arn:aws:iam::111122223333:role/example\"\n"),
	})
	if err != nil || !resp.Valid {
		t.Fatalf("Validate of a good configuration = %v, %v", resp, err)
	}
}

func TestMintBeforeConfigure(t *testing.T) {
	h := serve(t, newFake(nil))
	if _, _, err := h.mint(t, "spiffe://"+trustDomain, time.Hour); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("mint = %v, want FailedPrecondition", err)
	}
}

func TestUnimplemented(t *testing.T) {
	h := serve(t, newFake(nil))
	h.mustConfigure(t, v1Config(anyPin, ""))
	ctx := context.Background()
	pub, err := h.ua.PublishJWTKeyAndSubscribe(ctx, &upstreamauthorityv1.PublishJWTKeyRequest{})
	if err == nil {
		_, err = pub.Recv()
	}
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("PublishJWTKeyAndSubscribe = %v", err)
	}
	sub, err := h.ua.SubscribeToLocalBundle(ctx, &upstreamauthorityv1.SubscribeToLocalBundleRequest{})
	if err == nil {
		_, err = sub.Recv()
	}
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("SubscribeToLocalBundle = %v", err)
	}
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

func serveWithClock(t *testing.T, fake *fakeSecrets, now func() time.Time) *harness {
	t.Helper()
	h := servePlugin(t, plugin.New(
		plugin.WithNewClient(func(context.Context, plugin.ClientOptions) (plugin.SecretsClient, error) { return fake, nil }),
		plugin.WithClock(now),
	))
	h.fake = fake
	return h
}

// servePlugin serves p over the SDK's test harness.
func servePlugin(t *testing.T, p *plugin.Plugin) *harness {
	t.Helper()
	h := &harness{
		ua:  new(upstreamauthorityv1.UpstreamAuthorityPluginClient),
		cfg: new(configv1.ConfigServiceClient),
		log: new(syncBuffer),
	}
	plugintest.ServeInBackground(t, plugintest.Config{
		PluginServer:   upstreamauthorityv1.UpstreamAuthorityPluginServer(p),
		PluginClient:   h.ua,
		ServiceServers: []pluginsdk.ServiceServer{configv1.ConfigServiceServer(p)},
		ServiceClients: []pluginsdk.ServiceClient{h.cfg},
		Logger:         hclog.New(&hclog.LoggerOptions{Output: h.log, Level: hclog.Debug}),
	})
	return h
}

func TestJSONConfig(t *testing.T) {
	p := testpki.New(t, testpki.Options{})
	h := serve(t, newFake(map[string]string{secretID: p.V1(t)}))
	h.mustConfigure(t, fmt.Sprintf(`{"secret_id": %q, "root_sha256": [%q, %q]}`, secretID, anyPin, p.PinHex()))
	h.mustMint(t)
	if err := h.configure(t, fmt.Sprintf(`{"secret_id": %q, "root_sha256": %q, "typo": 1}`, secretID, p.PinHex())); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("JSON with an unknown key = %v", err)
	}
}

// plugin_data in JSON takes the same path as HCL: one pin as a string or a
// list, in either case, and unknown keys refused.
func TestJSONPluginData(t *testing.T) {
	p := testpki.New(t, testpki.Options{})
	h := serve(t, newFake(map[string]string{secretID: p.V1(t)}))
	for _, pins := range []string{
		fmt.Sprintf("%q", p.PinHex()),
		fmt.Sprintf("[%q, %q]", anyPin, strings.ToUpper(p.PinHex())),
	} {
		h.mustConfigure(t, fmt.Sprintf(`{"secret_id": %q, "root_sha256": %s, "fetch_timeout": "5s"}`, secretID, pins))
		h.mustMint(t)
	}
	err := h.configure(t, fmt.Sprintf(`{"secret_id": %q, "root_sha256": %q, "root_sha265": "x"}`, secretID, p.PinHex()))
	if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "unknown configuration keys: root_sha265") {
		t.Fatalf("Configure with an unknown JSON key = %v", err)
	}
}
