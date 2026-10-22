package plugin_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
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
	"github.com/bpalermo/spire-upstream-secretsmanager/pkg/plugin"
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

func v1Config(extra string) string {
	return fmt.Sprintf("region = \"us-east-1\"\nsecret_id = %q\n%s", secretID, extra)
}

func cacheConfig(t *testing.T) (string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cache", "intermediate.json")
	return path, v1Config(fmt.Sprintf("cache_path = %q\n", path))
}

func TestConfigureMakesNoAWSCall(t *testing.T) {
	p := testpki.New(t, testpki.Options{})
	h := serve(t, newFake(map[string]string{secretID: p.V1(t)}))
	path, hcl := cacheConfig(t)
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
	h.mustConfigure(t, v1Config(""))
	if n := fake.count(); n != 0 {
		t.Fatalf("Configure made %d calls", n)
	}
}

func TestMintFetchesEveryCall(t *testing.T) {
	p := testpki.New(t, testpki.Options{})
	h := serve(t, newFake(map[string]string{secretID: p.V1(t)}))
	h.mustConfigure(t, v1Config(""))
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
	h.mustConfigure(t, v1Config(""))
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
	h.mustConfigure(t, v1Config(""))
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
	h.mustConfigure(t, v1Config(""))
	_, _, err := h.mint(t, "spiffe://other.example.org", time.Hour)
	if status.Code(err) != codes.Internal || !strings.Contains(err.Error(), "trust domain") {
		t.Fatalf("mint = %v, want Internal about the trust domain", err)
	}
}

func TestFetchFailureFallsBackToCache(t *testing.T) {
	p := testpki.New(t, testpki.Options{})
	path, hcl := cacheConfig(t)

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
	h.mustConfigure(t, v1Config(""))
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
	h.mustConfigure(t, v1Config(""))
	h.mustMint(t)
	h.fake.set(secretID, `{"format":"intermediate-ca/v9"}`)
	chain, _ := h.mustMint(t)
	if !chain[1].Equal(p.Intermediate.Cert) {
		t.Fatal("did not keep the last good intermediate")
	}
	if !strings.Contains(h.log.String(), "unsupported secret format") {
		t.Fatalf("no warning with the reason:\n%s", h.log)
	}
}

func TestFetchFailureWithoutCacheFails(t *testing.T) {
	fake := newFake(nil)
	fake.fail(errors.New("connection refused"))
	h := serve(t, fake)
	_, hcl := cacheConfig(t)
	h.mustConfigure(t, hcl)
	_, _, err := h.mint(t, "spiffe://"+trustDomain, time.Hour)
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("mint = %v, want Unavailable with the reason", err)
	}
}

func TestCorruptCacheIgnored(t *testing.T) {
	path, hcl := cacheConfig(t)
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
	_, hcl := cacheConfig(t)
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

	h.mustConfigure(t, v1Config("min_remaining = \"1h\"\n"))
	_, _, err := h.mint(t, "spiffe://"+trustDomain, time.Hour)
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "min_remaining") {
		t.Fatalf("mint = %v, want refused for min_remaining", err)
	}

	h.mustConfigure(t, v1Config("min_remaining = \"10m\"\n"))
	h.mustMint(t)
}

func TestLastGoodBelowMinRemainingNotUsed(t *testing.T) {
	now := time.Now()
	clock := &fakeClock{now: now}
	p := testpki.New(t, testpki.Options{Now: now, IntermediateTTL: 3 * time.Hour})
	fake := newFake(map[string]string{secretID: p.V1(t)})
	h := serveWithClock(t, fake, clock.Now)
	h.mustConfigure(t, v1Config(""))
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
	sum := sha256.Sum256(other.Root.Cert.Raw)
	h := serve(t, newFake(map[string]string{secretID: p.V1(t)}))
	h.mustConfigure(t, v1Config(fmt.Sprintf("root_sha256 = %q\n", hex.EncodeToString(sum[:]))))
	_, _, err := h.mint(t, "spiffe://"+trustDomain, time.Hour)
	if err == nil || !strings.Contains(err.Error(), "root_sha256") {
		t.Fatalf("mint = %v, want refused for the root pin", err)
	}

	good := sha256.Sum256(p.Root.Cert.Raw)
	h.mustConfigure(t, v1Config(fmt.Sprintf("root_sha256 = %q\n", strings.ToUpper(hex.EncodeToString(good[:])))))
	h.mustMint(t)
}

func TestEmergencyRotationPickedUp(t *testing.T) {
	now := time.Now()
	p := testpki.New(t, testpki.Options{Now: now})
	h := serve(t, newFake(map[string]string{secretID: p.V1(t)}))
	h.mustConfigure(t, v1Config(""))
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
	const (
		certARN   = "arn:aws:secretsmanager:us-east-1:111122223333:secret:example-cert"
		keyARN    = "arn:aws:secretsmanager:us-east-1:111122223333:secret:example-key"
		bundleARN = "arn:aws:secretsmanager:us-east-1:111122223333:secret:example-bundle"
	)
	fake := newFake(map[string]string{
		certARN:   testpki.CertPEM(p.Intermediate.Cert, p.Middle[0].Cert),
		keyARN:    testpki.KeyPEM(t, p.Intermediate.Key),
		bundleARN: testpki.CertPEM(p.Root.Cert),
	})
	h := serve(t, fake)
	h.mustConfigure(t, fmt.Sprintf("cert_file_arn = %q\nkey_file_arn = %q\nbundle_file_arn = %q\n", certARN, keyARN, bundleARN))
	if fake.count() != 0 {
		t.Fatal("Configure called AWS")
	}
	chain, roots := h.mustMint(t)
	if fake.count() != 3 {
		t.Fatalf("%d calls, want 3", fake.count())
	}
	if len(chain) != 3 || !chain[1].Equal(p.Intermediate.Cert) || !chain[2].Equal(p.Middle[0].Cert) || !roots[0].Equal(p.Root.Cert) {
		t.Fatal("wrong chain or roots")
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
	h.mustConfigure(t, fmt.Sprintf("cert_file_arn = %q\nkey_file_arn = %q\n", certARN, keyARN))
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
		"both layouts":         v1Config("cert_file_arn = \"a\"\nkey_file_arn = \"b\"\n"),
		"cert without key":     "cert_file_arn = \"a\"",
		"bundle only":          "bundle_file_arn = \"a\"",
		"bad pin":              v1Config("root_sha256 = \"abc\"\n"),
		"bad fetch_timeout":    v1Config("fetch_timeout = \"soon\"\n"),
		"zero fetch_timeout":   v1Config("fetch_timeout = \"0s\"\n"),
		"negative remaining":   v1Config("min_remaining = \"-1h\"\n"),
		"min_remaining string": v1Config("min_remaining = \"1 hour\"\n"),
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
		HclConfiguration:  v1Config(""),
	})
	if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "trust_domain") {
		t.Fatalf("Configure without a trust domain = %v", err)
	}
	resp, err := h.cfg.Validate(context.Background(), &configv1.ValidateRequest{
		CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: trustDomain},
		HclConfiguration:  v1Config("fetch_timeout = \"5s\"\nmin_remaining = \"0s\"\ncache_path = \"/tmp/x\"\nassume_role_arn = \"arn:aws:iam::111122223333:role/example\"\n"),
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
	h.mustConfigure(t, v1Config(""))
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
		plugin.WithNewClient(func(context.Context, plugin.Config) (plugin.SecretsClient, error) { return fake, nil }),
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
