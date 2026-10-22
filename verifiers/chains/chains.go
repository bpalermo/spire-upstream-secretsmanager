// Package chains builds the certificate hierarchies the verifier tests run
// through real TLS stacks: a root, intermediates with and without X.509 name
// constraints, a SPIRE CA per trust domain below each, and leaf SVIDs.
//
// The shape matches production:
//
//	root (EC P-384, pathlen 2)
//	└─ intermediate (EC P-256, pathlen 1, NameConstraints critical, or none)
//	   └─ SPIRE CA (EC P-256, pathlen 0, URI SAN spiffe://<td>)
//	      └─ leaf (URI SAN spiffe://<td>/w, plus DNS SANs for some cases)
//
// Every leaf and every server certificate is listed with the verdict RFC 5280
// gives it, so a test can compare a verifier's behaviour with the standard.
package chains

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bpalermo/spire-upstream-secretsmanager/internal/testpki"
)

// The intermediates, by the name constraints they carry.
const (
	// URI is permitted URI domain "example.org": exactly the host example.org.
	URI = "uri"
	// URIDot is permitted URI domain ".example.org": RFC 5280 reads a leading
	// period as "any host below example.org", which excludes example.org.
	URIDot = "uri-dot"
	// DNS is permitted DNS ".svc.example.org", no URI constraint.
	DNS = "dns"
	// Excluded is excluded DNS ".nas.example.org".
	Excluded = "excluded"
	// None has no name constraints: the control.
	None = "none"
)

// Intermediates names every intermediate, in table order.
var Intermediates = []string{URI, URIDot, DNS, Excluded, None}

// Verdict is what a verifier did with a chain, or what it should do.
type Verdict string

const (
	Accepted Verdict = "ACCEPTED"
	Rejected Verdict = "REJECTED"
)

// Spec describes one end-entity certificate.
type Spec struct {
	// ID is the row name: the case letter and a variant, such as "C2".
	ID string
	// Case is the letter of the case the row belongs to (A to E).
	Case string
	// Intermediate is one of the constants above.
	Intermediate string
	// TrustDomain names the SPIRE CA (spiffe://<td>) and the leaf
	// (spiffe://<td>/w).
	TrustDomain string
	// DNS SANs of the leaf, if any.
	DNS []string
	// Server makes it a server certificate (serverAuth), named Path.
	Server bool
	// Path of a server certificate's SPIFFE ID; "/w" when empty.
	Path string
	// RFC is the verdict RFC 5280 gives the chain.
	RFC Verdict
	// Note says what the row shows.
	Note string
}

// ClientSpecs are the leaves presented as client certificates.
var ClientSpecs = []Spec{
	{ID: "A", Case: "A", Intermediate: URI, TrustDomain: "example.org", RFC: Accepted, Note: "permitted URI example.org, leaf spiffe://example.org/w"},
	{ID: "A-dot", Case: "A", Intermediate: URIDot, TrustDomain: "example.org", RFC: Rejected, Note: "permitted URI .example.org, leaf spiffe://example.org/w (host equals the domain)"},
	{ID: "A-sub", Case: "A", Intermediate: URI, TrustDomain: "td.example.org", RFC: Rejected, Note: "permitted URI example.org, leaf spiffe://td.example.org/w (host below the domain)"},
	{ID: "A-dot-sub", Case: "A", Intermediate: URIDot, TrustDomain: "td.example.org", RFC: Accepted, Note: "permitted URI .example.org, leaf spiffe://td.example.org/w"},
	{ID: "B", Case: "B", Intermediate: URI, TrustDomain: "other.test", RFC: Rejected, Note: "permitted URI example.org, SPIRE CA and leaf spiffe://other.test"},
	{ID: "C1", Case: "C", Intermediate: DNS, TrustDomain: "example.org", DNS: []string{"a.svc.example.org"}, RFC: Accepted, Note: "permitted DNS .svc.example.org, leaf DNS a.svc.example.org"},
	{ID: "C2", Case: "C", Intermediate: DNS, TrustDomain: "example.org", DNS: []string{"b.other.test"}, RFC: Rejected, Note: "permitted DNS .svc.example.org, leaf DNS b.other.test"},
	{ID: "D1", Case: "D", Intermediate: Excluded, TrustDomain: "example.org", DNS: []string{"kafka.nas.example.org"}, RFC: Rejected, Note: "excluded DNS .nas.example.org, leaf DNS kafka.nas.example.org"},
	{ID: "D2", Case: "D", Intermediate: Excluded, TrustDomain: "example.org", DNS: []string{"a.svc.example.org"}, RFC: Accepted, Note: "excluded DNS .nas.example.org, leaf DNS a.svc.example.org"},
	{ID: "E-A", Case: "E", Intermediate: None, TrustDomain: "example.org", RFC: Accepted, Note: "no constraints, leaf of A"},
	{ID: "E-sub", Case: "E", Intermediate: None, TrustDomain: "td.example.org", RFC: Accepted, Note: "no constraints, leaf of A-sub"},
	{ID: "E-B", Case: "E", Intermediate: None, TrustDomain: "other.test", RFC: Accepted, Note: "no constraints, leaf of B"},
	{ID: "E-C2", Case: "E", Intermediate: None, TrustDomain: "example.org", DNS: []string{"b.other.test"}, RFC: Accepted, Note: "no constraints, leaf of C2"},
	{ID: "E-D1", Case: "E", Intermediate: None, TrustDomain: "example.org", DNS: []string{"kafka.nas.example.org"}, RFC: Accepted, Note: "no constraints, leaf of D1"},
}

// ServerName is the DNS name of the server certificate every client-auth
// test uses: issued under the unconstrained intermediate, so only the client
// chain varies.
const ServerName = "server.example.org"

// ServerSpecs are server certificates. "server" is the one every client-auth
// test presents; the K rows are broker certificates for the Kafka client's
// hostname verification (case D on the server side).
var ServerSpecs = []Spec{
	{ID: "server", Intermediate: None, TrustDomain: "example.org", DNS: []string{ServerName}, Server: true, Path: "/server", RFC: Accepted, Note: "the server certificate of the client-auth tests"},
	{ID: "K-D1", Case: "D", Intermediate: Excluded, TrustDomain: "example.org", DNS: []string{"kafka.nas.example.org"}, Server: true, Path: "/kafka", RFC: Rejected, Note: "broker DNS kafka.nas.example.org under excluded .nas.example.org"},
	{ID: "K-D2", Case: "D", Intermediate: Excluded, TrustDomain: "example.org", DNS: []string{"kafka.svc.example.org"}, Server: true, Path: "/kafka", RFC: Accepted, Note: "broker DNS kafka.svc.example.org under excluded .nas.example.org"},
	{ID: "K-E", Case: "E", Intermediate: None, TrustDomain: "example.org", DNS: []string{"kafka.nas.example.org"}, Server: true, Path: "/kafka", RFC: Accepted, Note: "broker DNS kafka.nas.example.org, no constraints"},
}

// Leaf is an issued end-entity certificate.
type Leaf struct {
	Spec
	Cert *x509.Certificate
	Key  crypto.Signer
	// SPIRECA and Intermediate are the CAs between the leaf and the root.
	SPIRECA      *x509.Certificate
	Intermediate *x509.Certificate
}

// Chain is the leaf, the SPIRE CA and the intermediate: what a peer sends.
func (l *Leaf) Chain() []*x509.Certificate {
	return []*x509.Certificate{l.Cert, l.SPIRECA, l.Intermediate}
}

// SPIFFEID is the SPIFFE ID of the leaf.
func (l *Leaf) SPIFFEID() string { return l.Cert.URIs[0].String() }

// Set is every certificate of the tests.
type Set struct {
	Root          testpki.CA
	Intermediates map[string]testpki.CA
	Clients       []*Leaf
	Servers       map[string]*Leaf
}

// New issues the whole set. Certificates are valid from a minute ago for a day.
func New(t testing.TB) *Set {
	t.Helper()
	nb := time.Now().Add(-time.Minute)
	na := nb.Add(24 * time.Hour)

	rootTmpl := testpki.Template("Verifier Root CA", nb, na, true)
	rootTmpl.MaxPathLen = 2
	s := &Set{
		Root:          issue(t, nil, rootTmpl, elliptic.P384()),
		Intermediates: map[string]testpki.CA{},
		Servers:       map[string]*Leaf{},
	}
	for _, name := range Intermediates {
		tmpl := testpki.Template("Verifier Intermediate CA ("+name+")", nb, na, true)
		tmpl.MaxPathLen = 1
		constrain(tmpl, name)
		s.Intermediates[name] = issue(t, &s.Root, tmpl, elliptic.P256())
	}

	spireCAs := map[[2]string]testpki.CA{}
	spireCA := func(inter, td string) testpki.CA {
		k := [2]string{inter, td}
		if ca, ok := spireCAs[k]; ok {
			return ca
		}
		tmpl := testpki.Template("SPIRE CA", nb, na, true)
		tmpl.MaxPathLen = 0
		tmpl.MaxPathLenZero = true
		tmpl.URIs = []*url.URL{{Scheme: "spiffe", Host: td}}
		parent := s.Intermediates[inter]
		ca := issue(t, &parent, tmpl, elliptic.P256())
		spireCAs[k] = ca
		return ca
	}

	leaf := func(sp Spec) *Leaf {
		parent := spireCA(sp.Intermediate, sp.TrustDomain)
		path := sp.Path
		if path == "" {
			path = "/w"
		}
		cn := "workload"
		if sp.Server {
			cn = "server"
		}
		tmpl := testpki.Template(cn, nb, na, false)
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
		tmpl.URIs = []*url.URL{{Scheme: "spiffe", Host: sp.TrustDomain, Path: path}}
		tmpl.DNSNames = sp.DNS
		ca := issue(t, &parent, tmpl, elliptic.P256())
		return &Leaf{
			Spec:         sp,
			Cert:         ca.Cert,
			Key:          ca.Key,
			SPIRECA:      parent.Cert,
			Intermediate: s.Intermediates[sp.Intermediate].Cert,
		}
	}
	for _, sp := range ClientSpecs {
		s.Clients = append(s.Clients, leaf(sp))
	}
	for _, sp := range ServerSpecs {
		s.Servers[sp.ID] = leaf(sp)
	}
	return s
}

func constrain(tmpl *x509.Certificate, name string) {
	switch name {
	case URI:
		tmpl.PermittedURIDomains = []string{"example.org"}
	case URIDot:
		tmpl.PermittedURIDomains = []string{".example.org"}
	case DNS:
		tmpl.PermittedDNSDomains = []string{".svc.example.org"}
	case Excluded:
		tmpl.ExcludedDNSDomains = []string{".nas.example.org"}
	case None:
		return
	}
	// Go marks the extension critical with this flag whatever the name type.
	tmpl.PermittedDNSDomainsCritical = true
}

func issue(t testing.TB, parent *testpki.CA, tmpl *x509.Certificate, curve elliptic.Curve) testpki.CA {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	parentCert, parentKey := tmpl, crypto.Signer(key)
	if parent != nil {
		parentCert, parentKey = parent.Cert, parent.Key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, key.Public(), parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testpki.CA{Cert: cert, Key: key}
}

// Write writes the set as PEM files into dir, readable by any user (the
// containers run as their own users):
//
//	root.pem                the trust anchor
//	<id>.chain.pem          leaf, SPIRE CA, intermediate
//	<id>.key.pem            the leaf's PKCS#8 key
//	<id>.bundle.pem         key then chain: a Kafka PEM keystore
//	<id>.cert.pem           the leaf alone
//	<id>.untrusted.pem      SPIRE CA and intermediate (openssl -untrusted)
//
// for every client and server ID.
func (s *Set) Write(t testing.TB, dir string) {
	t.Helper()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	write("root.pem", testpki.CertPEM(s.Root.Cert))
	all := append([]*Leaf{}, s.Clients...)
	for _, sp := range ServerSpecs {
		all = append(all, s.Servers[sp.ID])
	}
	for _, l := range all {
		chain := testpki.CertPEM(l.Chain()...)
		key := testpki.KeyPEM(t, l.Key)
		write(l.Spec.ID+".chain.pem", chain)
		write(l.Spec.ID+".key.pem", key)
		write(l.Spec.ID+".bundle.pem", key+chain)
		write(l.Spec.ID+".cert.pem", testpki.CertPEM(l.Cert))
		write(l.Spec.ID+".untrusted.pem", testpki.CertPEM(l.SPIRECA, l.Intermediate))
	}
}

// Results collects a verifier's verdicts, compares each with what the test
// expects and writes them, tab separated, to results.tsv in the test's
// undeclared outputs (bazel-testlogs/<target>/test.outputs/<verifier>.tsv),
// as well as to
// the test log.
type Results struct {
	t        testing.TB
	verifier string
	expect   map[string]Verdict
	rows     []string
}

// NewResults starts the results of one verifier. expect overrides, by row ID,
// the RFC 5280 verdict a row is expected to get: the known deviations of that
// verifier, each of which RESULTS.md explains.
func NewResults(t testing.TB, verifier string, expect map[string]Verdict) *Results {
	r := &Results{t: t, verifier: verifier, expect: expect}
	t.Cleanup(r.flush)
	return r
}

// Record adds a row. detail is the error a rejection gave (one line).
func (r *Results) Record(sp Spec, got Verdict, detail string) {
	r.t.Helper()
	want := sp.RFC
	if v, ok := r.expect[sp.ID]; ok {
		want = v
	}
	r.rows = append(r.rows, r.verifier+"\t"+sp.ID+"\t"+string(got)+"\t"+string(sp.RFC)+"\t"+detail)
	r.t.Logf("RESULT %-14s %-10s %-8s (RFC 5280: %s) %s", r.verifier, sp.ID, got, sp.RFC, detail)
	if got != want {
		r.t.Errorf("%s %s (%s): got %s, want %s; %s", r.verifier, sp.ID, sp.Note, got, want, detail)
	}
}

func (r *Results) flush() {
	dir := os.Getenv("TEST_UNDECLARED_OUTPUTS_DIR")
	if dir == "" || len(r.rows) == 0 {
		return
	}
	out := "verifier\tid\tgot\trfc5280\tdetail\n"
	for _, row := range r.rows {
		out += row + "\n"
	}
	name := strings.NewReplacer("/", "_", " ", "_", "(", "", ")", "").Replace(r.verifier)
	if err := os.WriteFile(filepath.Join(dir, name+".tsv"), []byte(out), 0o644); err != nil {
		r.t.Error(err)
	}
}
