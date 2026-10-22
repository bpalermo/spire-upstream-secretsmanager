// Package testpki builds throwaway certificate hierarchies for tests: a root,
// optional middle CAs and an intermediate CA, in the shapes the plugin reads.
package testpki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// CA is a certificate and its key.
type CA struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

// PKI is a root, the middle CAs below it (root-side first) and an
// intermediate CA signed by the last middle CA, or by the root if there is
// none.
type PKI struct {
	Root         CA
	Middle       []CA
	Intermediate CA
}

// Options shape a PKI. The zero value is a root valid for a year and an
// intermediate valid for 90 days, starting now.
type Options struct {
	// Now is the start of every validity period (minus a minute); zero is
	// time.Now().
	Now time.Time
	// RootTTL and IntermediateTTL default to a year and 90 days.
	RootTTL         time.Duration
	IntermediateTTL time.Duration
	// Middle is the number of CAs between the root and the intermediate.
	Middle int
	// IntermediateNotCA makes the intermediate an end-entity certificate.
	IntermediateNotCA bool
	// CommonName of the intermediate, "Test Intermediate CA" if empty.
	CommonName string
}

// New builds a PKI.
func New(t testing.TB, o Options) *PKI {
	t.Helper()
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	if o.RootTTL == 0 {
		o.RootTTL = 365 * 24 * time.Hour
	}
	if o.IntermediateTTL == 0 {
		o.IntermediateTTL = 90 * 24 * time.Hour
	}
	if o.CommonName == "" {
		o.CommonName = "Test Intermediate CA"
	}
	notBefore := o.Now.Add(-time.Minute)
	p := &PKI{}
	p.Root = Issue(t, nil, Template("Test Root CA", notBefore, notBefore.Add(o.RootTTL), true))
	parent := p.Root
	for range o.Middle {
		m := Issue(t, &parent, Template("Test Middle CA", notBefore, notBefore.Add(o.RootTTL), true))
		p.Middle = append(p.Middle, m)
		parent = m
	}
	p.Intermediate = Issue(t, &parent, Template(o.CommonName, notBefore, notBefore.Add(o.IntermediateTTL), !o.IntermediateNotCA))
	return p
}

// Template is a certificate template with a fresh serial.
func Template(cn string, notBefore, notAfter time.Time, isCA bool) *x509.Certificate {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		panic(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"Example"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		KeyUsage:              x509.KeyUsageDigitalSignature,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}
	return tmpl
}

// Issue creates a new P-256 key and a certificate for it from tmpl, signed by
// parent, or self-signed if parent is nil.
func Issue(t testing.TB, parent *CA, tmpl *x509.Certificate) CA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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
	return CA{Cert: cert, Key: key}
}

// CertPEM encodes certificates as PEM.
func CertPEM(certs ...*x509.Certificate) string {
	var out []byte
	for _, c := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return string(out)
}

// KeyPEM encodes a key as PKCS#8 PEM.
func KeyPEM(t testing.TB, key crypto.Signer) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// ChainCerts returns the middle CAs from the intermediate's issuer up to the
// root's child: the order of a format v1 "chain".
func (p *PKI) ChainCerts() []*x509.Certificate {
	var out []*x509.Certificate
	for i := len(p.Middle) - 1; i >= 0; i-- {
		out = append(out, p.Middle[i].Cert)
	}
	return out
}

// V1Fields returns the fields of a format v1 secret for the PKI, to be edited
// and then encoded with [Encode].
func (p *PKI) V1Fields(t testing.TB) map[string]string {
	t.Helper()
	return map[string]string{
		"format": "intermediate-ca/v1",
		"cert":   CertPEM(p.Intermediate.Cert),
		"key":    KeyPEM(t, p.Intermediate.Key),
		"chain":  CertPEM(p.ChainCerts()...),
		"root":   CertPEM(p.Root.Cert),
	}
}

// V1 returns the format v1 secret for the PKI.
func (p *PKI) V1(t testing.TB) string {
	t.Helper()
	return Encode(t, p.V1Fields(t))
}

// Encode encodes secret fields as JSON.
func Encode(t testing.TB, fields map[string]string) string {
	t.Helper()
	b, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
