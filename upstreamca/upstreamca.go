// Package upstreamca signs the CA certificate signing requests of a SPIRE
// server with an upstream CA, exactly as SPIRE's own x509svid.UpstreamCA does
// for the disk and awssecret UpstreamAuthority plugins.
//
// Adapted from SPIRE v1.15.5 (https://github.com/spiffe/spire, Apache-2.0):
// pkg/common/x509svid/upstreamca.go and csr.go, and pkg/common/x509util's
// GetSubjectKeyID and NewSerialNumber. Copyright The SPIFFE Authors.
package upstreamca

import (
	"crypto"
	"crypto/fips140"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 5280 method 1, as SPIRE.
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

const (
	// DefaultBackdate is how far before now a minted certificate's NotBefore
	// is.
	DefaultBackdate = 10 * time.Second
	// DefaultTTL is the TTL of a minted certificate when SPIRE asks for none.
	DefaultTTL = time.Hour
)

// UpstreamCA signs CSRs with an upstream CA certificate and its key.
type UpstreamCA struct {
	cert        *x509.Certificate
	key         crypto.Signer
	trustDomain spiffeid.TrustDomain
	now         func() time.Time
}

// New returns an UpstreamCA that signs with cert and key for trustDomain. now
// is the clock, time.Now if nil.
func New(cert *x509.Certificate, key crypto.Signer, trustDomain spiffeid.TrustDomain, now func() time.Time) *UpstreamCA {
	if now == nil {
		now = time.Now
	}
	return &UpstreamCA{cert: cert, key: key, trustDomain: trustDomain, now: now}
}

// SignCSR checks the CSR (its signature, and its only URI SAN being the trust
// domain's ID) and signs a CA certificate for it valid from now minus
// DefaultBackdate until now plus preferredTTL (DefaultTTL if not positive),
// but never after the upstream CA certificate's NotAfter.
func (ca *UpstreamCA) SignCSR(csrDER []byte, preferredTTL time.Duration) (*x509.Certificate, error) {
	csr, err := ParseAndValidateCSR(csrDER, ca.trustDomain)
	if err != nil {
		return nil, err
	}

	keyID, err := SubjectKeyID(csr.PublicKey)
	if err != nil {
		return nil, err
	}

	ttl := DefaultTTL
	if preferredTTL > 0 {
		ttl = preferredTTL
	}
	now := ca.now()
	notBefore := now.Add(-DefaultBackdate)
	notAfter := now.Add(ttl)
	if notAfter.After(ca.cert.NotAfter) {
		notAfter = ca.cert.NotAfter
	}

	serial, err := NewSerialNumber()
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		RawSubject:            csr.RawSubject,
		URIs:                  csr.URIs,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		SubjectKeyId:          keyID,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtraExtensions:       csr.Extensions,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// ParseAndValidateCSR parses a DER CSR and validates it for trust domain td.
func ParseAndValidateCSR(csrDER []byte, td spiffeid.TrustDomain) (*x509.CertificateRequest, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("unable to parse CSR: %w", err)
	}
	if err := ValidateCSR(csr, td); err != nil {
		return nil, err
	}
	return csr, nil
}

// ValidateCSR checks the CSR's signature and that its only URI SAN is the ID
// of trust domain td.
func ValidateCSR(csr *x509.CertificateRequest, td spiffeid.TrustDomain) error {
	if err := csr.CheckSignature(); err != nil {
		return fmt.Errorf("CSR signature check failed: %w", err)
	}
	if len(csr.URIs) != 1 {
		return errors.New("CSR must have exactly one URI SAN")
	}
	id, err := spiffeid.FromURI(csr.URIs[0])
	if err != nil {
		return fmt.Errorf("CSR with SPIFFE ID %q is invalid: %w", csr.URIs[0], err)
	}
	if id != td.ID() {
		return fmt.Errorf("CSR with SPIFFE ID %q is invalid: must use the trust domain ID for trust domain %q", id, td)
	}
	return nil
}

var maxUint128 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1))

// NewSerialNumber returns a random serial number in [1, 2^128-1].
func NewSerialNumber() (*big.Int, error) {
	s, err := rand.Int(rand.Reader, maxUint128)
	if err != nil {
		return nil, fmt.Errorf("cannot create random number: %w", err)
	}
	return s.Add(s, big.NewInt(1)), nil
}

// SubjectKeyID returns the subject key identifier of a public key: the SHA-1
// of the subjectPublicKey BIT STRING (RFC 5280 section 4.2.1.2, method 1), or,
// when the process runs in FIPS 140-only mode, the leftmost 160 bits of its
// SHA-256 (RFC 7093 section 2, method 1), as SPIRE.
func SubjectKeyID(pub any) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		return nil, err
	}
	if fips140Only() {
		h := sha256.Sum256(spki.SubjectPublicKey.Bytes)
		return h[:20], nil
	}
	h := sha1.Sum(spki.SubjectPublicKey.Bytes) //nolint:gosec // RFC 5280 method 1.
	return h[:], nil
}

// fips140Only is SPIRE's util.FIPS140Only.
func fips140Only() bool {
	return fips140.Enabled() && strings.Contains(os.Getenv("GODEBUG"), "fips140=only")
}
