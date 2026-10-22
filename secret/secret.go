// Package secret parses and validates the intermediate CA that the plugin
// reads from AWS Secrets Manager, in either of the two layouts it supports:
//
//   - format v1 (docs/secret-format.md): one secret whose SecretString is a
//     JSON object with the intermediate certificate, its key, the chain and
//     the root;
//   - the layout of SPIRE's built-in awssecret UpstreamAuthority: up to three
//     secrets whose SecretString is PEM (the certificate file, the key file
//     and the bundle file).
//
// Either way the result is an [Authority], which is validated the same way
// before it is used: the key matches the certificate, the certificate is a CA
// and verifies to the root through the chain, the root is the pinned one (if
// a pin is configured) and enough of the certificate's lifetime is left.
package secret

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// FormatV1 is the value of the "format" field of a format v1 secret.
const FormatV1 = "intermediate-ca/v1"

// Authority is an intermediate CA: the certificate the plugin signs with,
// its private key, the certificates between it and the root, and the root.
type Authority struct {
	// Cert is the intermediate CA certificate.
	Cert *x509.Certificate
	// Key is Cert's private key.
	Key crypto.Signer
	// Chain holds the certificates between Cert and Root, in order from the
	// one that signed Cert towards the root. It may be empty.
	Chain []*x509.Certificate
	// Root is the trust anchor Cert verifies to. It is Cert itself when Cert
	// is self-signed.
	Root *x509.Certificate
	// Roots are the upstream roots SPIRE receives. It always holds Root; with
	// the awssecret layout it is the whole bundle, as SPIRE's awssecret and
	// disk plugins publish it. Nil means [Root].
	Roots []*x509.Certificate
}

// v1 is the JSON of a format v1 secret. Unknown fields are ignored.
type v1 struct {
	Format string `json:"format"`
	Cert   string `json:"cert"`
	Key    string `json:"key"`
	Chain  string `json:"chain"`
	Root   string `json:"root"`
	// UpstreamBundle is not part of format v1: the plugin's cache uses it to
	// keep the awssecret bundle (Roots) when it holds more than the root. It
	// is read only by [ParseCache], never from a secret.
	UpstreamBundle string `json:"x_upstream_bundle,omitempty"`
}

// ParseV1 parses a format v1 secret. It checks the structure (format, one
// certificate in cert and in root, a PKCS#8 key); [Authority.Validate] checks
// the rest.
func ParseV1(data []byte) (*Authority, error) {
	a, _, err := parseV1(data)
	return a, err
}

// ParseCache parses the plugin's cache file: format v1, plus the awssecret
// bundle when it holds more than the root.
func ParseCache(data []byte) (*Authority, error) {
	a, bundle, err := parseV1(data)
	if err != nil || bundle == "" {
		return a, err
	}
	if a.Roots, err = parseCertificates(bundle); err != nil {
		return nil, fmt.Errorf("x_upstream_bundle: %w", err)
	}
	return a, nil
}

func parseV1(data []byte) (*Authority, string, error) {
	a, s, err := parseV1Fields(data)
	if err != nil {
		return nil, "", err
	}
	return a, s.UpstreamBundle, nil
}

func parseV1Fields(data []byte) (*Authority, *v1, error) {
	var s v1
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, nil, fmt.Errorf("secret is not a JSON object: %w", err)
	}
	if s.Format != FormatV1 {
		return nil, nil, fmt.Errorf("unsupported secret format %q, want %q", s.Format, FormatV1)
	}
	cert, err := parseOneCertificate("cert", s.Cert)
	if err != nil {
		return nil, nil, err
	}
	root, err := parseOneCertificate("root", s.Root)
	if err != nil {
		return nil, nil, err
	}
	chain, err := parseCertificates(s.Chain)
	if err != nil {
		return nil, nil, fmt.Errorf("chain: %w", err)
	}
	key, err := parsePKCS8Key(s.Key)
	if err != nil {
		return nil, nil, fmt.Errorf("key: %w", err)
	}
	return &Authority{Cert: cert, Key: key, Chain: chain, Root: root}, &s, nil
}

// ParseAWSSecretLayout builds an Authority from the three PEM documents of
// SPIRE's awssecret layout, read exactly as awssecret reads them: certPEM
// holds the CA certificate first, optionally followed by the intermediates
// up to the root; keyPEM holds its private key; bundlePEM holds the trust
// bundle. bundlePEM may be empty only if certPEM is exactly one self-signed
// certificate, which is then its own root.
//
// The root is the certificate of the bundle that the certificate verifies to
// at time at; the whole bundle is kept as the upstream roots.
func ParseAWSSecretLayout(certPEM, keyPEM, bundlePEM string, at time.Time) (*Authority, error) {
	certs, err := parseCertificates(certPEM)
	if err != nil {
		return nil, fmt.Errorf("cert_file_arn: %w", err)
	}
	if len(certs) == 0 {
		return nil, errors.New("cert_file_arn: no certificate found")
	}
	key, err := parseAnyKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("key_file_arn: %w", err)
	}
	a := &Authority{Cert: certs[0], Key: key, Chain: certs[1:]}
	if bundlePEM == "" {
		// As awssecret: with no bundle, only a self-signed CA is supported,
		// and it is its own trust anchor.
		// awssecret only counts the certificates; a lone certificate that
		// is not self-signed would then be trusted as its own root, so
		// self-signature is checked as well.
		if len(certs) != 1 || !isSelfSigned(certs[0]) {
			return nil, errors.New("with no bundle_file_arn configured only self-signed CAs are supported")
		}
		a.Root = certs[0]
		a.Roots = []*x509.Certificate{certs[0]}
		return a, nil
	}
	bundle, err := parseCertificates(bundlePEM)
	if err != nil {
		return nil, fmt.Errorf("bundle_file_arn: %w", err)
	}
	if len(bundle) == 0 {
		return nil, errors.New("bundle_file_arn: no certificate found")
	}
	a.Root, err = anchorOf(a.Cert, a.Chain, bundle, at)
	if err != nil {
		return nil, err
	}
	a.Roots = bundle
	return a, nil
}

// isSelfSigned reports whether c is issued by itself and signed by its own
// key.
func isSelfSigned(c *x509.Certificate) bool {
	return bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignatureFrom(c) == nil
}

// anchorOf returns the certificate of bundle that cert verifies to through
// chain at time at.
func anchorOf(cert *x509.Certificate, chain, bundle []*x509.Certificate, at time.Time) (*x509.Certificate, error) {
	roots := x509.NewCertPool()
	for _, c := range bundle {
		roots.AddCert(c)
	}
	opts := verifyOptions(chain, roots, at)
	chains, err := cert.Verify(opts)
	if err != nil {
		return nil, fmt.Errorf("certificate cannot be validated with the provided bundle or is not self-signed: %w", err)
	}
	path := chains[0]
	return path[len(path)-1], nil
}

// ValidateOptions are the checks of [Authority.Validate] that depend on the
// configuration and on the time.
type ValidateOptions struct {
	// Now is the time the certificates must be valid at.
	Now time.Time
	// MinRemaining is how long, at least, the intermediate certificate must
	// still be valid after Now.
	MinRemaining time.Duration
	// RootPins are the SHA-256s of the DER of the roots accepted. At least
	// one is required.
	RootPins [][]byte
	// TrustDomain is the trust domain the intermediate must be able to sign
	// a SPIRE CA for. Required.
	TrustDomain spiffeid.TrustDomain
}

// Validate checks that the authority can be used: the key matches the
// certificate, the certificate is a CA, the root is pinned, the certificate
// verifies to the root through the chain at opts.Now, at least
// opts.MinRemaining of its lifetime is left, and it can actually sign a CA
// for the trust domain whose X509-SVIDs verify to the root (path length and
// name constraints included), which SPIRE checks for every CA it receives.
func (a *Authority) Validate(opts ValidateOptions) error {
	if err := a.validateStatic(opts); err != nil {
		return err
	}
	roots := x509.NewCertPool()
	roots.AddCert(a.Root)
	if _, err := a.Cert.Verify(verifyOptions(a.Chain, roots, opts.Now)); err != nil {
		return fmt.Errorf("certificate does not verify to the root through the chain: %w", err)
	}
	if left := a.Cert.NotAfter.Sub(opts.Now); left < opts.MinRemaining {
		return fmt.Errorf("certificate expires at %s, %s from now, less than min_remaining %s",
			a.Cert.NotAfter.UTC().Format(time.RFC3339), left.Round(time.Second), opts.MinRemaining)
	}
	return a.probe(opts)
}

// validateStatic runs the checks that do not depend on the time.
func (a *Authority) validateStatic(opts ValidateOptions) error {
	if a == nil || a.Cert == nil || a.Key == nil || a.Root == nil {
		return errors.New("incomplete intermediate CA")
	}
	if err := keyMatches(a.Key, a.Cert); err != nil {
		return err
	}
	if !a.Cert.BasicConstraintsValid || !a.Cert.IsCA {
		return errors.New("certificate is not a CA certificate")
	}
	if a.Cert.KeyUsage != 0 && a.Cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("certificate key usage does not allow certificate signing")
	}
	if !a.hasRoot() {
		return errors.New("the upstream roots do not include the root")
	}
	return checkPinned(a.Root, opts.RootPins)
}

func (a *Authority) hasRoot() bool {
	for _, r := range a.UpstreamRoots() {
		if r.Equal(a.Root) {
			return true
		}
	}
	return false
}

// checkPinned checks that root's SHA-256 is one of pins.
func checkPinned(root *x509.Certificate, pins [][]byte) error {
	if len(pins) == 0 {
		return errors.New("no root_sha256 configured")
	}
	got := RootSHA256(root)
	for _, pin := range pins {
		if bytes.Equal(got[:], pin) {
			return nil
		}
	}
	return fmt.Errorf("root certificate SHA-256 %x is not one of the configured root_sha256", got)
}

// verifyOptions verifies a CA certificate: any extended key usage is fine,
// since the certificate is not used as a TLS server's.
func verifyOptions(chain []*x509.Certificate, roots *x509.CertPool, at time.Time) x509.VerifyOptions {
	intermediates := x509.NewCertPool()
	for _, c := range chain {
		intermediates.AddCert(c)
	}
	return x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         roots,
		CurrentTime:   at,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
}

// SelfSigned reports whether the intermediate certificate is the root itself.
func (a *Authority) SelfSigned() bool {
	return a.Cert.Equal(a.Root)
}

// UpstreamChain is what follows a newly minted CA certificate in the chain
// SPIRE receives: the intermediate certificate and the chain, or nothing when
// the certificate is self-signed (it is then the root, which SPIRE receives
// as the upstream root), as SPIRE's disk and awssecret plugins do.
func (a *Authority) UpstreamChain() []*x509.Certificate {
	if a.SelfSigned() {
		return nil
	}
	return append([]*x509.Certificate{a.Cert}, a.Chain...)
}

// UpstreamRoots are the roots SPIRE receives: Roots, or [Root].
func (a *Authority) UpstreamRoots() []*x509.Certificate {
	if len(a.Roots) == 0 {
		return []*x509.Certificate{a.Root}
	}
	return a.Roots
}

// RootSHA256 returns the SHA-256 of the root certificate's DER, the value
// root_sha256 pins.
func RootSHA256(root *x509.Certificate) [sha256.Size]byte {
	return sha256.Sum256(root.Raw)
}

// MarshalV1 encodes the authority as a format v1 secret, with the key in
// PKCS#8. When the upstream roots hold more than the root (the awssecret
// layout), they are kept in the x_upstream_bundle field, which only
// [ParseCache] reads.
func (a *Authority) MarshalV1() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(a.Key)
	if err != nil {
		return nil, fmt.Errorf("unable to encode the private key: %w", err)
	}
	var chain []byte
	for _, c := range a.Chain {
		chain = append(chain, encodeCertificate(c)...)
	}
	return json.Marshal(v1{
		Format:         FormatV1,
		Cert:           string(encodeCertificate(a.Cert)),
		Key:            string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		Chain:          string(chain),
		Root:           string(encodeCertificate(a.Root)),
		UpstreamBundle: a.extraBundle(),
	})
}

func (a *Authority) extraBundle() string {
	roots := a.UpstreamRoots()
	if len(roots) == 1 && roots[0].Equal(a.Root) {
		return ""
	}
	var out []byte
	for _, c := range roots {
		out = append(out, encodeCertificate(c)...)
	}
	return string(out)
}

func encodeCertificate(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

// parseOneCertificate parses a field that must hold exactly one certificate.
func parseOneCertificate(field, s string) (*x509.Certificate, error) {
	certs, err := parseCertificates(s)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	if len(certs) != 1 {
		return nil, fmt.Errorf("%s: want exactly one certificate, found %d", field, len(certs))
	}
	return certs[0], nil
}

// parseCertificates parses every CERTIFICATE block of s. Anything else in s
// is an error, as is a PEM document with trailing garbage.
func parseCertificates(s string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := []byte(s)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("unexpected PEM block %q", block.Type)
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("unable to parse certificate: %w", err)
		}
		certs = append(certs, c)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("unexpected data after the PEM blocks")
	}
	return certs, nil
}

// decodeOneBlock returns the only PEM block of s.
func decodeOneBlock(s string) (*pem.Block, error) {
	block, rest := pem.Decode([]byte(s))
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("want exactly one PEM block")
	}
	return block, nil
}

// parsePKCS8Key parses a PKCS#8 PEM private key, as format v1 requires.
func parsePKCS8Key(s string) (crypto.Signer, error) {
	block, err := decodeOneBlock(s)
	if err != nil {
		return nil, err
	}
	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("want a PKCS#8 \"PRIVATE KEY\" PEM block, found %q", block.Type)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse PKCS#8 private key: %w", err)
	}
	return asSigner(k)
}

// parseAnyKey parses a PEM private key in any of the encodings SPIRE's
// pemutil accepts: PKCS#8, SEC 1 (EC) or PKCS#1 (RSA).
func parseAnyKey(s string) (crypto.Signer, error) {
	block, err := decodeOneBlock(s)
	if err != nil {
		return nil, err
	}
	switch block.Type {
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("unable to parse PKCS#8 private key: %w", err)
		}
		return asSigner(k)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unexpected PEM block %q", block.Type)
	}
}

// asSigner accepts the key types SPIRE supports for an upstream CA: ECDSA and
// RSA.
func asSigner(k any) (crypto.Signer, error) {
	switch k := k.(type) {
	case *ecdsa.PrivateKey:
		return k, nil
	case *rsa.PrivateKey:
		return k, nil
	default:
		return nil, fmt.Errorf("unsupported private key type %T", k)
	}
}

// keyMatches checks that key is the private key of cert.
func keyMatches(key crypto.Signer, cert *x509.Certificate) error {
	pub, ok := key.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(cert.PublicKey) {
		return errors.New("certificate and private key do not match")
	}
	return nil
}
