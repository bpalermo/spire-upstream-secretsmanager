// Package secret reads the intermediate CA that the plugin gets from AWS
// Secrets Manager, in either of the two layouts it supports:
//
//   - one secret in the intermediate-ca/v1 format (docs/secret-format.md),
//     which [ParseV1] decodes with the format's reader, package
//     intermediateca;
//   - the layout of SPIRE's built-in awssecret UpstreamAuthority: up to three
//     secrets whose SecretString is PEM (the certificate file, the key file
//     and the bundle file), which [ParseAWSSecretLayout] reads and then
//     checks with the same reader.
//
// Either way the result is an [Authority]: an [intermediateca.Bundle] the
// shared reader accepted (the key matches the certificate, the certificate is
// a CA and verifies to the root through the chain) and the upstream roots.
// [Authority.Validate] adds the plugin's own checks before every use: the
// root is a pinned one, enough of the certificate's lifetime is left, and it
// can sign a SPIRE CA for the trust domain.
package secret

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/bpalermo/spire-upstream-secretsmanager/intermediateca"
)

// Authority is an intermediate CA: the certificate the plugin signs with,
// its private key, the certificates between it and the root, and the root
// (the embedded Bundle), with the upstream roots SPIRE receives.
type Authority struct {
	intermediateca.Bundle
	// Roots are the upstream roots SPIRE receives. With the awssecret layout
	// it is the whole bundle, as SPIRE's awssecret and disk plugins publish
	// it, which includes Root. Nil means [Root] alone.
	Roots []*x509.Certificate
}

// ParseV1 decodes a secret in the intermediate-ca/v1 format as of at, with
// [intermediateca.DecodeAt]: unknown fields are ignored, and anything that is
// not a coherent intermediate CA valid at that time is refused, with an error
// that wraps one of the intermediateca sentinels.
func ParseV1(data []byte, at time.Time) (*Authority, error) {
	b, err := intermediateca.DecodeAt(data, at)
	if err != nil {
		return nil, err
	}
	return FromBundle(b, nil, at)
}

// ParseAWSSecretLayout builds an Authority from the three PEM documents of
// SPIRE's awssecret layout, read exactly as awssecret reads them: certPEM
// holds the CA certificate first, optionally followed by the intermediates
// up to the root; keyPEM holds its private key (PKCS#8, SEC 1 or PKCS#1);
// bundlePEM holds the trust bundle. bundlePEM may be empty only if certPEM is
// exactly one self-signed certificate, which is then its own root.
//
// The root is the certificate of the bundle that the certificate verifies to
// at time at; the whole bundle is kept as the upstream roots. The result is
// written in the intermediate-ca/v1 format and decoded again, so that it
// passes exactly the checks a format v1 secret does.
func ParseAWSSecretLayout(certPEM, keyPEM, bundlePEM string, at time.Time) (*Authority, error) {
	certs, err := ParseCertificates(certPEM)
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
	b := &intermediateca.Bundle{Cert: certs[0], Key: key, Chain: certs[1:]}
	roots, err := awsSecretRoots(certs, bundlePEM)
	if err != nil {
		return nil, err
	}
	if roots == nil {
		b.Root = certs[0]
	} else if b.Root, err = anchorOf(b.Cert, b.Chain, roots, at); err != nil {
		return nil, err
	}
	// The awssecret certificate file may end with the root, which the
	// format's chain should not hold.
	b.Chain = slices.DeleteFunc(b.Chain, b.Root.Equal)
	data, err := intermediateca.Encode(b)
	if err != nil {
		return nil, err
	}
	decoded, err := intermediateca.DecodeAt(data, at)
	if err != nil {
		return nil, err
	}
	return FromBundle(decoded, roots, at)
}

// awsSecretRoots parses the awssecret bundle file: nil roots, with no error,
// for a CA without one, which is then its own root.
func awsSecretRoots(certs []*x509.Certificate, bundlePEM string) ([]*x509.Certificate, error) {
	if bundlePEM == "" {
		// As awssecret: with no bundle, only a self-signed CA is supported,
		// and it is its own trust anchor.
		// awssecret only counts the certificates; a lone certificate that
		// is not self-signed would then be trusted as its own root, so
		// self-signature is checked as well.
		if len(certs) != 1 || !isSelfSigned(certs[0]) {
			return nil, errors.New("with no bundle_file_arn configured only self-signed CAs are supported")
		}
		return nil, nil
	}
	roots, err := ParseCertificates(bundlePEM)
	if err != nil {
		return nil, fmt.Errorf("bundle_file_arn: %w", err)
	}
	if len(roots) == 0 {
		return nil, errors.New("bundle_file_arn: no certificate found")
	}
	return roots, nil
}

// FromBundle returns the Authority of a bundle that [intermediateca.DecodeAt]
// accepted at time at, with roots as its upstream roots (nil: the bundle's
// root alone). It refuses a key type SPIRE does not support for an upstream
// CA, and upstream roots without the bundle's root; and it orders the chain
// from the certificate that signed Cert towards the root, the order SPIRE
// receives it in, since the format puts the chain in no required order.
func FromBundle(b *intermediateca.Bundle, roots []*x509.Certificate, at time.Time) (*Authority, error) {
	if _, err := asSigner(b.Key); err != nil {
		return nil, fmt.Errorf("key: %w", err)
	}
	a := &Authority{Bundle: *b, Roots: roots}
	pool := x509.NewCertPool()
	pool.AddCert(a.Root)
	chains, err := a.Cert.Verify(verifyOptions(a.Chain, pool, at))
	if err != nil {
		return nil, fmt.Errorf("certificate does not verify to the root through the chain: %w", err)
	}
	// The path is [Cert, the chain in order..., Root], and [Cert] when Cert
	// is the root.
	a.Chain = nil
	if path := chains[0]; len(path) > 2 {
		a.Chain = path[1 : len(path)-1]
	}
	if !slices.ContainsFunc(a.UpstreamRoots(), a.Root.Equal) {
		return nil, errors.New("the upstream roots do not include the root")
	}
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
	chains, err := cert.Verify(verifyOptions(chain, roots, at))
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
	RootPins [][32]byte
	// TrustDomain is the trust domain the intermediate must be able to sign
	// a SPIRE CA for. Required.
	TrustDomain spiffeid.TrustDomain
}

// Validate checks, before every use, what the format leaves to the plugin:
// the root is pinned, the certificate still verifies to the root through the
// chain at opts.Now, at least opts.MinRemaining of its lifetime is left, and
// it can actually sign a CA for the trust domain whose X509-SVIDs verify to
// the root (path length and name constraints included), which SPIRE checks
// for every CA it receives. The format's own checks were made when the
// Authority was read.
func (a *Authority) Validate(opts ValidateOptions) error {
	if a == nil || a.Cert == nil || a.Key == nil || a.Root == nil {
		return errors.New("incomplete intermediate CA")
	}
	if err := a.checkPinned(opts.RootPins); err != nil {
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

// checkPinned checks that the root's SHA-256 is one of pins.
func (a *Authority) checkPinned(pins [][32]byte) error {
	if len(pins) == 0 {
		return errors.New("no root_sha256 configured")
	}
	if slices.Contains(pins, intermediateca.RootSHA256(&a.Bundle)) {
		return nil
	}
	return fmt.Errorf("root certificate SHA-256 %s is not one of the configured root_sha256", a.RootSHA256Hex())
}

// RootSHA256Hex is the SHA-256 of the root certificate's DER, the value
// root_sha256 pins, in hexadecimal.
func (a *Authority) RootSHA256Hex() string {
	return intermediateca.RootSHA256Hex(&a.Bundle)
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

// ExtraRoots are the upstream roots when they are more than the root (the
// awssecret layout's bundle), and nil when they are the root alone.
func (a *Authority) ExtraRoots() []*x509.Certificate {
	roots := a.UpstreamRoots()
	if len(roots) == 1 && roots[0].Equal(a.Root) {
		return nil
	}
	return roots
}

// CertificatePEM encodes a certificate as one PEM "CERTIFICATE" block.
func CertificatePEM(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

// ParseCertificates parses every CERTIFICATE block of s. Anything else in s
// is an error, as is a PEM document with trailing garbage.
func ParseCertificates(s string) ([]*x509.Certificate, error) {
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

// parseAnyKey parses a PEM private key in any of the encodings SPIRE's
// pemutil accepts: PKCS#8, SEC 1 (EC) or PKCS#1 (RSA). The parsers' errors,
// which describe the key's encoding, are left out as a precaution.
func parseAnyKey(s string) (crypto.Signer, error) {
	block, rest := pem.Decode([]byte(s))
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("want exactly one PEM block")
	}
	switch block.Type {
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.New("unable to parse PKCS#8 private key")
		}
		return asSigner(k)
	case "EC PRIVATE KEY":
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.New("unable to parse SEC 1 private key")
		}
		return k, nil
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.New("unable to parse PKCS#1 private key")
		}
		return k, nil
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
