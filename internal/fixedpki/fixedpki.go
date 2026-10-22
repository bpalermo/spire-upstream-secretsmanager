// Package fixedpki builds small certificate hierarchies for tests and for the
// generator of the golden files (internal/gentestdata). Nothing here is for
// production: the keys of [FixedKey] are derived from public labels.
package fixedpki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

// Node is a certificate and its private key.
type Node struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// Options describes a certificate. The zero value is a CA certificate with
// no path length limit, valid from [NotBefore] to [NotAfter], whose key usage
// is certSign and cRLSign.
type Options struct {
	// CommonName is the subject's; it is also what makes the serial number
	// stable when Serial is zero.
	CommonName string
	// Serial is the serial number; zero derives one from CommonName.
	Serial int64
	// NotBefore and NotAfter default to the package's values.
	NotBefore, NotAfter time.Time
	// NotCA makes the certificate an end-entity one: no CA:TRUE.
	NotCA bool
	// NoKeyUsage leaves the key usage extension out.
	NoKeyUsage bool
	// KeyUsage replaces the default certSign|cRLSign when non-zero.
	KeyUsage x509.KeyUsage
	// MaxPathLen limits the CAs below this one, when MaxPathLenSet; without
	// it there is no limit.
	MaxPathLen    int
	MaxPathLenSet bool
}

var (
	// NotBefore is the start of the validity of certificates by default.
	NotBefore = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	// NotAfter is the end of it: far enough that tests do not rot.
	NotAfter = time.Date(2124, 1, 1, 0, 0, 0, 0, time.UTC)
)

// FixedKey returns the P-256 key derived from label: the same on every call
// and every machine, so generated files can be stable.
func FixedKey(label string) *ecdsa.PrivateKey {
	// The label prefix is that of the repository the golden files were first
	// generated in; changing it would change every key in them.
	sum := sha256.Sum256([]byte("intermediate-ca-format test key: " + label))
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), sum[:])
	if err != nil {
		panic("fixedpki: " + err.Error())
	}
	return key
}

// RandomKey returns a new P-256 key.
func RandomKey() *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic("fixedpki: " + err.Error())
	}
	return key
}

// Issue creates the certificate for pub described by o, signed by parent
// with signer; a nil parent makes it self-signed (and signer then signs with
// pub's own key).
func Issue(o Options, pub crypto.PublicKey, parent *x509.Certificate, signer crypto.Signer) (*x509.Certificate, error) {
	serial := o.Serial
	if serial == 0 {
		sum := sha256.Sum256([]byte(o.CommonName))
		serial = int64(sum[0])<<24 | int64(sum[1])<<16 | int64(sum[2])<<8 | int64(sum[3]) + 1
	}
	notBefore, notAfter := o.NotBefore, o.NotAfter
	if notBefore.IsZero() {
		notBefore = NotBefore
	}
	if notAfter.IsZero() {
		notAfter = NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: o.CommonName, Organization: []string{"Example"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		IsCA:                  !o.NotCA,
	}
	if o.MaxPathLenSet {
		tmpl.MaxPathLen = o.MaxPathLen
		tmpl.MaxPathLenZero = o.MaxPathLen == 0
	} else {
		tmpl.MaxPathLen = -1
	}
	if !o.NoKeyUsage {
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		if o.KeyUsage != 0 {
			tmpl.KeyUsage = o.KeyUsage
		}
	}
	if parent == nil {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// New issues a certificate for key, signed by parent (nil: self-signed), and
// panics on error, which only a bad Options value causes.
func New(o Options, key *ecdsa.PrivateKey, parent *Node) *Node {
	var (
		cert *x509.Certificate
		err  error
	)
	if parent == nil {
		cert, err = Issue(o, &key.PublicKey, nil, key)
	} else {
		cert, err = Issue(o, &key.PublicKey, parent.Cert, parent.Key)
	}
	if err != nil {
		panic("fixedpki: " + err.Error())
	}
	return &Node{Cert: cert, Key: key}
}
