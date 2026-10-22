// Package intermediateca reads and writes the "intermediate-ca/v1" secret
// format: a JSON document holding an intermediate CA's certificate, its
// private key, the certificates between it and a trust anchor, and the trust
// anchor. docs/secret-format.md is the specification, and the schema is
// intermediateca/v1/secret.proto.
//
// [Decode] is what a reader calls: it refuses anything that is not a coherent,
// currently valid intermediate CA and its key, and returns it parsed. [Encode]
// is what a writer calls. The errors [Decode] returns wrap one of the
// sentinels ([ErrInvalid], [ErrKeyMismatch], [ErrNotCA], [ErrChain],
// [ErrExpired]), and none of them contains key material.
package intermediateca

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"

	intermediatecav1 "github.com/bpalermo/spire-upstream-secretsmanager/intermediateca/v1"
)

// Format is the value of the "format" field of this version of the format.
const Format = "intermediate-ca/v1"

// The reasons [Decode] refuses a document. An error it returns satisfies
// errors.Is for exactly one of them.
var (
	// ErrInvalid: the document does not match the schema (it is not JSON, a
	// field is missing, has the wrong prefix or is too long, the format is
	// unknown) or a PEM block or key in it cannot be parsed.
	ErrInvalid = errors.New("intermediateca: invalid secret")
	// ErrKeyMismatch: the key is not the private key of the certificate.
	ErrKeyMismatch = errors.New("intermediateca: key does not match certificate")
	// ErrNotCA: the certificate is not a CA certificate allowed to sign other
	// certificates.
	ErrNotCA = errors.New("intermediateca: certificate is not a CA")
	// ErrChain: the certificate does not verify to the root through the chain.
	ErrChain = errors.New("intermediateca: certificate does not chain to root")
	// ErrExpired: the certificate, or one it chains through, is not valid at
	// the time of the check: expired or not yet valid.
	ErrExpired = errors.New("intermediateca: certificate is not valid at this time")
)

// Bundle is a decoded intermediate CA.
type Bundle struct {
	// Cert is the intermediate CA's certificate.
	Cert *x509.Certificate
	// Key is Cert's private key.
	Key crypto.Signer
	// Chain holds the certificates between Cert and Root, possibly none.
	Chain []*x509.Certificate
	// Root is the trust anchor.
	Root *x509.Certificate
	// Raw is the document as decoded, or as [Encode] built it.
	Raw *intermediatecav1.Secret
}

var (
	validatorOnce sync.Once
	validator     protovalidate.Validator
	validatorErr  error
)

// validate checks msg against the rules in secret.proto.
func validate(msg *intermediatecav1.Secret) error {
	validatorOnce.Do(func() { validator, validatorErr = protovalidate.New() })
	if validatorErr != nil {
		return fmt.Errorf("intermediateca: building the validator: %w", validatorErr)
	}
	err := validator.Validate(msg)
	if err == nil {
		return nil
	}
	var verr *protovalidate.ValidationError
	if !errors.As(err, &verr) {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	// Only where each violation is and which rule it broke: a violation's
	// value could be key material.
	reasons := make([]string, 0, len(verr.Violations))
	for _, v := range verr.Violations {
		reasons = append(reasons, fmt.Sprintf("%s (%s)", protovalidate.FieldPathString(v.Proto.GetField()), v.Proto.GetRuleId()))
	}
	return fmt.Errorf("%w: %s", ErrInvalid, strings.Join(reasons, ", "))
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// Decode parses and verifies a secret, as of the current time. See [DecodeAt].
func Decode(data []byte) (*Bundle, error) {
	return DecodeAt(data, time.Now())
}

// DecodeAt parses and verifies a secret as of at. It checks, in this order:
//
//  1. The JSON is a Secret (unknown fields are ignored) that satisfies the
//     rules of secret.proto: [ErrInvalid].
//  2. cert and root hold exactly one PEM certificate each, chain any number,
//     and key one PKCS#8 private key: [ErrInvalid].
//  3. The key is the private key of the certificate: [ErrKeyMismatch].
//  4. The certificate is a CA, and, if it has a key usage, may sign
//     certificates: [ErrNotCA].
//  5. The certificate verifies to the root through the chain at the time
//     given: [ErrExpired] if a certificate is not valid then, [ErrChain] for
//     any other reason.
func DecodeAt(data []byte, at time.Time) (*Bundle, error) {
	msg := &intermediatecav1.Secret{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(data, msg); err != nil {
		// protojson's message can quote part of the input; the input holds a
		// private key.
		return nil, invalid("not a JSON secret document")
	}
	if err := validate(msg); err != nil {
		return nil, err
	}

	b := &Bundle{Raw: msg}
	var err error
	if b.Cert, err = parseOneCertificate("cert", msg.GetCert()); err != nil {
		return nil, err
	}
	if b.Root, err = parseOneCertificate("root", msg.GetRoot()); err != nil {
		return nil, err
	}
	if b.Chain, err = parseCertificates("chain", msg.GetChain()); err != nil {
		return nil, err
	}
	if b.Key, err = parseKey(msg.GetKey()); err != nil {
		return nil, err
	}

	if !publicKeysEqual(b.Key.Public(), b.Cert.PublicKey) {
		return nil, ErrKeyMismatch
	}
	if err := checkCA(b.Cert); err != nil {
		return nil, err
	}
	if err := verifyChain(b, at); err != nil {
		return nil, err
	}
	return b, nil
}

// Encode returns the document for b: the JSON of a Secret, compact, with the
// fields in the order format, cert, key, chain, root and every one present
// (chain is "" without a chain). The same bundle always gives the same bytes.
// The key is written as PKCS#8, so it has to be a key crypto/x509 can marshal.
//
// Encode checks the document against the schema, and nothing more: call
// [Decode] on it to know a reader will accept it.
func Encode(b *Bundle) ([]byte, error) {
	if b == nil || b.Cert == nil || b.Key == nil || b.Root == nil {
		return nil, invalid("a bundle needs a certificate, a key and a root")
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(b.Key)
	if err != nil {
		return nil, fmt.Errorf("intermediateca: marshaling the key as PKCS#8: %w", err)
	}
	msg := &intermediatecav1.Secret{
		Format: Format,
		Cert:   certificatePEM(b.Cert),
		Key:    string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})),
		Root:   certificatePEM(b.Root),
	}
	var chain strings.Builder
	for _, c := range b.Chain {
		chain.WriteString(certificatePEM(c))
	}
	msg.Chain = chain.String()
	if err := validate(msg); err != nil {
		return nil, err
	}

	// protojson adds a random amount of white space to its output so that no
	// one depends on it; compacting removes it again.
	raw, err := protojson.MarshalOptions{EmitUnpopulated: true}.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("intermediateca: marshaling the secret: %w", err)
	}
	var out bytes.Buffer
	if err := json.Compact(&out, raw); err != nil {
		return nil, fmt.Errorf("intermediateca: compacting the secret: %w", err)
	}
	return out.Bytes(), nil
}

// RootSHA256 returns the SHA-256 of the DER encoding of the bundle's root
// certificate: the value to pin a trust anchor by. It is the zero value
// without a root.
func RootSHA256(b *Bundle) [32]byte {
	if b == nil || b.Root == nil {
		return [32]byte{}
	}
	return sha256.Sum256(b.Root.Raw)
}

// RootSHA256Hex is [RootSHA256] as 64 lower-case hexadecimal digits.
func RootSHA256Hex(b *Bundle) string {
	sum := RootSHA256(b)
	return hex.EncodeToString(sum[:])
}

func certificatePEM(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

// pemBlocks splits s into PEM blocks of the given type, refusing anything
// else: other block types, headers, and text before, between or after.
func pemBlocks(field, typ, s string) ([][]byte, error) {
	var blocks [][]byte
	rest := []byte(s)
	for {
		rest = bytes.TrimLeft(rest, " \t\r\n")
		if len(rest) == 0 {
			return blocks, nil
		}
		if !bytes.HasPrefix(rest, []byte("-----BEGIN ")) {
			return nil, invalid("%s: text that is not a PEM block", field)
		}
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, invalid("%s: malformed PEM block", field)
		}
		if block.Type != typ {
			return nil, invalid("%s: a PEM %q block, want %q", field, block.Type, typ)
		}
		if len(block.Headers) != 0 {
			return nil, invalid("%s: PEM headers are not allowed", field)
		}
		blocks = append(blocks, block.Bytes)
	}
}

func parseCertificates(field, s string) ([]*x509.Certificate, error) {
	blocks, err := pemBlocks(field, "CERTIFICATE", s)
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	for _, der := range blocks {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, invalid("%s: not an X.509 certificate", field)
		}
		certs = append(certs, c)
	}
	return certs, nil
}

func parseOneCertificate(field, s string) (*x509.Certificate, error) {
	certs, err := parseCertificates(field, s)
	if err != nil {
		return nil, err
	}
	if len(certs) != 1 {
		return nil, invalid("%s: %d certificates, want exactly one", field, len(certs))
	}
	return certs[0], nil
}

func parseKey(s string) (crypto.Signer, error) {
	blocks, err := pemBlocks("key", "PRIVATE KEY", s)
	if err != nil {
		return nil, err
	}
	if len(blocks) != 1 {
		return nil, invalid("key: %d private keys, want exactly one", len(blocks))
	}
	// The error of ParsePKCS8PrivateKey says what is wrong with the key's
	// encoding and not the key; it is still left out, as a precaution.
	parsed, err := x509.ParsePKCS8PrivateKey(blocks[0])
	if err != nil {
		return nil, invalid("key: not a PKCS#8 private key")
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, invalid("key: a private key that cannot sign")
	}
	return signer, nil
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	e, ok := a.(equaler)
	return ok && e.Equal(b)
}

// checkCA requires BasicConstraints with CA:TRUE and, when the certificate has
// a key usage, certSign in it.
func checkCA(c *x509.Certificate) error {
	if !c.BasicConstraintsValid || !c.IsCA {
		return fmt.Errorf("%w: no basic constraints with CA:TRUE", ErrNotCA)
	}
	if c.KeyUsage != 0 && c.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("%w: its key usage does not include certSign", ErrNotCA)
	}
	return nil
}

func verifyChain(b *Bundle, at time.Time) error {
	roots := x509.NewCertPool()
	roots.AddCert(b.Root)
	intermediates := x509.NewCertPool()
	for _, c := range b.Chain {
		intermediates.AddCert(c)
	}
	_, err := b.Cert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   at,
		// The certificate is a CA's: it has no extended key usage to check.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err == nil {
		return nil
	}
	var invalidCert x509.CertificateInvalidError
	if errors.As(err, &invalidCert) && invalidCert.Reason == x509.Expired {
		return fmt.Errorf("%w: at %s", ErrExpired, at.UTC().Format(time.RFC3339))
	}
	return fmt.Errorf("%w: %v", ErrChain, err)
}
