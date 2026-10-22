// Command gentestdata writes the golden files under intermediateca/testdata/:
// documents that every implementation of the format has to accept (valid/) or
// refuse (invalid/), and manifest.json, which says what to expect of each.
// Run it with
//
//	bazel run //internal/gentestdata
//
// The keys, names, serial numbers and validity periods are fixed. An ECDSA
// signature is not deterministic, so running it again changes the signatures
// in the files; the files are therefore committed, and regenerated only when
// a case is added or changed.
package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bpalermo/spire-upstream-secretsmanager/internal/fixedpki"
)

// decodeAt is the time every file is decoded at: all the valid ones are valid
// then, and for a long time after.
var decodeAt = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

// document is a secret as JSON, with fields that can be left out.
type document struct {
	Format  *string `json:"format,omitempty"`
	Cert    *string `json:"cert,omitempty"`
	Key     *string `json:"key,omitempty"`
	Chain   *string `json:"chain,omitempty"`
	Root    *string `json:"root,omitempty"`
	Comment *string `json:"comment,omitempty"`
	Extra   *int    `json:"x-extra,omitempty"`
}

func str(s string) *string { return &s }

func certPEM(certs ...*x509.Certificate) string {
	var b strings.Builder
	for _, c := range certs {
		b.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}
	return b.String()
}

func keyPEM(k *ecdsa.PrivateKey) string {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	check(err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func sec1PEM(label string, k *ecdsa.PrivateKey) string {
	der, err := x509.MarshalECPrivateKey(k)
	check(err)
	return string(pem.EncodeToMemory(&pem.Block{Type: label, Bytes: der}))
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "gentestdata:", err)
		os.Exit(1)
	}
}

// file is one golden file: its name, its content, and what is expected of it.
type file struct {
	name    string
	content []byte
	// reason is the category of the error expected, empty for a valid file.
	reason string
	// rootSHA256 is the hex SHA-256 of the root's DER, for a valid file.
	rootSHA256 string
	// why says what is wrong with an invalid file.
	why string
}

func marshal(d document) []byte {
	out, err := json.MarshalIndent(d, "", "  ")
	check(err)
	return append(out, '\n')
}

func main() {
	dir := filepath.Join(os.Getenv("BUILD_WORKSPACE_DIRECTORY"), "intermediateca", "testdata")
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}

	pathLen := func(n int) fixedpki.Options { return fixedpki.Options{MaxPathLen: n, MaxPathLenSet: true} }
	named := func(o fixedpki.Options, cn string) fixedpki.Options { o.CommonName = cn; return o }

	root := fixedpki.New(named(pathLen(3), "Example Root CA"), fixedpki.FixedKey("root"), nil)
	otherRoot := fixedpki.New(named(pathLen(3), "Example Other Root CA"), fixedpki.FixedKey("other-root"), nil)
	mid1 := fixedpki.New(named(pathLen(2), "Example Issuing CA 1"), fixedpki.FixedKey("mid1"), root)
	mid2 := fixedpki.New(named(pathLen(1), "Example Issuing CA 2"), fixedpki.FixedKey("mid2"), mid1)
	leafKey := fixedpki.FixedKey("intermediate")
	viaChain := fixedpki.New(named(pathLen(0), "Example Intermediate CA"), leafKey, mid2)
	direct := fixedpki.New(named(pathLen(0), "Example Intermediate CA (direct)"), fixedpki.FixedKey("direct"), root)

	rootSum := sha256.Sum256(root.Cert.Raw)
	rootHex := hex.EncodeToString(rootSum[:])

	secret := func(n *fixedpki.Node, chain string, r *fixedpki.Node) document {
		return document{
			Format: str("intermediate-ca/v1"),
			Cert:   str(certPEM(n.Cert)),
			Key:    str(keyPEM(n.Key)),
			Chain:  str(chain),
			Root:   str(certPEM(r.Cert)),
		}
	}
	with := func(d document, edit func(*document)) []byte { edit(&d); return marshal(d) }
	// issued creates a certificate under root, with the options given, and the
	// secret holding it with its key.
	issued := func(label string, o fixedpki.Options) document {
		n := fixedpki.New(named(o, "Example Intermediate CA ("+label+")"), fixedpki.FixedKey(label), root)
		return secret(n, "", root)
	}

	validDirect := secret(direct, "", root)
	files := []file{
		{name: "valid/direct.json", content: marshal(validDirect), rootSHA256: rootHex},
		{name: "valid/chain.json", content: marshal(secret(viaChain, certPEM(mid2.Cert, mid1.Cert), root)), rootSHA256: rootHex},
		{name: "valid/chain-root-first.json", content: marshal(secret(viaChain, certPEM(mid1.Cert, mid2.Cert), root)), rootSHA256: rootHex},
		{name: "valid/no-key-usage.json", content: marshal(issued("no-key-usage", fixedpki.Options{NoKeyUsage: true})), rootSHA256: rootHex},
		{name: "valid/unknown-fields.json", content: with(validDirect, func(d *document) { d.Comment = str("ignored"); d.Extra = new(int) }), rootSHA256: rootHex},

		{name: "invalid/not-json.json", content: []byte("this is not JSON\n"), reason: "invalid", why: "not a JSON document"},
		{name: "invalid/unknown-format.json", content: with(validDirect, func(d *document) { d.Format = str("intermediate-ca/v2") }), reason: "invalid", why: "unknown format"},
		{name: "invalid/missing-format.json", content: with(validDirect, func(d *document) { d.Format = nil }), reason: "invalid", why: "no format"},
		{name: "invalid/missing-cert.json", content: with(validDirect, func(d *document) { d.Cert = nil }), reason: "invalid", why: "no cert"},
		{name: "invalid/missing-key.json", content: with(validDirect, func(d *document) { d.Key = nil }), reason: "invalid", why: "no key"},
		{name: "invalid/missing-root.json", content: with(validDirect, func(d *document) { d.Root = nil }), reason: "invalid", why: "no root"},
		{name: "invalid/cert-bad-prefix.json", content: with(validDirect, func(d *document) { d.Cert = str("subject: example\n" + *d.Cert) }), reason: "invalid", why: "cert does not start with a PEM certificate"},
		{name: "invalid/root-bad-prefix.json", content: with(validDirect, func(d *document) { d.Root = str("root") }), reason: "invalid", why: "root does not start with a PEM certificate"},
		{name: "invalid/key-bad-prefix.json", content: with(validDirect, func(d *document) { d.Key = str(sec1PEM("EC PRIVATE KEY", direct.Key)) }), reason: "invalid", why: "key is a SEC1 EC PRIVATE KEY, not PKCS#8"},
		{name: "invalid/key-not-pkcs8.json", content: with(validDirect, func(d *document) { d.Key = str(sec1PEM("PRIVATE KEY", direct.Key)) }), reason: "invalid", why: "key is labeled PRIVATE KEY but holds a SEC1 structure, not PKCS#8"},
		{name: "invalid/chain-bad-prefix.json", content: with(validDirect, func(d *document) { d.Chain = str("not a certificate") }), reason: "invalid", why: "chain is neither empty nor a PEM certificate"},
		{name: "invalid/cert-too-large.json", content: with(validDirect, func(d *document) { d.Cert = str(*d.Cert + strings.Repeat("A", 16*1024)) }), reason: "invalid", why: "cert is over 16 KiB"},
		{name: "invalid/chain-too-large.json", content: with(validDirect, func(d *document) { d.Chain = str(certPEM(mid1.Cert) + strings.Repeat("A", 64*1024)) }), reason: "invalid", why: "chain is over 64 KiB"},
		{name: "invalid/two-certs-in-cert.json", content: with(validDirect, func(d *document) { d.Cert = str(certPEM(direct.Cert, mid1.Cert)) }), reason: "invalid", why: "cert holds two certificates"},
		{name: "invalid/two-certs-in-root.json", content: with(validDirect, func(d *document) { d.Root = str(certPEM(root.Cert, otherRoot.Cert)) }), reason: "invalid", why: "root holds two certificates"},
		{name: "invalid/trailing-text-in-cert.json", content: with(validDirect, func(d *document) { d.Cert = str(*d.Cert + "trailing text\n") }), reason: "invalid", why: "text after the certificate in cert"},
		{name: "invalid/key-mismatch.json", content: with(validDirect, func(d *document) { d.Key = str(keyPEM(fixedpki.FixedKey("someone-else"))) }), reason: "key_mismatch", why: "key is not cert's private key"},
		{name: "invalid/not-ca.json", content: marshal(issued("not-ca", fixedpki.Options{NotCA: true})), reason: "not_ca", why: "cert has no CA:TRUE basic constraint"},
		{name: "invalid/no-cert-sign.json", content: marshal(issued("no-cert-sign", fixedpki.Options{KeyUsage: x509.KeyUsageDigitalSignature})), reason: "not_ca", why: "cert has a key usage without certSign"},
		{name: "invalid/chain-missing.json", content: marshal(secret(viaChain, "", root)), reason: "chain", why: "cert is issued by an intermediate that is not in chain"},
		{name: "invalid/wrong-root.json", content: marshal(secret(direct, "", otherRoot)), reason: "chain", why: "cert does not verify to root"},
		{name: "invalid/expired.json", content: marshal(issued("expired", fixedpki.Options{NotAfter: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)})), reason: "expired", why: "cert expired before the decode time"},
		{name: "invalid/not-yet-valid.json", content: marshal(issued("not-yet-valid", fixedpki.Options{NotBefore: time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2300, 1, 1, 0, 0, 0, 0, time.UTC)})), reason: "expired", why: "cert is not valid until after the decode time"},
	}

	type validEntry struct {
		File       string `json:"file"`
		RootSHA256 string `json:"root_sha256"`
	}
	type invalidEntry struct {
		File   string `json:"file"`
		Error  string `json:"error"`
		Reason string `json:"reason"`
	}
	manifest := struct {
		Comment  string         `json:"comment"`
		DecodeAt string         `json:"decode_at"`
		Valid    []validEntry   `json:"valid"`
		Invalid  []invalidEntry `json:"invalid"`
	}{
		Comment:  "Decode each file at decode_at. A valid file decodes, and its root certificate's DER hashes to root_sha256. An invalid file is refused for the category in error: invalid (schema, JSON or PEM/PKCS#8 parsing), key_mismatch, not_ca, chain, or expired.",
		DecodeAt: decodeAt.Format(time.RFC3339),
	}
	for _, f := range files {
		check(os.MkdirAll(filepath.Dir(filepath.Join(dir, f.name)), 0o755))
		check(os.WriteFile(filepath.Join(dir, f.name), f.content, 0o644))
		if f.reason == "" {
			manifest.Valid = append(manifest.Valid, validEntry{File: f.name, RootSHA256: f.rootSHA256})
		} else {
			manifest.Invalid = append(manifest.Invalid, invalidEntry{File: f.name, Error: f.reason, Reason: f.why})
		}
	}
	out, err := json.MarshalIndent(manifest, "", "  ")
	check(err)
	check(os.WriteFile(filepath.Join(dir, "manifest.json"), append(out, '\n'), 0o644))
	fmt.Printf("wrote %d files and manifest.json to %s\n", len(files), dir)
}
