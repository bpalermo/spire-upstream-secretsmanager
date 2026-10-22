package intermediateca_test

import (
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bpalermo/spire-upstream-secretsmanager/intermediateca"
	"github.com/bpalermo/spire-upstream-secretsmanager/internal/fixedpki"
)

// The files under testdata/ and what to expect of them: see
// internal/gentestdata.
type manifest struct {
	DecodeAt string `json:"decode_at"`
	Valid    []struct {
		File       string `json:"file"`
		RootSHA256 string `json:"root_sha256"`
	} `json:"valid"`
	Invalid []struct {
		File  string `json:"file"`
		Error string `json:"error"`
	} `json:"invalid"`
}

var sentinels = map[string]error{
	"invalid":      intermediateca.ErrInvalid,
	"key_mismatch": intermediateca.ErrKeyMismatch,
	"not_ca":       intermediateca.ErrNotCA,
	"chain":        intermediateca.ErrChain,
	"expired":      intermediateca.ErrExpired,
}

func loadManifest(t *testing.T) (manifest, time.Time) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	at, err := time.Parse(time.RFC3339, m.DecodeAt)
	if err != nil {
		t.Fatal(err)
	}
	return m, at
}

func TestGoldenValid(t *testing.T) {
	m, at := loadManifest(t)
	if len(m.Valid) == 0 {
		t.Fatal("the manifest lists no valid file")
	}
	for _, v := range m.Valid {
		t.Run(v.File, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", v.File))
			if err != nil {
				t.Fatal(err)
			}
			b, err := intermediateca.DecodeAt(data, at)
			if err != nil {
				t.Fatalf("DecodeAt: %v", err)
			}
			if got := intermediateca.RootSHA256Hex(b); got != v.RootSHA256 {
				t.Errorf("root SHA-256 = %s, want %s", got, v.RootSHA256)
			}
			if b.Cert == nil || b.Key == nil || b.Root == nil || b.Raw == nil {
				t.Errorf("incomplete bundle: %+v", b)
			}
		})
	}
}

func TestGoldenInvalid(t *testing.T) {
	m, at := loadManifest(t)
	// Every category is covered by a file.
	covered := map[string]bool{}
	for _, inv := range m.Invalid {
		covered[inv.Error] = true
	}
	for name := range sentinels {
		if !covered[name] {
			t.Errorf("no invalid file for %q", name)
		}
	}
	for _, inv := range m.Invalid {
		t.Run(inv.File, func(t *testing.T) {
			want, ok := sentinels[inv.Error]
			if !ok {
				t.Fatalf("unknown error category %q", inv.Error)
			}
			data, err := os.ReadFile(filepath.Join("testdata", inv.File))
			if err != nil {
				t.Fatal(err)
			}
			_, err = intermediateca.DecodeAt(data, at)
			if !errors.Is(err, want) {
				t.Fatalf("DecodeAt error = %v, want %v", err, want)
			}
			// Exactly one category.
			for name, other := range sentinels {
				if other != want && errors.Is(err, other) {
					t.Errorf("error is also %s", name)
				}
			}
			assertNoKeyMaterial(t, data, err)
		})
	}
}

// assertNoKeyMaterial fails if err quotes the key of the document or looks
// like PEM.
func assertNoKeyMaterial(t *testing.T, doc []byte, err error) {
	t.Helper()
	msg := err.Error()
	if strings.Contains(msg, "PRIVATE KEY") || strings.Contains(msg, "-----") {
		t.Errorf("error looks like it contains PEM: %q", msg)
	}
	var d struct {
		Key string `json:"key"`
	}
	if json.Unmarshal(doc, &d) != nil {
		return
	}
	for _, line := range strings.Split(d.Key, "\n") {
		if len(line) > 16 && !strings.HasPrefix(line, "-----") && strings.Contains(msg, line[:16]) {
			t.Errorf("error contains part of the key: %q", msg)
		}
	}
}

func newBundle(chain bool) *intermediateca.Bundle {
	root := fixedpki.New(fixedpki.Options{CommonName: "Example Root", MaxPathLen: 2, MaxPathLenSet: true}, fixedpki.RandomKey(), nil)
	parent := root
	b := &intermediateca.Bundle{Root: root.Cert}
	if chain {
		mid := fixedpki.New(fixedpki.Options{CommonName: "Example Issuing", MaxPathLen: 1, MaxPathLenSet: true}, fixedpki.RandomKey(), root)
		b.Chain = append(b.Chain, mid.Cert)
		parent = mid
	}
	n := fixedpki.New(fixedpki.Options{CommonName: "Example Intermediate", MaxPathLen: 0, MaxPathLenSet: true}, fixedpki.RandomKey(), parent)
	b.Cert, b.Key = n.Cert, n.Key
	return b
}

func TestRoundTrip(t *testing.T) {
	for _, withChain := range []bool{false, true} {
		b := newBundle(withChain)
		data, err := intermediateca.Encode(b)
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		got, err := intermediateca.Decode(data)
		if err != nil {
			t.Fatalf("Decode(Encode()): %v", err)
		}
		if !got.Cert.Equal(b.Cert) || !got.Root.Equal(b.Root) {
			t.Error("certificates changed in the round trip")
		}
		if len(got.Chain) != len(b.Chain) {
			t.Fatalf("chain has %d certificates, want %d", len(got.Chain), len(b.Chain))
		}
		for i := range got.Chain {
			if !got.Chain[i].Equal(b.Chain[i]) {
				t.Errorf("chain[%d] changed", i)
			}
		}
		pub, ok := got.Key.Public().(interface{ Equal(crypto.PublicKey) bool })
		if !ok || !pub.Equal(b.Key.Public()) {
			t.Error("key changed in the round trip")
		}
		if got.Raw.GetFormat() != intermediateca.Format {
			t.Errorf("Raw.Format = %q", got.Raw.GetFormat())
		}
	}
}

func TestEncodeIsDeterministicAndShaped(t *testing.T) {
	b := newBundle(false)
	first, err := intermediateca.Encode(b)
	if err != nil {
		t.Fatal(err)
	}
	for range 20 {
		again, err := intermediateca.Encode(b)
		if err != nil {
			t.Fatal(err)
		}
		if string(again) != string(first) {
			t.Fatal("Encode gave different bytes for the same bundle")
		}
	}
	// Exactly these five fields, in this order, chain present though empty,
	// and no insignificant white space.
	want := `{"format":"intermediate-ca/v1","cert":"-----BEGIN CERTIFICATE-----\n`
	if !strings.HasPrefix(string(first), want) {
		t.Errorf("document starts %.80q, want prefix %q", first, want)
	}
	var fields map[string]string
	if err := json.Unmarshal(first, &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 5 {
		t.Errorf("%d fields, want 5", len(fields))
	}
	if chain, ok := fields["chain"]; !ok || chain != "" {
		t.Errorf("chain = %q, present %v; want present and empty", chain, ok)
	}
	order := []string{`"format"`, `"cert"`, `"key"`, `"chain"`, `"root"`}
	at := -1
	for _, name := range order {
		i := strings.Index(string(first), name+":")
		if i <= at {
			t.Errorf("field %s out of order", name)
		}
		at = i
	}
	if strings.Contains(string(first), "\n") || strings.Contains(string(first), `": `) {
		t.Error("the document has insignificant white space")
	}
}

func TestEncodeRejects(t *testing.T) {
	if _, err := intermediateca.Encode(nil); !errors.Is(err, intermediateca.ErrInvalid) {
		t.Errorf("Encode(nil) = %v, want ErrInvalid", err)
	}
	b := newBundle(false)
	b.Key = nil
	if _, err := intermediateca.Encode(b); !errors.Is(err, intermediateca.ErrInvalid) {
		t.Errorf("Encode without key = %v, want ErrInvalid", err)
	}
	// A key that cannot be written as PKCS#8, such as one inside a KMS.
	b = newBundle(false)
	b.Key = opaqueSigner{b.Key}
	if _, err := intermediateca.Encode(b); err == nil {
		t.Error("Encode accepted a key that cannot be marshaled")
	}
	// A chain just under the schema's limit is fine, one over it is not.
	b = newBundle(false)
	for range 40 {
		b.Chain = append(b.Chain, b.Root)
	}
	if _, err := intermediateca.Encode(b); err != nil {
		t.Errorf("a chain under 64 KiB was refused: %v", err)
	}
	for range 200 {
		b.Chain = append(b.Chain, b.Root)
	}
	if _, err := intermediateca.Encode(b); !errors.Is(err, intermediateca.ErrInvalid) {
		t.Errorf("Encode of an oversize chain = %v, want ErrInvalid", err)
	}
}

// opaqueSigner hides the concrete key type, as a KMS-backed signer does.
type opaqueSigner struct{ crypto.Signer }

func TestDecodeAtUsesTheGivenTime(t *testing.T) {
	b := newBundle(true)
	data, err := intermediateca.Encode(b)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		at   time.Time
		want error
	}{
		{"inside", fixedpki.NotBefore.Add(24 * time.Hour), nil},
		{"before", fixedpki.NotBefore.Add(-24 * time.Hour), intermediateca.ErrExpired},
		{"after", fixedpki.NotAfter.Add(24 * time.Hour), intermediateca.ErrExpired},
	} {
		_, err := intermediateca.DecodeAt(data, c.at)
		if c.want == nil && err != nil || c.want != nil && !errors.Is(err, c.want) {
			t.Errorf("%s: DecodeAt = %v, want %v", c.name, err, c.want)
		}
	}
	// Decode is DecodeAt of now.
	if _, err := intermediateca.Decode(data); err != nil {
		t.Errorf("Decode: %v", err)
	}
}

func TestDecodeChecksKeyAndRoot(t *testing.T) {
	good := newBundle(false)
	other := newBundle(false)

	mutate := func(edit func(b *intermediateca.Bundle)) *intermediateca.Bundle {
		b := *good
		edit(&b)
		return &b
	}
	cases := []struct {
		name string
		b    *intermediateca.Bundle
		want error
	}{
		{"valid", good, nil},
		{"wrong key", mutate(func(b *intermediateca.Bundle) { b.Key = other.Key }), intermediateca.ErrKeyMismatch},
		{"wrong root", mutate(func(b *intermediateca.Bundle) { b.Root = other.Root }), intermediateca.ErrChain},
	}
	for _, c := range cases {
		data, err := intermediateca.Encode(c.b)
		if err != nil {
			t.Fatalf("%s: Encode: %v", c.name, err)
		}
		_, err = intermediateca.Decode(data)
		if c.want == nil && err != nil || c.want != nil && !errors.Is(err, c.want) {
			t.Errorf("%s: Decode = %v, want %v", c.name, err, c.want)
		}
	}
}

func TestUnknownFieldsAreIgnored(t *testing.T) {
	b := newBundle(false)
	data, err := intermediateca.Encode(b)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	fields["comment"] = "ignored"
	fields["nested"] = map[string]any{"a": []int{1, 2}}
	extended, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := intermediateca.Decode(extended); err != nil {
		t.Errorf("a document with unknown fields was refused: %v", err)
	}
}

func TestRootSHA256(t *testing.T) {
	b := newBundle(false)
	want := sha256.Sum256(b.Root.Raw)
	if got := intermediateca.RootSHA256(b); got != want {
		t.Errorf("RootSHA256 = %x, want %x", got, want)
	}
	if got := intermediateca.RootSHA256Hex(b); got != hex.EncodeToString(want[:]) {
		t.Errorf("RootSHA256Hex = %s", got)
	}
	if got := intermediateca.RootSHA256(&intermediateca.Bundle{}); got != [32]byte{} {
		t.Errorf("RootSHA256 without a root = %x, want zeros", got)
	}
	if got := intermediateca.RootSHA256(nil); got != [32]byte{} {
		t.Error("RootSHA256(nil) is not zero")
	}
}

func TestDuplicateKeysAndLineEndings(t *testing.T) {
	b := newBundle(false)
	data, err := intermediateca.Encode(b)
	if err != nil {
		t.Fatal(err)
	}
	dup := strings.Replace(string(data), `{"format"`, `{"format":"intermediate-ca/v1","format"`, 1)
	if _, err := intermediateca.Decode([]byte(dup)); !errors.Is(err, intermediateca.ErrInvalid) {
		t.Errorf("a duplicate key = %v, want ErrInvalid", err)
	}

	// PEM written with CRLF line endings is the same PEM.
	var fields map[string]string
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	for k, v := range fields {
		fields[k] = strings.ReplaceAll(v, "\n", "\r\n")
	}
	fields["format"] = intermediateca.Format
	crlf, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := intermediateca.Decode(crlf); err != nil {
		t.Errorf("CRLF line endings were refused: %v", err)
	}
}
