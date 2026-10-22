package cache_test

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/bpalermo/spire-upstream-secretsmanager/cache"
	"github.com/bpalermo/spire-upstream-secretsmanager/intermediateca"
	"github.com/bpalermo/spire-upstream-secretsmanager/internal/testpki"
	"github.com/bpalermo/spire-upstream-secretsmanager/secret"
)

var td = spiffeid.RequireTrustDomainFromString("example.org")

// vo validates for example.org at now with a's root pinned.
func vo(a *secret.Authority, now time.Time, minRemaining time.Duration) secret.ValidateOptions {
	return secret.ValidateOptions{
		Now:          now,
		MinRemaining: minRemaining,
		RootPins:     [][32]byte{intermediateca.RootSHA256(&a.Bundle)},
		TrustDomain:  td,
	}
}

func authority(t *testing.T, o testpki.Options) *secret.Authority {
	t.Helper()
	a, err := secret.ParseV1([]byte(testpki.New(t, o).V1(t)), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestSaveIsAtomicAndPrivate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sub")
	path := filepath.Join(dir, "intermediate.json")
	a := authority(t, testpki.Options{Middle: 1})

	// An existing file with looser permissions is replaced, not rewritten.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cache.Save(path, a); err != nil {
		t.Fatalf("Save: %v", err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := st.Mode().Perm(); mode != 0o600 {
		t.Fatalf("mode = %o, want 600", mode)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("directory holds %d entries, want only the cache (no temporary file left)", len(entries))
	}

	got, err := cache.Load(path, vo(a, time.Now(), time.Hour))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !got.Cert.Equal(a.Cert) || len(got.Chain) != 1 || !got.Chain[0].Equal(a.Chain[0]) || !got.Root.Equal(a.Root) {
		t.Fatal("Load returned other certificates")
	}
	if got.ExtraRoots() != nil {
		t.Fatal("Load made up upstream roots")
	}
}

// The file is a CacheEntry: the secret in the shared format, and no bundle
// when the upstream roots are the root alone.
func TestFileFormat(t *testing.T) {
	a := authority(t, testpki.Options{})
	data, err := cache.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc) != 1 || doc["secret"] == nil {
		t.Fatalf("top-level fields: %s", data)
	}
	if _, err := intermediateca.Decode(doc["secret"]); err != nil {
		t.Fatalf("the cached secret is not an intermediate-ca/v1 secret: %v", err)
	}
}

func TestAWSSecretBundleRoundTrip(t *testing.T) {
	now := time.Now()
	p := testpki.New(t, testpki.Options{Middle: 1})
	other := testpki.New(t, testpki.Options{})
	a, err := secret.ParseAWSSecretLayout(
		testpki.CertPEM(p.Intermediate.Cert, p.Middle[0].Cert), testpki.KeyPEM(t, p.Intermediate.Key),
		testpki.CertPEM(other.Root.Cert, p.Root.Cert), now)
	if err != nil {
		t.Fatal(err)
	}
	data, err := cache.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"upstream_bundle"`) {
		t.Fatalf("no upstream_bundle written: %s", data)
	}
	got, err := cache.Unmarshal(data, vo(a, now, 0))
	if err != nil {
		t.Fatal(err)
	}
	roots := got.UpstreamRoots()
	if len(roots) != 2 || !roots[0].Equal(other.Root.Cert) || !roots[1].Equal(p.Root.Cert) {
		t.Fatalf("the cache lost the bundle: %d roots", len(roots))
	}
	if !got.Root.Equal(p.Root.Cert) {
		t.Fatal("wrong root")
	}
}

func TestSaveCreatesDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a", "b", "cache.json")
	if err := cache.Save(path, authority(t, testpki.Options{})); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if mode := st.Mode().Perm(); mode != 0o700 {
		t.Fatalf("directory mode = %o, want 700", mode)
	}
}

func TestSaveRefusesNothing(t *testing.T) {
	if err := cache.Save(filepath.Join(t.TempDir(), "c.json"), &secret.Authority{}); err == nil {
		t.Fatal("saved an empty authority")
	}
}

func TestLoadMissing(t *testing.T) {
	_, err := cache.Load(filepath.Join(t.TempDir(), "none.json"), secret.ValidateOptions{Now: time.Now(), TrustDomain: td})
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Load = %v, want ErrNotExist", err)
	}
}

// Entries that are not what Save writes: each is refused, and no error
// carries key material.
func TestUnmarshalRejects(t *testing.T) {
	now := time.Now()
	p := testpki.New(t, testpki.Options{})
	a, err := secret.ParseV1([]byte(p.V1(t)), now)
	if err != nil {
		t.Fatal(err)
	}
	good, err := cache.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var entry map[string]any
	if err := json.Unmarshal(good, &entry); err != nil {
		t.Fatal(err)
	}
	sec := entry["secret"].(map[string]any)
	key := sec["key"].(string)
	enc := func(edit func(e, s map[string]any)) string {
		e := map[string]any{}
		s := map[string]any{}
		for k, v := range entry {
			e[k] = v
		}
		for k, v := range sec {
			s[k] = v
		}
		e["secret"] = s
		edit(e, s)
		b, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}

	for name, tc := range map[string]struct {
		data string
		want string
	}{
		"truncated":           {data: string(good[:len(good)/2]), want: "not a JSON cache entry"},
		"not JSON":            {data: "{not json", want: "not a JSON cache entry"},
		"old format":          {data: p.V1(t), want: "not a JSON cache entry"},
		"old bundle field":    {data: enc(func(e, _ map[string]any) { e["x_upstream_bundle"] = "" }), want: "not a JSON cache entry"},
		"unknown field":       {data: enc(func(e, _ map[string]any) { e["extra"] = 1 }), want: "not a JSON cache entry"},
		"unknown in secret":   {data: enc(func(_, s map[string]any) { s["comment"] = "x" }), want: "not a JSON cache entry"},
		"no secret":           {data: `{}`, want: "secret (required)"},
		"bundle not PEM":      {data: enc(func(e, _ map[string]any) { e["upstream_bundle"] = []string{"garbage"} }), want: "upstream_bundle[0] (string.prefix)"},
		"bundle of two":       {data: enc(func(e, _ map[string]any) { e["upstream_bundle"] = []string{testpki.CertPEM(p.Root.Cert, p.Root.Cert)} }), want: "want exactly one certificate"},
		"bundle without root": {data: enc(func(e, _ map[string]any) { e["upstream_bundle"] = []string{testpki.CertPEM(p.Intermediate.Cert)} }), want: "do not include the root"},
		"secret format":       {data: enc(func(_, s map[string]any) { s["format"] = "intermediate-ca/v2" }), want: "secret.format (string.const)"},
		"secret key":          {data: enc(func(_, s map[string]any) { s["key"] = "garbage" }), want: "secret.key (string.prefix)"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := cache.Unmarshal([]byte(tc.data), vo(a, now, 0))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Unmarshal = %v, want %q", err, tc.want)
			}
			if strings.Contains(err.Error(), key[30:60]) {
				t.Fatalf("the error holds the key: %v", err)
			}
		})
	}
}

func TestLoadUnpinnedOrUnusable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.json")
	other := authority(t, testpki.Options{})
	a := authority(t, testpki.Options{Intermediate: testpki.PathLen(0)})
	if err := cache.Save(path, a); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Load(path, vo(other, time.Now(), 0)); err == nil {
		t.Fatal("cache under an unpinned root accepted")
	}
	if _, err := cache.Load(path, vo(a, time.Now(), 0)); err == nil {
		t.Fatal("cache with an intermediate that cannot sign a SPIRE CA accepted")
	}
}

func TestLoadExpired(t *testing.T) {
	now := time.Now()
	path := filepath.Join(t.TempDir(), "cache.json")
	a := authority(t, testpki.Options{Now: now, IntermediateTTL: 2 * time.Hour})
	if err := cache.Save(path, a); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Load(path, vo(a, now.Add(3*time.Hour), 0)); !errors.Is(err, intermediateca.ErrExpired) {
		t.Fatalf("expired cache: %v, want ErrExpired", err)
	}
	if _, err := cache.Load(path, vo(a, now, 3*time.Hour)); err == nil {
		t.Fatal("cache with less than min_remaining left accepted")
	}
}
