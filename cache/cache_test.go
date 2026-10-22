package cache_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/bpalermo/spire-upstream-secretsmanager/cache"
	"github.com/bpalermo/spire-upstream-secretsmanager/internal/testpki"
	"github.com/bpalermo/spire-upstream-secretsmanager/secret"
)

var td = spiffeid.RequireTrustDomainFromString("example.org")

// vo validates for example.org at now with a's root pinned.
func vo(a *secret.Authority, now time.Time, minRemaining time.Duration) secret.ValidateOptions {
	pin := secret.RootSHA256(a.Root)
	return secret.ValidateOptions{Now: now, MinRemaining: minRemaining, RootPins: [][]byte{pin[:]}, TrustDomain: td}
}

func authority(t *testing.T, o testpki.Options) *secret.Authority {
	t.Helper()
	a, err := secret.ParseV1([]byte(testpki.New(t, o).V1(t)))
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
	if !got.Cert.Equal(a.Cert) || len(got.Chain) != 1 {
		t.Fatal("Load returned other certificates")
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

func TestLoadMissing(t *testing.T) {
	_, err := cache.Load(filepath.Join(t.TempDir(), "none.json"), secret.ValidateOptions{Now: time.Now(), TrustDomain: td})
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Load = %v, want ErrNotExist", err)
	}
}

func TestLoadCorrupt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.json")
	if err := os.WriteFile(path, []byte(`{"format":"intermediate-ca/v1","cert":"x"`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Load(path, secret.ValidateOptions{Now: time.Now(), TrustDomain: td}); err == nil {
		t.Fatal("corrupt cache accepted")
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
	if _, err := cache.Load(path, vo(a, now.Add(3*time.Hour), 0)); err == nil {
		t.Fatal("expired cache accepted")
	}
	if _, err := cache.Load(path, vo(a, now, 3*time.Hour)); err == nil {
		t.Fatal("cache with less than min_remaining left accepted")
	}
}
