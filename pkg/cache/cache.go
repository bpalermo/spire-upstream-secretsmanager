// Package cache keeps the last good intermediate CA on local disk, in format
// v1 (docs/secret-format.md), so that the plugin can keep minting while AWS
// Secrets Manager is unreachable, including across a restart.
package cache

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/bpalermo/spire-upstream-secretsmanager/pkg/secret"
)

// Save writes a to path atomically, with mode 0600: the JSON goes to a
// temporary file in the same directory, which is synced, renamed over path,
// and the directory is synced, so that a crash leaves either the old file or
// the new one. The directory is created (mode 0700) if it does not exist.
func Save(path string, a *secret.Authority) error {
	data, err := a.MarshalV1()
	if err != nil {
		return err
	}
	return writeAtomic(path, data, 0o600)
}

// Load reads the cache at path and validates it with opts. A cache that does
// not exist is an error satisfying errors.Is(err, fs.ErrNotExist); a cache
// that cannot be parsed or does not validate is an error too, and the caller
// is expected to ignore it.
func Load(path string, opts secret.ValidateOptions) (*secret.Authority, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	a, err := secret.ParseV1(data)
	if err != nil {
		return nil, fmt.Errorf("cache %s is corrupt: %w", path, err)
	}
	if err := a.Validate(opts); err != nil {
		return nil, fmt.Errorf("cache %s is not usable: %w", path, err)
	}
	return a, nil
}

// writeAtomic writes data to path through a temporary file in the same
// directory and a rename.
func writeAtomic(path string, data []byte, mode os.FileMode) (err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if err = f.Chmod(mode); err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	return syncDir(dir)
}

// syncDir makes a rename in dir durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	return errors.Join(err, d.Close())
}
