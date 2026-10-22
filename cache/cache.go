// Package cache keeps the last good intermediate CA on local disk, so that
// the plugin can keep minting while AWS Secrets Manager is unreachable,
// including across a restart. The file is the protobuf JSON mapping of a
// cache.v1.CacheEntry (cache/v1/cache.proto): the intermediate CA in the
// intermediate-ca/v1 format, and the upstream roots when they are more than
// its root.
package cache

import (
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"

	cachev1 "github.com/bpalermo/spire-upstream-secretsmanager/cache/v1"
	"github.com/bpalermo/spire-upstream-secretsmanager/intermediateca"
	"github.com/bpalermo/spire-upstream-secretsmanager/secret"
)

var (
	validatorOnce sync.Once
	validator     protovalidate.Validator
	validatorErr  error
)

// validate checks an entry against the rules of cache.proto and of the
// secret it holds. A violation is reported by field and rule only: its value
// could be key material.
func validate(entry *cachev1.CacheEntry) error {
	validatorOnce.Do(func() { validator, validatorErr = protovalidate.New() })
	if validatorErr != nil {
		return fmt.Errorf("building the validator: %w", validatorErr)
	}
	err := validator.Validate(entry)
	var verr *protovalidate.ValidationError
	if err == nil || !errors.As(err, &verr) {
		return err
	}
	reasons := make([]string, 0, len(verr.Violations))
	for _, v := range verr.Violations {
		reasons = append(reasons, fmt.Sprintf("%s (%s)", protovalidate.FieldPathString(v.Proto.GetField()), v.Proto.GetRuleId()))
	}
	return fmt.Errorf("invalid cache entry: %s", strings.Join(reasons, ", "))
}

// Save writes a to path atomically, with mode 0600: the JSON goes to a
// temporary file in the same directory, which is synced, renamed over path,
// and the directory is synced, so that a crash leaves either the old file or
// the new one. The directory is created (mode 0700) if it does not exist.
func Save(path string, a *secret.Authority) error {
	data, err := Marshal(a)
	if err != nil {
		return err
	}
	return writeAtomic(path, data, 0o600)
}

// Marshal returns the cache entry of a, as Save writes it. An entry that
// would break a rule of cache.proto (a bundle too large) is an error.
func Marshal(a *secret.Authority) ([]byte, error) {
	if a == nil || a.Raw == nil {
		return nil, errors.New("no intermediate CA to cache")
	}
	entry := &cachev1.CacheEntry{Secret: a.Raw}
	for _, c := range a.ExtraRoots() {
		entry.UpstreamBundle = append(entry.UpstreamBundle, secret.CertificatePEM(c))
	}
	if err := validate(entry); err != nil {
		return nil, err
	}
	data, err := protojson.Marshal(entry)
	if err != nil {
		return nil, fmt.Errorf("unable to encode the cache entry: %w", err)
	}
	return data, nil
}

// Load reads the cache at path and validates it with opts. A cache that does
// not exist is an error satisfying errors.Is(err, fs.ErrNotExist); a cache
// that cannot be decoded or does not validate is an error too, and the caller
// is expected to ignore it.
func Load(path string, opts secret.ValidateOptions) (*secret.Authority, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	a, err := Unmarshal(data, opts)
	if err != nil {
		return nil, fmt.Errorf("cache %s is not usable: %w", path, err)
	}
	return a, nil
}

// Unmarshal decodes a cache entry and validates it with opts. The JSON is
// read strictly: an unknown field, in the entry or in its secret, makes it
// invalid, since the plugin alone writes the file. The secret is then read
// exactly as one from Secrets Manager is, and the result validated as one.
func Unmarshal(data []byte, opts secret.ValidateOptions) (*secret.Authority, error) {
	entry := &cachev1.CacheEntry{}
	if err := protojson.Unmarshal(data, entry); err != nil {
		// protojson's message can quote part of the input, which holds a
		// private key.
		return nil, errors.New("not a JSON cache entry, or one with unknown fields")
	}
	if err := validate(entry); err != nil {
		return nil, err
	}
	raw, err := protojson.Marshal(entry.GetSecret())
	if err != nil {
		return nil, fmt.Errorf("unable to encode the cached secret: %w", err)
	}
	b, err := intermediateca.DecodeAt(raw, opts.Now)
	if err != nil {
		return nil, err
	}
	var roots []*x509.Certificate
	for i, s := range entry.GetUpstreamBundle() {
		certs, err := secret.ParseCertificates(s)
		if err != nil {
			return nil, fmt.Errorf("upstream_bundle[%d]: %w", i, err)
		}
		if len(certs) != 1 {
			return nil, fmt.Errorf("upstream_bundle[%d]: want exactly one certificate, found %d", i, len(certs))
		}
		roots = append(roots, certs[0])
	}
	a, err := secret.FromBundle(b, roots, opts.Now)
	if err != nil {
		return nil, err
	}
	if err := a.Validate(opts); err != nil {
		return nil, err
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
