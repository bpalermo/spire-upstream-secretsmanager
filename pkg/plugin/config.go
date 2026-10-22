package plugin

import (
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
)

const (
	defaultFetchTimeout = 10 * time.Second
	defaultMinRemaining = time.Hour
)

// Config is the plugin_data of the plugin, in HCL.
type Config struct {
	// Region, Endpoint and AssumeRoleARN select the AWS Secrets Manager
	// endpoint and the credentials, as SPIRE's awssecret plugin does.
	// Endpoint is meant for tests.
	Region        string `hcl:"region" json:"region"`
	Endpoint      string `hcl:"endpoint" json:"endpoint"`
	AssumeRoleARN string `hcl:"assume_role_arn" json:"assume_role_arn"`

	// SecretID is a format v1 secret (docs/secret-format.md).
	SecretID string `hcl:"secret_id" json:"secret_id"`

	// The layout of SPIRE's awssecret plugin, instead of SecretID: three
	// secrets whose SecretString is PEM.
	CertFileARN   string `hcl:"cert_file_arn" json:"cert_file_arn"`
	KeyFileARN    string `hcl:"key_file_arn" json:"key_file_arn"`
	BundleFileARN string `hcl:"bundle_file_arn" json:"bundle_file_arn"`

	// CachePath is where the last good intermediate CA is kept.
	CachePath string `hcl:"cache_path" json:"cache_path"`

	// RootSHA256 is the hex SHA-256 of the DER of the only root accepted.
	RootSHA256 string `hcl:"root_sha256" json:"root_sha256"`

	// FetchTimeout bounds the Secrets Manager reads of one mint.
	FetchTimeout string `hcl:"fetch_timeout" json:"fetch_timeout"`

	// MinRemaining is the least lifetime an intermediate CA must have left
	// to be used.
	MinRemaining string `hcl:"min_remaining" json:"min_remaining"`
}

// config is a parsed and validated Config.
type config struct {
	Config
	trustDomain  spiffeid.TrustDomain
	rootSHA256   []byte
	fetchTimeout time.Duration
	minRemaining time.Duration
}

// buildConfig parses and validates the plugin configuration of a Configure
// or Validate request. It reports every problem it finds.
func buildConfig(core *configv1.CoreConfiguration, hclText string) (*config, error) {
	c := &config{}
	if err := hcl.Decode(&c.Config, hclText); err != nil {
		return nil, fmt.Errorf("plugin configuration is malformed: %w", err)
	}
	var errs []error
	if core == nil || core.TrustDomain == "" {
		errs = append(errs, errors.New("server core configuration must contain trust_domain"))
	} else {
		td, err := spiffeid.TrustDomainFromString(core.TrustDomain)
		if err != nil {
			errs = append(errs, fmt.Errorf("server core configuration trust_domain is malformed: %w", err))
		}
		c.trustDomain = td
	}
	errs = append(errs, c.validateSource()...)
	var err error
	if c.rootSHA256, err = parsePin(c.RootSHA256); err != nil {
		errs = append(errs, err)
	}
	if c.fetchTimeout, err = parseDuration("fetch_timeout", c.FetchTimeout, defaultFetchTimeout, false); err != nil {
		errs = append(errs, err)
	}
	if c.minRemaining, err = parseDuration("min_remaining", c.MinRemaining, defaultMinRemaining, true); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return c, nil
}

// validateSource checks that exactly one of the two secret layouts is
// configured.
func (c *config) validateSource() []error {
	awssecret := c.CertFileARN != "" || c.KeyFileARN != "" || c.BundleFileARN != ""
	switch {
	case c.SecretID != "" && awssecret:
		return []error{errors.New("set either 'secret_id' or 'cert_file_arn', 'key_file_arn' and 'bundle_file_arn', not both")}
	case c.SecretID != "":
		return nil
	case !awssecret:
		return []error{errors.New("configuration missing 'secret_id' value (or 'cert_file_arn' and 'key_file_arn')")}
	}
	var errs []error
	if c.CertFileARN == "" {
		errs = append(errs, errors.New("configuration missing 'cert_file_arn' value"))
	}
	if c.KeyFileARN == "" {
		errs = append(errs, errors.New("configuration missing 'key_file_arn' value"))
	}
	return errs
}

func parsePin(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return nil, fmt.Errorf("'root_sha256' must be 64 hex characters, the SHA-256 of the root certificate's DER")
	}
	return b, nil
}

func parseDuration(name, s string, def time.Duration, zeroOK bool) (time.Duration, error) {
	if s == "" {
		return def, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("'%s' is not a duration: %w", name, err)
	}
	if d < 0 || (d == 0 && !zeroOK) {
		return 0, fmt.Errorf("'%s' must be positive", name)
	}
	return d, nil
}
