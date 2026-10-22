package plugin

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"buf.build/go/protovalidate"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protoreflect"

	pluginv1 "github.com/bpalermo/spire-upstream-secretsmanager/plugin/v1"
)

const (
	defaultFetchTimeout = 10 * time.Second
	defaultMinRemaining = time.Hour
)

// config is a parsed and validated plugin_data (plugin/v1/config.proto).
type config struct {
	*pluginv1.Config
	trustDomain  spiffeid.TrustDomain
	rootPins     [][32]byte
	fetchTimeout time.Duration
	minRemaining time.Duration
}

var (
	validatorOnce sync.Once
	validator     protovalidate.Validator
	validatorErr  error
)

// buildConfig parses and validates the plugin configuration of a Configure
// or Validate request: HCL (or JSON, which HCL reads too) is decoded into a
// generic document, unknown keys are refused, a single root_sha256 string
// becomes a list of one (and every pin lower case), and the result is read
// strictly as the JSON of a pluginv1.Config, then checked against the rules of config.proto and the server's
// trust domain. Every problem of those last two steps is reported.
func buildConfig(core *configv1.CoreConfiguration, hclText string) (*config, error) {
	msg, err := decodeConfig(hclText)
	if err != nil {
		return nil, err
	}
	c := &config{Config: msg}
	var errs []error
	if err := validateConfig(msg); err != nil {
		errs = append(errs, err)
	}
	if core == nil || core.TrustDomain == "" {
		errs = append(errs, errors.New("server core configuration must contain trust_domain"))
	} else {
		td, err := spiffeid.TrustDomainFromString(core.TrustDomain)
		if err != nil {
			errs = append(errs, fmt.Errorf("server core configuration trust_domain is malformed: %w", err))
		}
		c.trustDomain = td
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	// The rules have checked the forms of these already.
	for _, h := range msg.GetRootSha256() {
		var pin [32]byte
		if _, err := hex.Decode(pin[:], []byte(h)); err != nil {
			return nil, fmt.Errorf("'root_sha256' value %q is not hexadecimal", h)
		}
		c.rootPins = append(c.rootPins, pin)
	}
	if c.fetchTimeout, err = parseDuration("fetch_timeout", msg.GetFetchTimeout(), defaultFetchTimeout); err != nil {
		return nil, err
	}
	if c.minRemaining, err = parseDuration("min_remaining", msg.GetMinRemaining(), defaultMinRemaining); err != nil {
		return nil, err
	}
	return c, nil
}

// decodeConfig reads plugin_data into a pluginv1.Config.
func decodeConfig(hclText string) (*pluginv1.Config, error) {
	var doc map[string]any
	if err := hcl.Decode(&doc, hclText); err != nil {
		return nil, fmt.Errorf("plugin configuration is malformed: %w", err)
	}
	if unknown := unknownKeys(doc); len(unknown) > 0 {
		// A misspelt root_sha265 must not silently disable a check. protojson
		// refuses unknown keys too; this names all of them at once.
		return nil, fmt.Errorf("unknown configuration keys: %s", strings.Join(unknown, ", "))
	}
	normaliseRootPins(doc)
	data, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("plugin configuration is malformed: %w", err)
	}
	msg := &pluginv1.Config{}
	if err := protojson.Unmarshal(data, msg); err != nil {
		// An unknown key (a misspelt root_sha265 must not silently disable
		// a check) or a value of the wrong type; the message names the key.
		return nil, fmt.Errorf("plugin configuration is invalid: %s", protojsonReason(err))
	}
	return msg, nil
}

// unknownKeys are the keys of doc that are not fields of pluginv1.Config,
// sorted.
func unknownKeys(doc map[string]any) []string {
	fields := (&pluginv1.Config{}).ProtoReflect().Descriptor().Fields()
	var unknown []string
	for k := range doc {
		if fields.ByJSONName(k) == nil && fields.ByName(protoreflect.Name(k)) == nil {
			unknown = append(unknown, k)
		}
	}
	slices.Sort(unknown)
	return unknown
}

// normaliseRootPins turns a single root_sha256 string into a list of one,
// and lower-cases every pin: hexadecimal digits are accepted in either case,
// as before the schema, which only takes lower case.
func normaliseRootPins(doc map[string]any) {
	switch v := doc["root_sha256"].(type) {
	case string:
		doc["root_sha256"] = []any{strings.ToLower(v)}
	case []any:
		for i, e := range v {
			if s, ok := e.(string); ok {
				v[i] = strings.ToLower(s)
			}
		}
	}
}

// protojsonReason is protojson's error without its "proto:" prefix and the
// non-breaking space it adds, on purpose, so that no one depends on its text.
func protojsonReason(err error) string {
	s := strings.ReplaceAll(err.Error(), " ", " ")
	return strings.TrimSpace(strings.TrimPrefix(s, "proto:"))
}

// validateConfig checks msg against the rules of config.proto, naming the
// field that breaks each.
func validateConfig(msg *pluginv1.Config) error {
	validatorOnce.Do(func() { validator, validatorErr = protovalidate.New() })
	if validatorErr != nil {
		return fmt.Errorf("building the validator: %w", validatorErr)
	}
	err := validator.Validate(msg)
	if err == nil {
		return nil
	}
	var verr *protovalidate.ValidationError
	if !errors.As(err, &verr) {
		return fmt.Errorf("plugin configuration is invalid: %w", err)
	}
	errs := make([]error, 0, len(verr.Violations))
	for _, v := range verr.Violations {
		if field := protovalidate.FieldPathString(v.Proto.GetField()); field != "" {
			errs = append(errs, fmt.Errorf("'%s' is invalid: %s", field, v.Proto.GetMessage()))
		} else {
			errs = append(errs, fmt.Errorf("plugin configuration is invalid: %s", v.Proto.GetMessage()))
		}
	}
	return errors.Join(errs...)
}

func parseDuration(name, s string, def time.Duration) (time.Duration, error) {
	if s == "" {
		return def, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("'%s' is not a duration: %w", name, err)
	}
	return d, nil
}
