// Package plugin is the SPIRE UpstreamAuthority plugin: it reads its
// intermediate CA from AWS Secrets Manager at every mint, validates it, keeps
// the last good copy in memory and on disk, and signs the SPIRE server's CA
// with it.
//
// It behaves like SPIRE's built-in disk and awssecret UpstreamAuthority
// plugins (SPIRE v1.15.5, https://github.com/spiffe/spire, Apache-2.0), from
// which the response layout, the unimplemented methods and the awssecret
// secret layout are adapted, except that the CA is read at every mint rather
// than once at Configure, and that Configure makes no AWS call.
package plugin

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	upstreamauthorityv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/upstreamauthority/v1"
	"github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/bpalermo/spire-upstream-secretsmanager/pkg/cache"
	"github.com/bpalermo/spire-upstream-secretsmanager/pkg/secret"
	"github.com/bpalermo/spire-upstream-secretsmanager/pkg/upstreamca"
)

// Plugin implements the UpstreamAuthority and Config services.
type Plugin struct {
	upstreamauthorityv1.UnsafeUpstreamAuthorityServer
	configv1.UnsafeConfigServer

	newClient NewClientFunc
	now       func() time.Time

	// mu guards log, cfg and client.
	mu     sync.RWMutex
	log    hclog.Logger
	cfg    *config
	client SecretsClient

	// mintMu serialises the fetch, validation and cache update of mints,
	// and guards last.
	mintMu sync.Mutex
	// last is the last good intermediate CA: the one last fetched, or the
	// one loaded from the cache at Configure.
	last *secret.Authority
}

// Option configures a Plugin.
type Option func(*Plugin)

// WithNewClient replaces the Secrets Manager client constructor (tests).
func WithNewClient(f NewClientFunc) Option {
	return func(p *Plugin) { p.newClient = f }
}

// WithClock replaces the clock (tests).
func WithClock(now func() time.Time) Option {
	return func(p *Plugin) { p.now = now }
}

// New returns an unconfigured plugin.
func New(opts ...Option) *Plugin {
	p := &Plugin{
		newClient: NewSecretsManagerClient,
		now:       time.Now,
		log:       hclog.NewNullLogger(),
	}
	for _, o := range opts {
		o(p)
	}
	return p
}

// SetLogger is called by the plugin SDK with the logger wired to SPIRE.
func (p *Plugin) SetLogger(log hclog.Logger) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.log = log
}

func (p *Plugin) logger() hclog.Logger {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.log
}

// Configure parses and validates the configuration, builds the Secrets
// Manager client (without calling AWS) and loads the cache, if there is a
// valid one. It makes no AWS call, so that the SPIRE server starts while AWS
// is unreachable.
func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	cfg, err := buildConfig(req.GetCoreConfiguration(), req.GetHclConfiguration())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	client, err := p.newClient(ctx, cfg.Config)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to create AWS client: %v", err)
	}
	cached := p.loadCache(cfg)

	p.mintMu.Lock()
	defer p.mintMu.Unlock()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cfg = cfg
	p.client = client
	p.last = cached
	return &configv1.ConfigureResponse{}, nil
}

// loadCache returns the cached intermediate CA, or nil (with a warning) if
// there is none that is valid.
func (p *Plugin) loadCache(cfg *config) *secret.Authority {
	if cfg.CachePath == "" {
		return nil
	}
	a, err := cache.Load(cfg.CachePath, p.validateOptions(cfg))
	switch {
	case err == nil:
		p.logger().Info("Loaded the cached intermediate CA", "path", cfg.CachePath,
			"serial", a.Cert.SerialNumber.String(), "not_after", a.Cert.NotAfter.UTC().Format(time.RFC3339))
		return a
	case errors.Is(err, fs.ErrNotExist):
		p.logger().Info("No cached intermediate CA yet", "path", cfg.CachePath)
	default:
		p.logger().Warn("Ignoring the cached intermediate CA", "path", cfg.CachePath, "reason", err.Error())
	}
	return nil
}

// Validate reports whether the configuration is usable.
func (p *Plugin) Validate(_ context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	_, err := buildConfig(req.GetCoreConfiguration(), req.GetHclConfiguration())
	if err != nil {
		return &configv1.ValidateResponse{Valid: false, Notes: []string{err.Error()}}, nil
	}
	return &configv1.ValidateResponse{Valid: true}, nil
}

// MintX509CAAndSubscribe reads the intermediate CA from Secrets Manager (or
// falls back to the last good copy), signs the CSR with it and sends the
// chain and the root once, like SPIRE's disk plugin.
func (p *Plugin) MintX509CAAndSubscribe(req *upstreamauthorityv1.MintX509CARequest, stream upstreamauthorityv1.UpstreamAuthority_MintX509CAAndSubscribeServer) error {
	p.mu.RLock()
	cfg, client := p.cfg, p.client
	p.mu.RUnlock()
	if cfg == nil {
		return status.Error(codes.FailedPrecondition, "not configured")
	}

	a, err := p.authority(stream.Context(), cfg, client)
	if err != nil {
		return status.Error(codes.Unavailable, err.Error())
	}

	ca := upstreamca.New(a.Cert, a.Key, cfg.trustDomain, p.now)
	cert, err := ca.SignCSR(req.GetCsr(), time.Second*time.Duration(req.GetPreferredTtl()))
	if err != nil {
		return status.Errorf(codes.Internal, "unable to sign CSR: %v", err)
	}

	return stream.Send(&upstreamauthorityv1.MintX509CAResponse{
		X509CaChain:       toPlugin(append([]*x509.Certificate{cert}, a.UpstreamChain()...)),
		UpstreamX509Roots: toPlugin([]*x509.Certificate{a.Root}),
	})
}

// PublishJWTKeyAndSubscribe is not supported, as in SPIRE's disk plugin.
func (*Plugin) PublishJWTKeyAndSubscribe(*upstreamauthorityv1.PublishJWTKeyRequest, upstreamauthorityv1.UpstreamAuthority_PublishJWTKeyAndSubscribeServer) error {
	return status.Error(codes.Unimplemented, "publishing upstream is unsupported")
}

// SubscribeToLocalBundle is not supported, as in SPIRE's disk plugin.
func (*Plugin) SubscribeToLocalBundle(*upstreamauthorityv1.SubscribeToLocalBundleRequest, upstreamauthorityv1.UpstreamAuthority_SubscribeToLocalBundleServer) error {
	return status.Error(codes.Unimplemented, "fetching upstream trust bundle is unsupported")
}

// authority returns the intermediate CA to sign with: the one in Secrets
// Manager if it can be read and is valid, which then replaces the cache;
// otherwise the last good one, if it is still valid.
func (p *Plugin) authority(ctx context.Context, cfg *config, client SecretsClient) (*secret.Authority, error) {
	p.mintMu.Lock()
	defer p.mintMu.Unlock()
	log := p.logger()

	fetched, err := p.fetch(ctx, cfg, client)
	if err == nil {
		err = fetched.Validate(p.validateOptions(cfg))
	}
	if err == nil {
		p.remember(cfg, fetched, log)
		return fetched, nil
	}

	if p.last == nil {
		log.Warn("Unable to use the intermediate CA from Secrets Manager and there is no cached copy", "reason", err.Error())
		return nil, fmt.Errorf("no valid intermediate CA: %v; and no cached copy", err)
	}
	if cerr := p.last.Validate(p.validateOptions(cfg)); cerr != nil {
		log.Warn("Unable to use the intermediate CA from Secrets Manager and the cached copy is no longer valid",
			"reason", err.Error(), "cache_reason", cerr.Error())
		return nil, fmt.Errorf("no valid intermediate CA: %v; cached copy: %v", err, cerr)
	}
	log.Warn("Unable to use the intermediate CA from Secrets Manager; using the cached copy",
		"reason", err.Error(), "serial", p.last.Cert.SerialNumber.String(),
		"not_after", p.last.Cert.NotAfter.UTC().Format(time.RFC3339))
	return p.last, nil
}

// remember makes a the last good intermediate CA and writes it to the cache.
// A cache write failure is logged and does not fail the mint.
func (p *Plugin) remember(cfg *config, a *secret.Authority, log hclog.Logger) {
	if p.last == nil || !p.last.Cert.Equal(a.Cert) {
		log.Info("Using intermediate CA from Secrets Manager", "serial", a.Cert.SerialNumber.String(),
			"not_after", a.Cert.NotAfter.UTC().Format(time.RFC3339))
	}
	p.last = a
	if cfg.CachePath == "" {
		return
	}
	if err := cache.Save(cfg.CachePath, a); err != nil {
		log.Warn("Unable to write the intermediate CA cache", "path", cfg.CachePath, "reason", err.Error())
	}
}

// fetch reads the intermediate CA from Secrets Manager within fetch_timeout.
func (p *Plugin) fetch(ctx context.Context, cfg *config, client SecretsClient) (*secret.Authority, error) {
	ctx, cancel := context.WithTimeout(ctx, cfg.fetchTimeout)
	defer cancel()

	if cfg.SecretID != "" {
		s, err := readSecret(ctx, client, cfg.SecretID)
		if err != nil {
			return nil, fmt.Errorf("unable to read %s: %w", cfg.SecretID, err)
		}
		return secret.ParseV1([]byte(s))
	}

	// The awssecret layout, read in awssecret's order.
	ids := []string{cfg.KeyFileARN, cfg.CertFileARN, cfg.BundleFileARN}
	values := make([]string, len(ids))
	for i, id := range ids {
		if id == "" {
			continue
		}
		s, err := readSecret(ctx, client, id)
		if err != nil {
			return nil, fmt.Errorf("unable to read %s: %w", id, err)
		}
		values[i] = s
	}
	return secret.ParseAWSSecretLayout(values[1], values[0], values[2], p.now())
}

func (p *Plugin) validateOptions(cfg *config) secret.ValidateOptions {
	return secret.ValidateOptions{
		Now:          p.now(),
		MinRemaining: cfg.minRemaining,
		RootSHA256:   cfg.rootSHA256,
	}
}

func toPlugin(certs []*x509.Certificate) []*types.X509Certificate {
	out := make([]*types.X509Certificate, 0, len(certs))
	for _, c := range certs {
		out = append(out, &types.X509Certificate{Asn1: c.Raw})
	}
	return out
}
