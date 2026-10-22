package secret

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"github.com/bpalermo/spire-upstream-secretsmanager/pkg/upstreamca"
)

// probe signs a throwaway SPIRE CA for the trust domain with the
// intermediate, exactly as a mint would, and a throwaway X509-SVID with that
// CA, and verifies the SVID through [CA, intermediate, chain...] to the root
// the way SPIRE's X509CAValidator checks every upstream-signed CA
// (pkg/server/ca/validation.go in SPIRE v1.15.5). An intermediate whose path
// length or name constraints leave no room for the SPIRE CA fails here, not
// at SPIRE after it has replaced the last good copy.
func (a *Authority) probe(opts ValidateOptions) error {
	if opts.TrustDomain.IsZero() {
		return errors.New("no trust domain to validate the intermediate CA for")
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		URIs: []*url.URL{opts.TrustDomain.ID().URL()},
	}, caKey)
	if err != nil {
		return err
	}
	now := func() time.Time { return opts.Now }
	ca, err := upstreamca.New(a.Cert, a.Key, opts.TrustDomain, now).SignCSR(csr, upstreamca.DefaultTTL)
	if err != nil {
		return fmt.Errorf("unable to sign a CA for %s: %w", opts.TrustDomain.ID(), err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	id, err := spiffeid.FromPath(opts.TrustDomain, "/spire/throwaway")
	if err != nil {
		return err
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    ca.NotBefore,
		NotAfter:     ca.NotAfter,
		URIs:         []*url.URL{id.URL()},
	}, ca, leafKey.Public(), caKey)
	if err != nil {
		return fmt.Errorf("unable to sign a probe X509-SVID: %w", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return err
	}

	chain := append([]*x509.Certificate{leaf, ca}, a.UpstreamChain()...)
	bundle := x509bundle.FromX509Authorities(opts.TrustDomain, []*x509.Certificate{a.Root})
	if _, _, err := x509svid.Verify(chain, bundle, x509svid.WithTime(opts.Now)); err != nil {
		return fmt.Errorf("a CA signed by this intermediate for %s would be rejected by SPIRE: %w", opts.TrustDomain.ID(), err)
	}
	return nil
}
