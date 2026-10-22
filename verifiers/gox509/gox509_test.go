// Package gox509_test runs every chain of package chains through Go's
// crypto/x509 path validation, the verifier of SPIRE itself and of go-spiffe.
package gox509_test

import (
	"crypto/x509"
	"testing"

	"github.com/bpalermo/spire-upstream-secretsmanager/verifiers/chains"
)

func pools(s *chains.Set, l *chains.Leaf) x509.VerifyOptions {
	roots := x509.NewCertPool()
	roots.AddCert(s.Root.Cert)
	inter := x509.NewCertPool()
	inter.AddCert(l.SPIRECA)
	inter.AddCert(l.Intermediate)
	return x509.VerifyOptions{Roots: roots, Intermediates: inter}
}

func verdict(err error) (chains.Verdict, string) {
	if err != nil {
		return chains.Rejected, err.Error()
	}
	return chains.Accepted, ""
}

func TestClientChains(t *testing.T) {
	s := chains.New(t)
	// Go reads a URI constraint without a leading period as "this host and
	// every host below it", as it does for DNS constraints; RFC 5280 says it
	// names one host.
	r := chains.NewResults(t, "go-crypto/x509", map[string]chains.Verdict{"A-sub": chains.Accepted})
	for _, l := range s.Clients {
		o := pools(s, l)
		o.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		_, err := l.Cert.Verify(o)
		got, detail := verdict(err)
		r.Record(l.Spec, got, detail)
	}
}

func TestServerChains(t *testing.T) {
	s := chains.New(t)
	r := chains.NewResults(t, "go-crypto/x509 (server)", nil)
	for _, sp := range chains.ServerSpecs {
		l := s.Servers[sp.ID]
		o := pools(s, l)
		o.DNSName = sp.DNS[0]
		_, err := l.Cert.Verify(o)
		got, detail := verdict(err)
		r.Record(l.Spec, got, detail)
	}
}

// The extension is critical on every constrained intermediate: a verifier
// that does not understand it has to reject the chain, so the other tests
// prove the extension is understood, not ignored.
func TestConstraintsAreCritical(t *testing.T) {
	s := chains.New(t)
	for _, name := range chains.Intermediates {
		c := s.Intermediates[name].Cert
		var found, critical bool
		for _, e := range c.Extensions {
			if e.Id.Equal([]int{2, 5, 29, 30}) {
				found, critical = true, e.Critical
			}
		}
		if want := name != chains.None; found != want || critical != want {
			t.Errorf("%s: name constraints present=%v critical=%v, want %v", name, found, critical, want)
		}
		if c.MaxPathLen != 1 {
			t.Errorf("%s: pathlen %d, want 1", name, c.MaxPathLen)
		}
	}
	if s.Root.Cert.MaxPathLen != 2 {
		t.Errorf("root pathlen %d, want 2", s.Root.Cert.MaxPathLen)
	}
}
