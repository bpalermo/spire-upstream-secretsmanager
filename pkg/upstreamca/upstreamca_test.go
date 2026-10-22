package upstreamca_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bpalermo/spire-upstream-secretsmanager/internal/testpki"
	"github.com/bpalermo/spire-upstream-secretsmanager/pkg/upstreamca"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

var td = spiffeid.RequireTrustDomainFromString("example.org")

func csr(t *testing.T, uris ...string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{Organization: []string{"SPIFFE"}}}
	for _, u := range uris {
		parsed, err := url.Parse(u)
		if err != nil {
			t.Fatal(err)
		}
		tmpl.URIs = append(tmpl.URIs, parsed)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestSignCSR(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	p := testpki.New(t, testpki.Options{Now: now})
	ca := upstreamca.New(p.Intermediate.Cert, p.Intermediate.Key, td, func() time.Time { return now })

	cert, err := ca.SignCSR(csr(t, "spiffe://example.org"), 2*time.Hour)
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	if !cert.IsCA || !cert.BasicConstraintsValid {
		t.Fatal("minted certificate is not a CA")
	}
	if cert.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		t.Fatalf("key usage = %v", cert.KeyUsage)
	}
	if !cert.NotBefore.Equal(now.Add(-upstreamca.DefaultBackdate)) || !cert.NotAfter.Equal(now.Add(2*time.Hour)) {
		t.Fatalf("validity %s..%s", cert.NotBefore, cert.NotAfter)
	}
	if len(cert.URIs) != 1 || cert.URIs[0].String() != "spiffe://example.org" {
		t.Fatalf("URIs = %v", cert.URIs)
	}
	ski, err := upstreamca.SubjectKeyID(cert.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cert.SubjectKeyId, ski) || len(ski) != 20 {
		t.Fatal("unexpected subject key ID")
	}
	if err := cert.CheckSignatureFrom(p.Intermediate.Cert); err != nil {
		t.Fatalf("not signed by the intermediate: %v", err)
	}
	if cert.SerialNumber.Sign() <= 0 {
		t.Fatal("serial number is not positive")
	}
}

func TestSignCSRDefaultTTL(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	p := testpki.New(t, testpki.Options{Now: now})
	ca := upstreamca.New(p.Intermediate.Cert, p.Intermediate.Key, td, func() time.Time { return now })
	cert, err := ca.SignCSR(csr(t, "spiffe://example.org"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if !cert.NotAfter.Equal(now.Add(upstreamca.DefaultTTL)) {
		t.Fatalf("NotAfter = %s, want now+1h", cert.NotAfter)
	}
}

func TestSignCSRCapsNotAfter(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	p := testpki.New(t, testpki.Options{Now: now, IntermediateTTL: 3 * time.Hour})
	ca := upstreamca.New(p.Intermediate.Cert, p.Intermediate.Key, td, func() time.Time { return now })
	cert, err := ca.SignCSR(csr(t, "spiffe://example.org"), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !cert.NotAfter.Equal(p.Intermediate.Cert.NotAfter) {
		t.Fatalf("NotAfter = %s, want the intermediate's %s", cert.NotAfter, p.Intermediate.Cert.NotAfter)
	}
}

func TestSignCSRRejects(t *testing.T) {
	p := testpki.New(t, testpki.Options{})
	ca := upstreamca.New(p.Intermediate.Cert, p.Intermediate.Key, td, nil)
	bad := csr(t, "spiffe://example.org")
	bad[len(bad)-1] ^= 0xff
	for name, tc := range map[string]struct {
		der  []byte
		want string
	}{
		"other trust domain": {csr(t, "spiffe://other.example.org"), "must use the trust domain ID"},
		"workload ID":        {csr(t, "spiffe://example.org/workload"), "must use the trust domain ID"},
		"no URI":             {csr(t), "exactly one URI SAN"},
		"two URIs":           {csr(t, "spiffe://example.org", "spiffe://example.org/x"), "exactly one URI SAN"},
		"not a SPIFFE ID":    {csr(t, "https://example.org"), "is invalid"},
		"bad signature":      {bad, "CSR"},
		"garbage":            {[]byte("garbage"), "unable to parse CSR"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ca.SignCSR(tc.der, time.Hour)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("SignCSR = %v, want an error containing %q", err, tc.want)
			}
		})
	}
}
