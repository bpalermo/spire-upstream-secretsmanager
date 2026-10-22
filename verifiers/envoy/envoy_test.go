// Package envoy_test runs every client chain of package chains against an
// Envoy mTLS listener, with each of Envoy's two certificate validators:
//
//   - default: validation_context trusted_ca = the root, and
//     match_typed_subject_alt_names with a URI prefix "spiffe://", so only
//     path validation (and not the SAN match) can reject a chain;
//   - spiffe: the SPIFFE certificate validator, with the root as the bundle
//     of every trust domain the chains use.
//
// The client is curl (OpenSSL) presenting the leaf, SPIRE CA and
// intermediate. Needs a local Docker daemon.
package envoy_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bpalermo/spire-upstream-secretsmanager/verifiers/chains"
	"github.com/bpalermo/spire-upstream-secretsmanager/verifiers/internal/docker"
)

// Pinned by the digest of the multi-platform index.
const (
	envoyImage = "envoyproxy/envoy:v1.39.4@sha256:74bd4eb5629708d3fadca1a5e6b85d208f338d7bb54e06b69565905c5294cc01"
	curlImage  = "curlimages/curl:8.22.0@sha256:58adaa4e8dca9c988bae2aba4ab3434a0bb2da16bbe3f92dec39ec7785166777"
)

const listenerTmpl = `
  - name: %[1]s
    address: {socket_address: {address: 0.0.0.0, port_value: %[2]d}}
    filter_chains:
    - transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
          require_client_certificate: true
          common_tls_context:
            tls_certificates:
            - certificate_chain: {filename: /pki/server.chain.pem}
              private_key: {filename: /pki/server.key.pem}
            validation_context:
%[3]s
      filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: %[1]s
          route_config:
            virtual_hosts:
            - name: all
              domains: ["*"]
              routes:
              - match: {prefix: "/"}
                direct_response: {status: 200, body: {inline_string: "ok"}}
          http_filters:
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
`

const defaultValidator = `              trusted_ca: {filename: /pki/root.pem}
              match_typed_subject_alt_names:
              - san_type: URI
                matcher: {prefix: "spiffe://"}`

func spiffeValidator() string {
	var b strings.Builder
	b.WriteString(`              custom_validator_config:
                name: envoy.tls.cert_validator.spiffe
                typed_config:
                  "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.SPIFFECertValidatorConfig
                  trust_domains:
`)
	seen := map[string]bool{}
	for _, sp := range chains.ClientSpecs {
		if seen[sp.TrustDomain] {
			continue
		}
		seen[sp.TrustDomain] = true
		fmt.Fprintf(&b, "                  - {name: %s, trust_bundle: {filename: /pki/root.pem}}\n", sp.TrustDomain)
	}
	return strings.TrimRight(b.String(), "\n")
}

var validators = []struct {
	name string
	port int
	conf string
}{
	{"default", 10000, defaultValidator},
	{"spiffe", 10001, spiffeValidator()},
}

func TestEnvoy(t *testing.T) {
	docker.Require(t)
	dir := t.TempDir()
	s := chains.New(t)
	s.Write(t, dir)

	conf := "static_resources:\n  listeners:\n"
	for _, v := range validators {
		conf += fmt.Sprintf(listenerTmpl, v.name, v.port, v.conf)
	}
	if err := os.WriteFile(filepath.Join(dir, "envoy.yaml"), []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}

	net := docker.Network(t)
	srv := docker.Name("envoy")
	docker.Start(t, srv, "--network", net, "--network-alias", chains.ServerName,
		"-v", dir+":/pki:ro", envoyImage,
		"-c", "/pki/envoy.yaml", "--log-level", "info", "--component-log-level", "connection:debug")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	curl := func(port int, id string) (string, error) {
		return docker.Once(ctx, "--network", net, "-v", dir+":/pki:ro", curlImage,
			"-sS", "--max-time", "10",
			"--cacert", "/pki/root.pem",
			"--cert", "/pki/"+id+".chain.pem", "--key", "/pki/"+id+".key.pem",
			fmt.Sprintf("https://%s:%d/", chains.ServerName, port))
	}
	docker.WaitFor(t, "envoy", time.Minute, func() error {
		out, err := curl(10000, "E-A")
		if err != nil || out != "ok" {
			return fmt.Errorf("%v: %s", err, out)
		}
		return nil
	})

	for _, v := range validators {
		t.Run(v.name, func(t *testing.T) {
			r := chains.NewResults(t, "envoy/"+v.name, nil)
			for _, l := range s.Clients {
				before := logLines(t, srv)
				out, err := curl(v.port, l.Spec.ID)
				if err == nil && out == "ok" {
					r.Record(l.Spec, chains.Accepted, "")
					continue
				}
				// Envoy says why it refused the certificate in its connection
				// log; curl only sees the alert.
				detail := docker.LastLine(out, "curl:")
				if why := newVerifyError(t, srv, before); why != "" {
					detail = "envoy: " + why + "; " + detail
				}
				r.Record(l.Spec, chains.Rejected, detail)
			}
		})
	}
}

func logLines(t *testing.T, name string) int {
	return len(strings.Split(docker.Must(t, "logs", name), "\n"))
}

// newVerifyError is the first certificate verification message Envoy logged
// after line `from`.
func newVerifyError(t *testing.T, name string, from int) string {
	time.Sleep(200 * time.Millisecond)
	lines := strings.Split(docker.Must(t, "logs", name), "\n")
	if from > len(lines) {
		from = len(lines)
	}
	for _, l := range lines[from:] {
		for _, k := range []string{"verify cert failed", "CERTIFICATE_VERIFY_FAILED"} {
			if i := strings.Index(l, k); i >= 0 {
				return strings.TrimSuffix(strings.TrimSpace(l[i:]), ":TLS_error_end")
			}
		}
	}
	return ""
}
