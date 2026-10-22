// Package kafka_test runs the chains of package chains through Apache
// Kafka's TLS (the JDK's PKIX validator) in both directions:
//
//   - client auth: a KRaft broker with an SSL listener, ssl.client.auth =
//     required and the root as its PEM truststore; the Java client of the same
//     image presents each client chain;
//   - server auth: the client (holding an unconstrained client chain) checks
//     broker certificates issued under the constrained intermediate, with
//     hostname verification (ssl.endpoint.identification.algorithm = https,
//     the default) against the broker's DNS SAN: case D on the server side.
//
// Needs a local Docker daemon.
package kafka_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/bpalermo/spire-upstream-secretsmanager/verifiers/chains"
	"github.com/bpalermo/spire-upstream-secretsmanager/verifiers/internal/docker"
)

// Pinned by the digest of the multi-platform index.
const kafkaImage = "apache/kafka:4.3.1@sha256:77e3df9054047a88b520d0cc46e16696d3b22022e1d580aeccd2632df6532837"

const clusterID = "U3VzbVZlcmlmaWVyMDAwMQ"

const brokerProps = `process.roles=broker,controller
node.id=1
controller.quorum.bootstrap.servers=localhost:9094
controller.listener.names=CONTROLLER
listeners=SSL://:9093,INTERNAL://:9092,CONTROLLER://:9094
advertised.listeners=SSL://%[1]s:9093,INTERNAL://localhost:9092
listener.security.protocol.map=SSL:SSL,INTERNAL:PLAINTEXT,CONTROLLER:PLAINTEXT
inter.broker.listener.name=INTERNAL
log.dirs=/tmp/kraft
offsets.topic.replication.factor=1
transaction.state.log.replication.factor=1
transaction.state.log.min.isr=1
ssl.client.auth=required
ssl.keystore.type=PEM
ssl.keystore.location=/pki/%[2]s.bundle.pem
ssl.truststore.type=PEM
ssl.truststore.location=/pki/root.pem
`

const clientProps = `security.protocol=SSL
ssl.truststore.type=PEM
ssl.truststore.location=/pki/root.pem
ssl.keystore.type=PEM
ssl.keystore.location=/pki/%s.bundle.pem
`

type broker struct {
	t    *testing.T
	ctx  context.Context
	dir  string
	net  string
	name string
	host string
}

// startBroker runs a broker presenting the server certificate certID, under
// the network alias host.
func startBroker(t *testing.T, ctx context.Context, dir, net, certID, host string) *broker {
	b := &broker{t: t, ctx: ctx, dir: dir, net: net, name: docker.Name("kafka"), host: host}
	props := "broker-" + certID + ".properties"
	write(t, dir, props, fmt.Sprintf(brokerProps, host, certID))
	docker.Start(t, b.name, "--network", net, "--network-alias", host, "-v", dir+":/pki:ro",
		"-e", "KAFKA_OPTS=-Djavax.net.debug=ssl:handshake",
		"--entrypoint", "sh", kafkaImage, "-c",
		"/opt/kafka/bin/kafka-storage.sh format --standalone -t "+clusterID+" -c /pki/"+props+
			" && exec /opt/kafka/bin/kafka-server-start.sh /pki/"+props)
	docker.WaitFor(t, "kafka", 2*time.Minute, func() error {
		logs, _ := docker.Run(ctx, "logs", b.name)
		if !strings.Contains(logs, "Kafka Server started") {
			return fmt.Errorf("not started yet")
		}
		return nil
	})
	return b
}

// produce sends one record as the client chain clientID and returns whether
// the broker took it, and the error line otherwise.
func (b *broker) produce(clientID string) (bool, string) {
	props := "client-" + clientID + ".properties"
	write(b.t, b.dir, props, fmt.Sprintf(clientProps, clientID))
	out, err := docker.Once(b.ctx, "--network", b.net, "-v", b.dir+":/pki:ro", "--entrypoint", "sh", kafkaImage, "-c",
		"echo verifier | /opt/kafka/bin/kafka-console-producer.sh --bootstrap-server "+b.host+":9093"+
			" --topic verifier --producer.config /pki/"+props+
			" --producer-property max.block.ms=20000 --producer-property delivery.timeout.ms=25000"+
			" --producer-property request.timeout.ms=20000 --producer-property linger.ms=0 --producer-property acks=1")
	if err == nil && !strings.Contains(out, "ERROR") {
		return true, ""
	}
	return false, reason(out)
}

var causeRE = regexp.MustCompile(`(?:CertPathValidatorException|SSLHandshakeException|CertificateException|SslAuthenticationException)[^\n]*`)

// reason is the most specific exception message of a client's output.
func reason(out string) string {
	m := causeRE.FindAllString(out, -1)
	if len(m) == 0 {
		return docker.LastLine(out, "ERROR", "Exception")
	}
	best := m[0]
	for _, s := range m {
		if strings.Contains(s, "CertPathValidatorException") || strings.Contains(s, "No subject alternative") {
			best = s
		}
	}
	return strings.TrimSpace(best)
}

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestKafka(t *testing.T) {
	docker.Require(t)
	dir := t.TempDir()
	s := chains.New(t)
	s.Write(t, dir)
	net := docker.Network(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	t.Run("client-auth", func(t *testing.T) {
		b := startBroker(t, ctx, dir, net, "server", chains.ServerName)
		if v, err := docker.Run(ctx, "exec", b.name, "java", "-version"); err == nil {
			t.Logf("broker JDK: %s", strings.ReplaceAll(v, "\n", " | "))
		}
		r := chains.NewResults(t, "kafka/client-auth", nil)
		accepted := 0
		for _, l := range s.Clients {
			before, _ := docker.Run(ctx, "logs", b.name)
			ok, why := b.produce(l.Spec.ID)
			after, _ := docker.Run(ctx, "logs", b.name)
			if !ok {
				// The client sees only the alert; the broker's JSSE debug log
				// (javax.net.debug=ssl:handshake) says why it sent it.
				if f := docker.LastLine(after[min(len(before), len(after)):], "Fatal ("); strings.Contains(f, "Fatal (") {
					why = "broker: " + strings.TrimSuffix(f[strings.Index(f, "Fatal ("):], " (") + "; client: " + why
				}
			}
			if ok {
				accepted++
				r.Record(l.Spec, chains.Accepted, "")
			} else {
				r.Record(l.Spec, chains.Rejected, why)
			}
		}
		// An accepted chain is one whose record reached the log: count them
		// over the broker's plaintext loopback listener.
		out, err := docker.Run(ctx, "exec", b.name, "/opt/kafka/bin/kafka-get-offsets.sh",
			"--bootstrap-server", "localhost:9092", "--topic", "verifier")
		if want := fmt.Sprintf("verifier:0:%d", accepted); err != nil || !strings.Contains(out, want) {
			t.Errorf("offsets: got %q (%v), want %s", out, err, want)
		}
	})

	t.Run("server-auth", func(t *testing.T) {
		r := chains.NewResults(t, "kafka/server-auth", nil)
		for _, sp := range chains.ServerSpecs[1:] {
			b := startBroker(t, ctx, dir, net, sp.ID, sp.DNS[0])
			ok, why := b.produce("E-A")
			if ok {
				r.Record(sp, chains.Accepted, "")
			} else {
				r.Record(sp, chains.Rejected, why)
			}
			_, _ = docker.Run(ctx, "rm", "-f", b.name)
		}
	})
}
