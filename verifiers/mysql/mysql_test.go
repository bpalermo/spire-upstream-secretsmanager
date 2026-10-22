// Package mysql_test runs every client chain of package chains against a
// MySQL 8.4 server (OpenSSL 3) whose ssl_ca is the root, as a user that
// REQUIRE SUBJECT matches the leaves' subject. The client is the mysql CLI
// of the same image, presenting the leaf, SPIRE CA and intermediate. Needs a
// local Docker daemon.
//
// mysqld gives no reason for a refused certificate (its log says "Bad
// handshake" at verbosity 3), so a rejection's detail also has what `openssl
// verify` of the image's own OpenSSL says about the same chain.
package mysql_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/bpalermo/spire-upstream-secretsmanager/verifiers/chains"
	"github.com/bpalermo/spire-upstream-secretsmanager/verifiers/internal/docker"
)

// Pinned by the digest of the multi-platform index.
const mysqlImage = "mysql:8.4.13@sha256:76f0358884cb92d9a086d24e5671c38048d3fef40f2588703d73eb55392d6b69"

// The subject every client leaf has, in the form REQUIRE SUBJECT compares.
const subject = "/O=Example/CN=workload"

func TestMySQL(t *testing.T) {
	docker.Require(t)
	dir := t.TempDir()
	s := chains.New(t)
	s.Write(t, dir)

	srv := docker.Name("mysql")
	docker.Start(t, srv, "-e", "MYSQL_ROOT_PASSWORD=verifier", "-v", dir+":/pki:ro", mysqlImage,
		"--ssl-ca=/pki/root.pem",
		"--ssl-cert=/pki/server.chain.pem",
		"--ssl-key=/pki/server.key.pem",
		"--require-secure-transport=ON",
		"--log-error-verbosity=3")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	root := func(sql string) (string, error) {
		return docker.Run(ctx, "exec", srv, "mysql", "-uroot", "-pverifier", "-N", "-e", sql)
	}
	// The entrypoint starts a temporary server for initialisation first; the
	// real one listens on TCP 3306.
	docker.WaitFor(t, "mysql", 3*time.Minute, func() error {
		out, err := docker.Run(ctx, "exec", srv, "mysql", "-uroot", "-pverifier", "--protocol=TCP", "-h127.0.0.1", "-N", "-e", "SELECT 1")
		if err != nil {
			return fmt.Errorf("%v: %s", err, out)
		}
		return nil
	})
	if out, err := root("CREATE USER 'w'@'%' REQUIRE SUBJECT '" + subject + "'"); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if out, err := root("SELECT @@version"); err == nil {
		lib, _ := docker.Run(ctx, "exec", srv, "rpm", "-q", "openssl-libs")
		t.Logf("server: MySQL %s, %s", docker.LastLine(out), lib)
	}

	r := chains.NewResults(t, "mysql", nil)
	for _, l := range s.Clients {
		out, err := docker.Run(ctx, "exec", srv, "mysql", "--protocol=TCP", "-h127.0.0.1", "-uw", "-N",
			"--ssl-mode=VERIFY_CA", "--ssl-ca=/pki/root.pem",
			"--ssl-cert=/pki/"+l.Spec.ID+".chain.pem", "--ssl-key=/pki/"+l.Spec.ID+".key.pem",
			"-e", "SELECT CURRENT_USER()")
		if err == nil && strings.Contains(out, "w@%") {
			r.Record(l.Spec, chains.Accepted, "")
			continue
		}
		// The client sees only a dropped connection, and the server logs only
		// "Bad handshake", so the reason comes from the OpenSSL of the same
		// image, verifying the same chain the same way.
		why, _ := docker.Run(ctx, "exec", srv, "openssl", "verify", "-purpose", "sslclient",
			"-CAfile", "/pki/root.pem", "-untrusted", "/pki/"+l.Spec.ID+".untrusted.pem", "/pki/"+l.Spec.ID+".cert.pem")
		r.Record(l.Spec, chains.Rejected, docker.LastLine(out, "ERROR")+"; openssl verify: "+docker.LastLine(why, "depth lookup"))
	}
}
