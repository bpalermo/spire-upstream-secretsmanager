package plugin_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"

	"github.com/bpalermo/spire-upstream-secretsmanager/internal/fakesm"
	"github.com/bpalermo/spire-upstream-secretsmanager/internal/testpki"
	"github.com/bpalermo/spire-upstream-secretsmanager/pkg/plugin"
)

// isolateAWSEnv points the AWS SDK at static test credentials and away from
// any configuration of the machine running the test.
func isolateAWSEnv(t *testing.T) {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "example")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_CONFIG_FILE", "/dev/null")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
}

func TestNewSecretsManagerClientUsesEndpoint(t *testing.T) {
	isolateAWSEnv(t)
	srv := fakesm.New(map[string]string{secretID: "hello"})
	defer srv.Close()

	client, err := plugin.NewSecretsManagerClient(context.Background(), plugin.Config{Region: "us-east-1", Endpoint: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if len(srv.Requests()) != 0 {
		t.Fatal("building the client called AWS")
	}
	out, err := client.GetSecretValue(context.Background(), &secretsmanager.GetSecretValueInput{SecretId: aws.String(secretID), VersionStage: aws.String("AWSCURRENT")})
	if err != nil {
		t.Fatalf("GetSecretValue: %v", err)
	}
	if aws.ToString(out.SecretString) != "hello" {
		t.Fatalf("SecretString = %q", aws.ToString(out.SecretString))
	}
	reqs := srv.Requests()
	if len(reqs) != 1 || reqs[0].VersionStage != "AWSCURRENT" || !strings.Contains(reqs[0].Authorization, "AKIAEXAMPLE") {
		t.Fatalf("requests = %+v", reqs)
	}
}

func TestNewSecretsManagerClientAssumeRoleIsLazy(t *testing.T) {
	isolateAWSEnv(t)
	// Building a client that assumes a role makes no STS call either.
	if _, err := plugin.NewSecretsManagerClient(context.Background(), plugin.Config{
		Region:        "us-east-1",
		AssumeRoleARN: "arn:aws:iam::111122223333:role/example",
	}); err != nil {
		t.Fatal(err)
	}
}

func TestMintThroughTheAWSSDK(t *testing.T) {
	isolateAWSEnv(t)
	p := testpki.New(t, testpki.Options{})
	srv := fakesm.New(map[string]string{secretID: p.V1(t)})
	defer srv.Close()

	h := servePlugin(t, plugin.New())
	h.mustConfigure(t, v1Config(fmt.Sprintf("endpoint = %q\n", srv.URL)))
	if len(srv.Requests()) != 0 {
		t.Fatal("Configure called Secrets Manager")
	}
	chain, roots := h.mustMint(t)
	if !chain[1].Equal(p.Intermediate.Cert) || !roots[0].Equal(p.Root.Cert) {
		t.Fatal("wrong chain or roots")
	}
	if n := len(srv.Requests()); n != 1 {
		t.Fatalf("%d requests, want 1", n)
	}
}
