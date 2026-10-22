package plugin

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// currentStage is the version stage the plugin reads.
const currentStage = "AWSCURRENT"

// SecretsClient is the part of the Secrets Manager API the plugin uses.
type SecretsClient interface {
	GetSecretValue(ctx context.Context, in *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

// NewClientFunc builds the Secrets Manager client for a configuration. It
// must not call AWS: credentials are resolved on the first request.
type NewClientFunc func(ctx context.Context, cfg Config) (SecretsClient, error)

// NewSecretsManagerClient builds a Secrets Manager client from the default
// AWS configuration (environment, shared config and credentials files, web
// identity, container and instance metadata endpoints, credential_process),
// with the configured region and endpoint, assuming assume_role_arn if set,
// as SPIRE's awssecret plugin does. LoadDefaultConfig makes no request, so
// neither does this.
func NewSecretsManagerClient(ctx context.Context, cfg Config) (SecretsClient, error) {
	var opts []func(*awsconfig.LoadOptions) error
	if cfg.Region != "" {
		opts = append(opts, awsconfig.WithRegion(cfg.Region))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, err
	}
	if cfg.AssumeRoleARN != "" {
		stsClient := sts.NewFromConfig(awsCfg)
		opts = append(opts, awsconfig.WithCredentialsProvider(aws.NewCredentialsCache(
			stscreds.NewAssumeRoleProvider(stsClient, cfg.AssumeRoleARN))))
		if awsCfg, err = awsconfig.LoadDefaultConfig(ctx, opts...); err != nil {
			return nil, err
		}
	}
	return secretsmanager.NewFromConfig(awsCfg, func(o *secretsmanager.Options) {
		if cfg.Endpoint != "" {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
		}
	}), nil
}

// readSecret returns the SecretString of the AWSCURRENT version of a secret.
func readSecret(ctx context.Context, sm SecretsClient, id string) (string, error) {
	out, err := sm.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(id),
		VersionStage: aws.String(currentStage),
	})
	if err != nil {
		return "", err
	}
	if out == nil || out.SecretString == nil {
		return "", errors.New("response or SecretString is nil")
	}
	return *out.SecretString, nil
}
