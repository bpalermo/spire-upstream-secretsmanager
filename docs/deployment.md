# Deployment

## The rotator Lambda (Terraform)

A minimal example, with placeholder ARNs:

```hcl
locals {
  root_key_arn = "arn:aws:kms:us-east-1:111122223333:key/00000000-0000-0000-0000-000000000000"
  secret_cmk   = "arn:aws:kms:us-east-1:111122223333:key/11111111-1111-1111-1111-111111111111"
  version      = "0.1.0"
  zip          = "kms-intermediate-rotator_${local.version}_linux_arm64.zip"
}

resource "aws_secretsmanager_secret" "intermediate" {
  name       = "example-intermediate-ca"
  kms_key_id = local.secret_cmk
}

# A placeholder first version: the first rotation replaces it.
resource "aws_secretsmanager_secret_version" "placeholder" {
  secret_id     = aws_secretsmanager_secret.intermediate.id
  secret_string = "{}"
  lifecycle { ignore_changes = [secret_string] }
}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "rotator" {
  statement {
    actions   = ["kms:GetPublicKey", "kms:Sign"]
    resources = [local.root_key_arn]
  }
  statement {
    actions = [
      "secretsmanager:DescribeSecret",
      "secretsmanager:GetSecretValue",
      "secretsmanager:PutSecretValue",
      "secretsmanager:UpdateSecretVersionStage",
    ]
    resources = [aws_secretsmanager_secret.intermediate.arn]
  }
  statement {
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [local.secret_cmk]
  }
}

resource "aws_iam_role" "rotator" {
  name               = "kms-intermediate-rotator"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

resource "aws_iam_role_policy" "rotator" {
  role   = aws_iam_role.rotator.id
  policy = data.aws_iam_policy_document.rotator.json
}

resource "aws_iam_role_policy_attachment" "logs" {
  role       = aws_iam_role.rotator.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_lambda_function" "rotator" {
  function_name = "kms-intermediate-rotator"
  role          = aws_iam_role.rotator.arn
  runtime       = "provided.al2023"
  architectures = ["arm64"]
  handler       = "bootstrap"
  # From the GitHub Release; verify checksums.txt first (see releases.md).
  filename         = local.zip
  source_code_hash = filebase64sha256(local.zip)
  timeout          = 30
  memory_size      = 256

  environment {
    variables = {
      ROTATOR_CONFIG = jsonencode({
        kms_key_id       = local.root_key_arn
        root_certificate = file("root.pem")
        secrets = {
          (aws_secretsmanager_secret.intermediate.arn) = {
            subject  = { common_name = "Example Intermediate CA", organization = ["Example"] }
            validity = "2160h"
            # SPIRE's CA is one CA below the intermediate.
            max_path_len = 1
            name_constraints = {
              permitted_uri_domains = ["example.org"]
              excluded_uri_domains  = [".example.org"]
            }
          }
        }
      })
    }
  }
}

resource "aws_lambda_permission" "secretsmanager" {
  statement_id   = "AllowSecretsManager"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.rotator.function_name
  principal      = "secretsmanager.amazonaws.com"
  source_account = "111122223333"
}

resource "aws_secretsmanager_secret_rotation" "intermediate" {
  secret_id           = aws_secretsmanager_secret.intermediate.id
  rotation_lambda_arn = aws_lambda_function.rotator.arn
  rotation_rules {
    # Well inside the 90-day validity, so a failed rotation has time to be
    # noticed before the current intermediate expires.
    schedule_expression = "rate(30 days)"
  }
  depends_on = [aws_lambda_permission.secretsmanager, aws_secretsmanager_secret_version.placeholder]
}
```

## The plugin

The release publishes static plugin binaries for linux/amd64 and linux/arm64,
listed in `checksums.txt` (the SHA-256 is SPIRE's `plugin_checksum`), and a
multi-arch image `quay.io/palermo/spire-upstream-secretsmanager` that contains
only `/upstream-secretsmanager` (no shell, no libc). The checksum differs per
architecture; use the one of the nodes the server runs on.

### SPIRE Helm chart (`customPlugins`)

With the [hardened SPIRE Helm chart](https://github.com/spiffe/helm-charts-hardened),
declare it as a custom plugin; the chart copies `plugin_cmd` out of the image
into the server pod and points SPIRE at the copy:

```yaml
spire-server:
  customPlugins:
    upstreamAuthority:
      secretsmanager:
        image:
          registry: quay.io
          repository: palermo/spire-upstream-secretsmanager
          tag: "<version>"
        plugin_cmd: /upstream-secretsmanager
        plugin_checksum: "<SHA-256 of upstream-secretsmanager for the nodes' architecture>"
        plugin_data:
          region: us-east-1
          secret_id: arn:aws:secretsmanager:us-east-1:111122223333:secret:example
          cache_path: /run/spire/data/upstream-secretsmanager.json
          root_sha256:
            - "<hex SHA-256 of the root certificate's DER>"
```

`/run/spire/data` is the chart's persistent volume, so the cache survives a
restart. Give the server's service account the
[IAM permissions](plugin.md#plugin-iam-permissions) (for example with IRSA).

### Kubernetes image volume

On Kubernetes with image volumes (the `ImageVolume` feature), mount the image
straight into the SPIRE server pod:

```yaml
spec:
  containers:
    - name: spire-server
      volumeMounts:
        - name: upstream-secretsmanager
          mountPath: /opt/spire/plugins/secretsmanager
          readOnly: true
  volumes:
    - name: upstream-secretsmanager
      image:
        reference: quay.io/palermo/spire-upstream-secretsmanager:<version>
        pullPolicy: IfNotPresent
```

and set `plugin_cmd = "/opt/spire/plugins/secretsmanager/upstream-secretsmanager"`.

### Docker Compose

The image has no shell, so it installs itself: `upstream-secretsmanager
install <dir>` copies its own executable to `<dir>/upstream-secretsmanager`
with mode 0755 and exits.

```yaml
services:
  install-upstream-secretsmanager:
    image: quay.io/palermo/spire-upstream-secretsmanager:<version>
    command: ["install", "/plugins"]
    volumes:
      - plugins:/plugins

  spire-server:
    image: ghcr.io/spiffe/spire-server:1.15.5
    depends_on:
      install-upstream-secretsmanager:
        condition: service_completed_successfully
    volumes:
      - plugins:/opt/spire/plugins:ro
      - ./server.conf:/opt/spire/conf/server/server.conf:ro
      - spire-data:/opt/spire/data
    # plugin_cmd = "/opt/spire/plugins/upstream-secretsmanager"

volumes:
  plugins: {}
  spire-data: {}
```
