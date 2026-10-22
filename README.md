# spire-upstream-secretsmanager

An intermediate CA for [SPIRE](https://spiffe.io/) that lives in AWS Secrets
Manager, is rotated by a Lambda that signs it with a root key held in AWS KMS,
and is read by the SPIRE server **at every mint**. Three components, built,
tested and released together from this repository:

| Component | Directory | What it is | Released as |
| --- | --- | --- | --- |
| **upstream-secretsmanager** | [`upstream-secretsmanager/`](upstream-secretsmanager) | A SPIRE UpstreamAuthority plugin that reads its intermediate CA from Secrets Manager at every mint, with a validated local cache. | static binaries (linux/amd64, linux/arm64) and the image `quay.io/palermo/spire-upstream-secretsmanager` |
| **kms-intermediate-rotator** | [`rotator/`](rotator) | A Secrets Manager rotation Lambda that issues a name-constrained intermediate CA signed by a KMS key. | `kms-intermediate-rotator_<version>_linux_<arch>.zip` |
| **intermediate-ca/v1** | [`intermediateca/`](intermediateca) | The secret format the two share: a JSON document, its protobuf schema, and the Go package that reads and writes it. | the Go package `github.com/bpalermo/spire-upstream-secretsmanager/intermediateca` |

```text
 AWS KMS key (root, never leaves KMS)
      | Sign
      v
 rotator Lambda --PutSecretValue--> Secrets Manager secret (intermediate-ca/v1)
                                         | GetSecretValue AWSCURRENT, at every mint
                                         v
                    SPIRE server + upstream-secretsmanager plugin
                                         | signs
                                         v
                        SPIRE CA --> X509-SVIDs (chain to the KMS root)
```

Each piece works without the others: the plugin reads any secret in the
format (or SPIRE's `awssecret` three-secret layout), the rotator writes one for
any reader, and the format is specified in
[docs/secret-format.md](docs/secret-format.md) for implementations in any
language.

> This repository supersedes
> [bpalermo/kms-intermediate-rotator](https://github.com/bpalermo/kms-intermediate-rotator)
> and
> [bpalermo/intermediate-ca-format](https://github.com/bpalermo/intermediate-ca-format),
> whose code now lives here (`rotator/` and its libraries, `intermediateca/`).
> Those repositories are kept for their history and receive no further
> changes.

## Quick start

1. **The root.** Create an asymmetric `SIGN_VERIFY` KMS key (`ECC_NIST_P384`,
   say) and a self-signed root CA certificate for it, made once with any tool
   that signs through KMS (for example smallstep's `step-kms-plugin`). Give
   the root a path length of at least 2: the intermediate is one CA below it
   and SPIRE's own CA one below that.
2. **The rotator.** Create the secret, deploy the Lambda with the root
   certificate and the secret in its [configuration](#rotator-configuration),
   and turn rotation on ([Terraform example](#the-rotator-lambda-terraform)).
   The first rotation replaces the placeholder value with an intermediate.
3. **The plugin.** Pin the root (`root_sha256`, the SHA-256 of its DER:
   `openssl x509 -in root.pem -outform DER | sha256sum`) and install the
   plugin in the SPIRE server ([Helm](#spire-helm-chart-customplugins),
   [image volume](#kubernetes-image-volume) or
   [Docker Compose](#docker-compose)), with `secret_id` set to the secret.
4. Every SVID SPIRE mints now chains to the KMS root through the current
   intermediate, and the next rotation is used from SPIRE's next CA rotation
   on, without a restart.

## upstream-secretsmanager: the SPIRE plugin

An external SPIRE plugin (built on the
[SPIRE plugin SDK](https://github.com/spiffe/spire-plugin-sdk)): one statically
linked binary, `upstream-secretsmanager`, that the SPIRE server executes.

### Why

SPIRE's built-in
[`awssecret`](https://github.com/spiffe/spire/blob/main/doc/plugin_server_upstreamauthority_awssecret.md)
UpstreamAuthority reads the upstream CA from Secrets Manager once, when the
server starts. An intermediate CA that is rotated in Secrets Manager (by the
rotator, for example) is not picked up until every SPIRE server restarts, and
a server that starts while AWS is unreachable does not start at all.

This plugin:

- reads the `AWSCURRENT` version of the secret every time SPIRE asks for a new
  X.509 CA, so a rotated (or emergency-replaced) intermediate is used from the
  next CA rotation on, without a restart;
- makes no AWS call when it is configured, so SPIRE starts with AWS
  unreachable;
- validates what it reads (key matches certificate, certificate is a CA, it
  verifies to a pinned root through the chain, it can sign a CA for the trust
  domain that SPIRE will accept, enough lifetime left) and keeps the last good
  copy in memory and, optionally, on disk, falling back to it when Secrets
  Manager cannot be read or returns something invalid.

Everything else behaves as SPIRE's built-in `disk` and `awssecret` plugins do:
the CSR checks, the certificate template of the minted CA, the response
layout, and JWT-SVID publishing and `SubscribeToLocalBundle` being
unsupported.

### Plugin configuration

```hcl
UpstreamAuthority "secretsmanager" {
  plugin_cmd      = "/opt/spire/plugins/upstream-secretsmanager"
  plugin_checksum = "<SHA-256 of the binary, from the release's checksums.txt>"
  plugin_data {
    region        = "us-east-1"
    secret_id     = "arn:aws:secretsmanager:us-east-1:111122223333:secret:example"
    cache_path    = "/opt/spire/data/server/upstream-secretsmanager.json"
    root_sha256   = "<hex SHA-256 of the root certificate's DER>"
    fetch_timeout = "10s"
    min_remaining = "1h"
  }
}
```

| Key | Default | Meaning |
| --- | --- | --- |
| `region` | from the AWS environment | AWS region of the secret. |
| `endpoint` | the regional endpoint | Secrets Manager endpoint URL. Meant for tests. |
| `assume_role_arn` | none | Role to assume (with STS `AssumeRole`) on top of the default credentials, as `awssecret` does. |
| `secret_id` | | ARN or name of a secret in [format v1](docs/secret-format.md). |
| `cert_file_arn`, `key_file_arn`, `bundle_file_arn` | | Instead of `secret_id`: the three-secret layout of `awssecret`, each secret's `SecretString` being PEM, read exactly as `awssecret` reads them. `cert_file_arn` holds the CA certificate, optionally followed by intermediates; `key_file_arn` its key; `bundle_file_arn` the root(s). `bundle_file_arn` may be left out only if `cert_file_arn` is one self-signed certificate. |
| `cache_path` | none | File where the last good intermediate is kept (format v1, mode 0600). Optional but recommended: without it a restarted server cannot mint while Secrets Manager is unreachable. |
| `root_sha256` | **required** | Hex SHA-256 of the root certificate's DER, or a list of them. An intermediate under any other root is refused, whether read from Secrets Manager or from the cache. A list stages a root rotation: pin the new root next to the old one, then switch the secret. |
| `fetch_timeout` | `10s` | Time limit for the Secrets Manager reads of one mint. It is also the timeout of every HTTP request of the AWS client (Secrets Manager, STS and the other credential endpoints), so a hung request cannot outlive a mint. |
| `min_remaining` | `1h` | An intermediate (fetched or cached) with less than this left before its `NotAfter` is not used. |

Set either `secret_id` or the `awssecret` layout, not both. Unknown keys are
refused, so a misspelt key (`root_sha265`) fails the configuration instead of
disabling a check. The SPIRE server's `trust_domain` is used to check CSRs and
the intermediate.

`root_sha256` is required because anyone who can write the secret
(`secretsmanager:PutSecretValue`) could otherwise install a trust anchor of
their own, which SPIRE would add to its bundle. To rotate the root, configure
both pins:

```hcl
root_sha256 = [
  "<hex SHA-256 of the current root>",
  "<hex SHA-256 of the next root>",
]
```

A change of the root actually in use is logged at WARN.

Credentials come from the AWS SDK's default chain: environment variables, the
shared config and credentials files (profiles, `credential_process`), web
identity (`AWS_WEB_IDENTITY_TOKEN_FILE`, so IRSA works), the container
credentials endpoint (ECS, EKS Pod Identity) and the EC2 instance metadata
service (`AWS_EC2_METADATA_SERVICE_ENDPOINT` is honoured). The plugin runs
with the SPIRE server's environment.

### Plugin IAM permissions

The plugin only reads. On the one secret (each of the three, with the
`awssecret` layout):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "secretsmanager:GetSecretValue",
      "Resource": "arn:aws:secretsmanager:us-east-1:111122223333:secret:example-*"
    },
    {
      "Effect": "Allow",
      "Action": "kms:Decrypt",
      "Resource": "arn:aws:kms:us-east-1:111122223333:key/00000000-0000-0000-0000-000000000000",
      "Condition": {
        "StringEquals": { "kms:ViaService": "secretsmanager.us-east-1.amazonaws.com" }
      }
    }
  ]
}
```

`kms:Decrypt` is for the customer managed key that encrypts the secret; it is
not needed if the secret uses the AWS managed key `aws/secretsmanager`. With
`assume_role_arn`, the caller also needs `sts:AssumeRole` on that role, and
the role gets the permissions above.

### Behaviour at each mint

When SPIRE prepares a new X.509 CA, the plugin:

1. reads the `AWSCURRENT` version of the secret(s), within `fetch_timeout`;
2. validates it: format v1 (or the `awssecret` layout), the key matches the
   certificate, the certificate is a CA and verifies to the root through the
   chain, the root is one of `root_sha256`, at least `min_remaining` is left,
   and the intermediate can actually be used: the plugin signs a throwaway CA
   for `spiffe://<trust domain>` with it and a throwaway X509-SVID under that
   CA, and verifies the SVID through `[CA, intermediate, chain...]` to the
   root, as SPIRE checks every CA an UpstreamAuthority returns. An
   intermediate whose path length or name constraints leave no room for the
   SPIRE CA is therefore refused here, and does not replace the cache;
3. on success, writes it to `cache_path` (atomically: a temporary file in the
   same directory, fsync, rename, fsync of the directory; mode 0600) and uses
   it. On failure, it logs a warning with the reason and uses the last good
   copy (the last one fetched, or the one loaded from `cache_path` at startup)
   if that still passes step 2 at the current time; if there is none, the
   mint fails and SPIRE retries;
4. signs SPIRE's CSR as SPIRE's own `disk` plugin does: the CSR's signature
   must be valid and its only URI SAN must be `spiffe://<trust domain>`; the
   CA is valid from 10 seconds ago until now plus SPIRE's preferred TTL (1
   hour if SPIRE gives none), but never after the intermediate's `NotAfter`;
5. returns the chain `[new CA, intermediate, chain...]` and the upstream
   roots: `[root]` for format v1; the whole `bundle_file_arn` bundle with the
   `awssecret` layout, as `awssecret` does (the chain must still verify to a
   pinned root in it). When the CA from the `awssecret` layout is
   self-signed, the chain is `[new CA]` and the root is that CA, as with
   `awssecret`.

At startup (Configure) the plugin only parses the configuration and loads
`cache_path` if it exists; an invalid, unpinned or expiring cache is ignored
with a warning. A later Configure without a valid cache keeps the in-memory
last good copy, which is validated against the new configuration when it is
used.

Beyond what [the specification](docs/secret-format.md) requires of every
reader, the plugin refuses an intermediate whose root is not one of
`root_sha256`, one with less than `min_remaining` of its lifetime left, and
one that cannot sign a CA for the SPIRE trust domain that SPIRE accepts (path
length, name constraints). The cache file is written in the same format; with
the awssecret layout it adds an `x_upstream_bundle` field holding the whole
bundle, which the plugin reads only from its cache, never from a secret.

### Cache and slack

The cache bounds how long SPIRE can keep minting while Secrets Manager is
unreachable: until the cached intermediate has less than `min_remaining` left.
With intermediates valid for 90 days that are rotated well before they expire,
an outage has weeks of slack. SPIRE's own CA is capped at the intermediate's
`NotAfter`, so an intermediate close to its end yields correspondingly short
CAs; `min_remaining` sets the point where the plugin stops using it. Choose
`min_remaining` at least as large as SPIRE's `ca_ttl` if every CA must get its
full lifetime.

## kms-intermediate-rotator: the rotation Lambda

An AWS Secrets Manager rotation Lambda that keeps a name-constrained
intermediate CA, signed by an AWS KMS key, in a secret. The root CA's private
key stays in KMS. On each rotation the Lambda generates a new intermediate
key, builds the intermediate certificate from its own configuration, has KMS
sign it, and stores certificate, key and root in the secret in the
[`intermediate-ca/v1` format](docs/secret-format.md). Whatever consumes the
intermediate reads the secret's `AWSCURRENT` version; the rotator knows
nothing about it.

It runs on the `provided.al2023` custom runtime, arm64 or x86_64, as the
executable `bootstrap`.

### Rotation flow

Secrets Manager invokes the function four times per rotation, with
`{"SecretId", "ClientRequestToken", "Step"}` and, when the function rotates
through an assumed role or across accounts, a `RotationToken`, which is passed
on to `PutSecretValue` (and never logged). Before every step, as the AWS
rotation templates do, the function checks that the secret is in its
configuration (by full ARN; a `SecretId` given as a name is resolved with
`DescribeSecret`), that rotation is enabled on it and that the token is one of
its versions. If that version is already `AWSCURRENT` the step succeeds and
does nothing; if it is not `AWSPENDING` the step fails.

1. **createSecret**: if the `AWSPENDING` version of the token already has a
   value (a retry), it returns without signing again. Otherwise it generates a
   key, builds the certificate from the secret's configuration, signs it with
   KMS (`Sign`, `MessageType: DIGEST`, on the key ARN `GetPublicKey` resolved
   `kms_key_id` to at start), checks the signature against the root and that
   a chain as deep as its path length allows verifies, and writes the secret
   with `PutSecretValue` (the token, `VersionStages: [AWSPENDING]`). If a
   concurrent invocation for the same token stored its version first, that
   one is kept and the step succeeds.
2. **setSecret**: nothing; there is no service to configure.
3. **testSecret**: reads `AWSPENDING` and checks it as a reader would (the
   format's `Decode`: schema, key matches cert, cert is a CA and verifies to
   the root), that its root is the configured one, that subject, basic
   constraints, path length, key usage, name constraints and key type equal
   the configuration, that a throwaway chain as deep as its path length
   allows (sub-CAs and a leaf, made in memory) verifies to the root, and its
   lifetime:
   - measured from its issuance (`NotBefore` + 5m), it was given the
     configured `validity` (or up to the root's `NotAfter`, if sooner);
   - it has at least `min_remaining` (default half the validity) left now.

   So a rotation retried days later with the same `AWSPENDING` version still
   passes, and one whose pending version is mostly used up fails (see
   [Recovering a stuck rotation](#recovering-a-stuck-rotation)).

   A `testSecret` with nothing to test (the token is not a version of the
   secret, or its `AWSPENDING` version has no value) is the configuration test
   Secrets Manager runs when rotation is set up without rotating immediately:
   it succeeds, since the configuration and the KMS key were checked at start,
   and is logged as a configuration test. A pending version with a value is
   always tested in full.
4. **finishSecret**: moves `AWSCURRENT` to the token with
   `UpdateSecretVersionStage`, removing it from the version that had it
   (Secrets Manager then labels that one `AWSPREVIOUS`).

At cold start, before serving anything, the function loads its configuration
and calls KMS `GetPublicKey`: if the key's public key is not the configured
root certificate's, it refuses to start.

### The certificate

Nothing in it comes from the event; everything comes from the configuration:

- the configured subject; a random positive 128-bit serial number;
- `NotBefore` = now − 5m, `NotAfter` = now + `validity`, never after the
  root's `NotAfter`;
- basic constraints `CA:TRUE` with the configured path length (0 included),
  critical; key usage `keyCertSign | cRLSign`, critical;
- name constraints, critical, when any are configured: permitted and excluded
  URI domains and DNS domains (see below);
- subject key identifier = SHA-1 of the new public key (RFC 5280 method 1);
  authority key identifier = the root's subject key identifier.

What it writes (informative; the format is the contract): `cert` is issued
directly by the root, so `chain` is always `""`; `root` is the configured
`root_certificate`, re-encoded from its DER; `key` is a newly generated key of
the configured `key_type`, which exists only in the Lambda's memory and in the
secret; the JSON is what `intermediateca.Encode` writes.

For SPIRE, keep `max_path_len` at 1 or more: SPIRE's own CA is a CA below the
intermediate, and the plugin refuses an intermediate that cannot sign one.

#### Name constraints: verifiers differ

A domain without a leading dot does not mean the same everywhere:

| Constraint | Go `crypto/x509` (URI and DNS) | RFC 5280, OpenSSL, BoringSSL (URI) |
| --- | --- | --- |
| `example.org` | `example.org` **and every host below it** | `example.org` only |
| `.example.org` | hosts below `example.org`, not `example.org` | hosts below `example.org` |

So `permitted_uri_domains: ["example.org"]` alone lets a Go verifier accept
`spiffe://sub.example.org`. To allow exactly one host (a SPIFFE trust domain,
for instance) in every stack, pair the two:

```json
"name_constraints": {
  "permitted_uri_domains": ["example.org"],
  "excluded_uri_domains": [".example.org"]
}
```

For DNS constraints all of them read `example.org` as the domain and its
subdomains. [verifiers/RESULTS.md](verifiers/RESULTS.md) records what Envoy,
MySQL, Kafka and Go actually enforce.

#### Path length and the root

The intermediate is one CA below the root. At start the configuration is
refused if the root's path length is 0, if a secret's `max_path_len` does not
fit under it (`max_path_len` ≤ root path length − 1), or if the root has a key
usage without `keyCertSign`. createSecret and testSecret also verify a chain
of the full depth, so an intermediate whose chains could not verify is never
promoted.

#### The root's expiry

`NotAfter` is capped at the root's, and testSecret wants `min_remaining` left,
so rotation starts to fail once the root has less than `min_remaining` left:
the current intermediate stays in place and keeps working until it expires.
Alarm on rotation failures and renew the root before then.

### Rotator configuration

Exactly one of these environment variables must be set:

| Variable | Value |
| --- | --- |
| `ROTATOR_CONFIG` | the configuration, inline JSON |
| `ROTATOR_CONFIG_PARAMETER` | the name of an SSM parameter (`String` or `SecureString`) holding it, read once per cold start |

The configuration is the protobuf JSON of `Config` in
[config/v1/config.proto](config/v1/config.proto), which is its reference:
every field, its default and its rules are there.

```json
{
  "kms_key_id": "alias/example-root",
  "root_certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
  "signing_algorithm": "",
  "secrets": {
    "arn:aws:secretsmanager:us-east-1:111122223333:secret:example-AbCdEf": {
      "subject": {"common_name": "Example Intermediate CA", "organization": ["Example"], "country": ["US"]},
      "key_type": "ec-p256",
      "validity": "2160h",
      "min_remaining": "1080h",
      "max_path_len": 1,
      "name_constraints": {
        "permitted_uri_domains": ["example.org"],
        "excluded_uri_domains": [],
        "permitted_dns_domains": [".example.org"],
        "excluded_dns_domains": []
      }
    }
  }
}
```

| Field | Meaning | Default |
| --- | --- | --- |
| `kms_key_id` | the root's KMS key: key ID, key ARN, alias name (`alias/...`) or alias ARN; an asymmetric `SIGN_VERIFY` key | required |
| `root_certificate` | the root certificate: exactly one PEM `CERTIFICATE` block, nothing before or after it, at most 16 KiB; its public key must be the KMS key's | required |
| `signing_algorithm` | a KMS signing algorithm (`ECDSA_SHA_256`, `ECDSA_SHA_384`, `ECDSA_SHA_512`, `RSASSA_PKCS1_V1_5_SHA_*`, `RSASSA_PSS_SHA_*`) | from the key spec: `ECC_NIST_P256` → `ECDSA_SHA_256`, `ECC_NIST_P384` → `ECDSA_SHA_384`, `ECC_NIST_P521` → `ECDSA_SHA_512`, `RSA_*` → `RSASSA_PKCS1_V1_5_SHA_256` |
| `secrets` | per secret, by ARN (`arn:<partition>:secretsmanager:<region>:<account>:secret:<name>`): what to issue (a `SecretProfile`). Use the full ARN (with the six random characters Secrets Manager appends) or the ARN without them. An event for any other secret fails. | at least one |
| `subject` | `common_name` (required, at most 64 characters), `organization`, `organizational_unit`, `country`, `province`, `locality` | required |
| `key_type` | the intermediate's key: `ec-p256`, `ec-p384`, `rsa-2048`, `rsa-4096` | `ec-p256` |
| `validity` | a Go duration string of `h`, `m`, `s`, `ms`, `us`, `ns` (`"2160h"`, `"1.5h"`, `"2h30m"`), positive | `2160h` (90 days) |
| `min_remaining` | a duration like `validity`: the least validity a pending intermediate must have left for testSecret to promote it; at most `validity` | half of `validity` |
| `max_path_len` | path length constraint, 0 to 8, and at most the root's path length − 1 | `1` |
| `name_constraints` | `permitted_uri_domains`, `excluded_uri_domains`, `permitted_dns_domains`, `excluded_dns_domains`: host names, each optionally with a leading dot (no scheme, port, path or wildcard), at most 64 per list | none |

An empty string is the same as a missing field. Unknown fields are errors, at
every level, so a misspelt setting does not go unnoticed; protobuf JSON also
accepts each field's lowerCamelCase name (`kmsKeyId`). The checks run in this
order, and the first that fails stops the Lambda from starting: the JSON
against the schema (unknown fields, types), the schema's rules
(protovalidate), then the ones a schema cannot express: the root certificate
parses and is a CA that may sign certificates and issue an intermediate
(`keyCertSign`, a path length other than 0), each `max_path_len` fits under
it, and, at start, the KMS key's public key is the root's. No error contains
the certificate.

### Recovering a stuck rotation

A version's value cannot change, and Secrets Manager retries a failed rotation
with the same `AWSPENDING` version. When testSecret rejects that value (too
little validity left, a root that is no longer the configured one, a
configuration changed since it was issued), every retry fails the same way,
and the error says so. Take the label off the version, and the next rotation
starts afresh with a new token:

```bash
aws secretsmanager update-secret-version-stage \
  --secret-id arn:aws:secretsmanager:us-east-1:111122223333:secret:example-AbCdEf \
  --version-stage AWSPENDING \
  --remove-from-version-id <the version in the error>
aws secretsmanager rotate-secret \
  --secret-id arn:aws:secretsmanager:us-east-1:111122223333:secret:example-AbCdEf
```

`AWSCURRENT` is untouched throughout: readers keep the current intermediate.

### Rotator IAM permissions

The Lambda's execution role needs:

| Actions | Resource |
| --- | --- |
| `kms:GetPublicKey`, `kms:Sign` | the root KMS key (by key ARN; IAM does not match aliases) |
| `secretsmanager:DescribeSecret`, `secretsmanager:GetSecretValue`, `secretsmanager:PutSecretValue`, `secretsmanager:UpdateSecretVersionStage` | the rotated secrets |
| `kms:Decrypt`, `kms:GenerateDataKey` (Encrypt) | the KMS key the secrets are encrypted with, when it is a customer managed key |
| `ssm:GetParameter` | the configuration parameter, with `ROTATOR_CONFIG_PARAMETER` only |
| `kms:Decrypt` | the parameter's key, for a `SecureString` with a customer managed key |
| `logs:CreateLogGroup`, `logs:CreateLogStream`, `logs:PutLogEvents` | its log group (`AWSLambdaBasicExecutionRole`) |

Secrets Manager must be allowed to invoke the function (a resource policy for
`secretsmanager.amazonaws.com`). The function calls KMS, Secrets Manager and,
with the parameter form, SSM: in a VPC it needs endpoints or a route to them.

### Logs

One JSON object per line on stdout (`log/slog`). Each issued certificate is
logged once, with `secret_arn`, `serial` (hex), `not_after` (RFC 3339) and
`public_key_sha256` (SHA-256 of the SubjectPublicKeyInfo DER). No private key
or certificate is ever logged.

## intermediate-ca/v1: the secret format

A small JSON document that holds an intermediate CA: its certificate, its
PKCS#8 private key, the certificates up to a trust anchor, and the trust
anchor.

```json
{
  "format": "intermediate-ca/v1",
  "cert": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n",
  "key": "-----BEGIN PRIVATE KEY-----\nMIGH...\n-----END PRIVATE KEY-----\n",
  "chain": "",
  "root": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n"
}
```

- [`docs/secret-format.md`](docs/secret-format.md): the specification, which
  is authoritative.
- [`intermediateca/v1/secret.proto`](intermediateca/v1/secret.proto): the
  schema, with protovalidate rules.
- [`intermediateca/testdata/`](intermediateca/testdata): documents any
  implementation must accept or refuse, with `manifest.json`.

Version 1 is frozen: a change that would alter what a v1 document means or
which documents are accepted is a new format, `intermediate-ca/v2` in package
`intermediateca/v2`, never an edit of v1. `buf breaking` enforces it for the
schema on every pull request, and the golden files for the rules.

```go
import "github.com/bpalermo/spire-upstream-secretsmanager/intermediateca"

// Reading: parse and verify, as of now.
b, err := intermediateca.Decode(secretString)
switch {
case errors.Is(err, intermediateca.ErrExpired):
	// refresh the secret
case err != nil:
	// ErrInvalid, ErrKeyMismatch, ErrNotCA or ErrChain; never contains the key
	return err
}
b.Cert, b.Key, b.Chain, b.Root // *x509.Certificate, crypto.Signer, ...

// Pin the trust anchor.
if intermediateca.RootSHA256Hex(b) != wantRootSHA256 {
	return errors.New("unexpected root")
}

// Writing: the same bytes for the same certificates.
data, err := intermediateca.Encode(&intermediateca.Bundle{
	Cert: cert, Key: key, Chain: nil, Root: root,
})
```

`DecodeAt(data, t)` checks validity at `t` instead of now. The generated
message type (`Bundle.Raw`) is in
`github.com/bpalermo/spire-upstream-secretsmanager/intermediateca/v1`.

The Go packages build with Bazel: the code generated from the protos is not
committed. A plain `go get` of `intermediateca` therefore lacks
`intermediateca/v1`, and a user of the Go toolchain alone has to generate it
(protoc with protoc-gen-go, from `intermediateca/v1/secret.proto` and
protovalidate's `buf/validate/validate.proto`).

## Deployment

### The rotator Lambda (Terraform)

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
  # From the GitHub Release; verify checksums.txt first (see Releases).
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

### The plugin

The release publishes static plugin binaries for linux/amd64 and linux/arm64,
listed in `checksums.txt` (the SHA-256 is SPIRE's `plugin_checksum`), and a
multi-arch image `quay.io/palermo/spire-upstream-secretsmanager` that contains
only `/upstream-secretsmanager` (no shell, no libc). The checksum differs per
architecture; use the one of the nodes the server runs on.

#### SPIRE Helm chart (`customPlugins`)

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
[IAM permissions](#plugin-iam-permissions) (for example with IRSA).

#### Kubernetes image volume

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

#### Docker Compose

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

## Releases

One version for everything (`VERSION`). Pushing a tag `v<VERSION>` publishes,
on the GitHub Release:

- `upstream-secretsmanager_<version>_linux_amd64` and `_linux_arm64`, the
  plugin binaries, statically linked;
- `kms-intermediate-rotator_<version>_linux_amd64.zip` and `_linux_arm64.zip`,
  each holding one statically linked executable, `bootstrap`;
- `checksums.txt` (SHA-256 of all four), signed keyless with cosign
  (`checksums.txt.sigstore.json`);
- an SBOM, `spire-upstream-secretsmanager_<version>_sbom.spdx.json`, signed
  the same way;

and pushes the multi-arch plugin image to Quay
(`quay.io/palermo/spire-upstream-secretsmanager`), signed with cosign (the
index and each platform's manifest; the signatures are OCI referrers). The release notes list the plugin's
`plugin_checksum` for each architecture, the image digest and the SHA-256 of
each Lambda archive. Every binary reports the tag with `--version`. The Go
package `intermediateca` is versioned by the same tag.

Verify a download:

```bash
cosign verify-blob checksums.txt --bundle checksums.txt.sigstore.json \
  --certificate-identity 'https://github.com/bpalermo/spire-upstream-secretsmanager/.github/workflows/release.yml@refs/tags/v<version>' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --ignore-missing -c checksums.txt
```

## Build

Everything is built with [Bazel](https://bazel.build) (bzlmod); the version is
pinned in `.bazelversion`, so [Bazelisk](https://github.com/bazelbuild/bazelisk)
picks the right one. No Go toolchain is needed on the host: Bazel downloads
the pinned one.

```bash
bazel build //...                                  # everything
bazel test //...                                   # unit tests, buf lint, a real SPIRE server, the end-to-end test
bazel run //upstream-secretsmanager -- --version
bazel run //rotator -- --version
bazel run //:gazelle                               # after adding, removing or renaming Go files
bazel run //:format                                # format Go, Starlark, shell and protos
bazel build --config=ci //...                      # what CI builds: static analysis, shellcheck, gocognit
```

The release artifacts, statically linked and stamped with the version:

```bash
bazel build //upstream-secretsmanager:upstream-secretsmanager_linux_amd64 \
            //upstream-secretsmanager:upstream-secretsmanager_linux_arm64 \
            //rotator:zip_linux_amd64 //rotator:zip_linux_arm64
bazel run //upstream-secretsmanager:image_load     # the plugin image, into a local Docker daemon
```

The tests use in-process fakes of KMS, Secrets Manager and SSM backed by real
keys, and make no network calls beyond loopback. `//integration/e2e:e2e_test`
runs the three components together: the rotation code rotates an intermediate
into the fake Secrets Manager, the SPIRE server release pinned in
`MODULE.bazel` mints from it with the plugin, and a second rotation is picked
up by the CA SPIRE prepares next. See [AGENTS.md](AGENTS.md) for the layout
and the rest of the commands.

### Layout

| Directory | Contents |
| --- | --- |
| `upstream-secretsmanager/` | the plugin binary, its release builds and image |
| `rotator/` | the Lambda binary (`bootstrap`) and its release archives |
| `plugin/`, `secret/`, `cache/`, `upstreamca/` | the plugin's libraries |
| `config/` (with `config/v1`), `intermediate/`, `kmssigner/`, `rotation/` | the rotator's libraries |
| `intermediateca/` (with `v1/` and `testdata/`) | the secret format |
| `internal/` | the version, and test helpers |
| `integration/` | the SPIRE server test and the end-to-end test |
| `verifiers/` | which verifiers enforce name constraints ([RESULTS](verifiers/RESULTS.md)) |
| `docs/` | the secret format's specification |
| `bazel/` | build rules and CI scripts |

## License

Apache-2.0, see [LICENSE](LICENSE). The CSR signing (`upstreamca`) and parts
of the plugin are adapted from [SPIRE](https://github.com/spiffe/spire)
v1.15.5, also Apache-2.0, as noted in the source.
