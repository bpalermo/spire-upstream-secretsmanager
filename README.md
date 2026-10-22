# spire-upstream-secretsmanager

A [SPIRE](https://spiffe.io/) UpstreamAuthority plugin that reads its intermediate CA from AWS Secrets Manager **at every mint**, with a validated local cache.

The plugin is an external SPIRE plugin (built on the [SPIRE plugin SDK](https://github.com/spiffe/spire-plugin-sdk)): one statically linked binary, `upstream-secretsmanager`, that the SPIRE server executes.

## Why

SPIRE's built-in [`awssecret`](https://github.com/spiffe/spire/blob/main/doc/plugin_server_upstreamauthority_awssecret.md) UpstreamAuthority reads the upstream CA from Secrets Manager once, when the server starts. An intermediate CA that is rotated in Secrets Manager (for example by a rotation Lambda such as [kms-intermediate-rotator](https://github.com/bpalermo/kms-intermediate-rotator), which signs short-lived intermediates with a root key in KMS) is not picked up until every SPIRE server restarts, and a server that starts while AWS is unreachable does not start at all.

This plugin:

- reads the `AWSCURRENT` version of the secret every time SPIRE asks for a new X.509 CA, so a rotated (or emergency-replaced) intermediate is used from the next CA rotation on, without a restart;
- makes no AWS call when it is configured, so SPIRE starts with AWS unreachable;
- validates what it reads (key matches certificate, certificate is a CA, it verifies to the root through the chain, optional root pin, enough lifetime left) and keeps the last good copy in memory and, optionally, on disk, falling back to it when Secrets Manager cannot be read or returns something invalid.

Everything else behaves as SPIRE's built-in `disk` and `awssecret` plugins do: the CSR checks, the certificate template of the minted CA, the response layout, and JWT-SVID publishing and `SubscribeToLocalBundle` being unsupported.

## Configuration

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
| `root_sha256` | none | Hex SHA-256 of the root certificate's DER. If set, an intermediate under any other root is refused, whether read from Secrets Manager or from the cache. |
| `fetch_timeout` | `10s` | Time limit for the Secrets Manager reads of one mint. |
| `min_remaining` | `1h` | An intermediate (fetched or cached) with less than this left before its `NotAfter` is not used. |

Set either `secret_id` or the `awssecret` layout, not both. The SPIRE server's `trust_domain` is used to check CSRs.

Credentials come from the AWS SDK's default chain: environment variables, the shared config and credentials files (profiles, `credential_process`), web identity (`AWS_WEB_IDENTITY_TOKEN_FILE`, so IRSA works), the container credentials endpoint (ECS, EKS Pod Identity) and the EC2 instance metadata service (`AWS_EC2_METADATA_SERVICE_ENDPOINT` is honoured). The plugin runs with the SPIRE server's environment.

### IAM permissions

The plugin only reads. On the one secret (each of the three, with the `awssecret` layout):

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

`kms:Decrypt` is for the customer managed key that encrypts the secret; it is not needed if the secret uses the AWS managed key `aws/secretsmanager`. With `assume_role_arn`, the caller also needs `sts:AssumeRole` on that role, and the role gets the permissions above.

## Behaviour at each mint

When SPIRE prepares a new X.509 CA, the plugin:

1. reads the `AWSCURRENT` version of the secret(s), within `fetch_timeout`;
2. validates it: format v1 (or the `awssecret` layout), the key matches the certificate, the certificate is a CA and verifies to the root through the chain, the root matches `root_sha256` if set, and at least `min_remaining` is left;
3. on success, writes it to `cache_path` (atomically: a temporary file in the same directory, fsync, rename, fsync of the directory; mode 0600) and uses it. On failure, it logs a warning with the reason and uses the last good copy (the last one fetched, or the one loaded from `cache_path` at startup) if that still passes step 2 at the current time; if there is none, the mint fails and SPIRE retries;
4. signs SPIRE's CSR as SPIRE's own `disk` plugin does: the CSR's signature must be valid and its only URI SAN must be `spiffe://<trust domain>`; the CA is valid from 10 seconds ago until now plus SPIRE's preferred TTL (1 hour if SPIRE gives none), but never after the intermediate's `NotAfter`;
5. returns the chain `[new CA, intermediate, chain...]` and the upstream roots `[root]`. When the CA from the `awssecret` layout is self-signed, the chain is `[new CA]` and the root is that CA, as with `awssecret`.

At startup (Configure) the plugin only parses the configuration and loads `cache_path` if it exists; an invalid or expiring cache is ignored with a warning.

### Cache and slack

The cache bounds how long SPIRE can keep minting while Secrets Manager is unreachable: until the cached intermediate has less than `min_remaining` left. With intermediates valid for 90 days that are rotated well before they expire, an outage has weeks of slack. SPIRE's own CA is capped at the intermediate's `NotAfter`, so an intermediate close to its end yields correspondingly short CAs; `min_remaining` sets the point where the plugin stops using it. Choose `min_remaining` at least as large as SPIRE's `ca_ttl` if every CA must get its full lifetime.

## Deployment

The release publishes static binaries for linux/amd64 and linux/arm64 with a `checksums.txt` (the SHA-256 is SPIRE's `plugin_checksum`), and a multi-arch image `ghcr.io/bpalermo/spire-upstream-secretsmanager` that contains only `/upstream-secretsmanager` (no shell, no libc). The checksum differs per architecture; use the one of the nodes the server runs on.

### Kubernetes image volume

On Kubernetes with image volumes (the `ImageVolume` feature), mount the image straight into the SPIRE server pod:

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
        reference: ghcr.io/bpalermo/spire-upstream-secretsmanager:<version>
        pullPolicy: IfNotPresent
```

and set `plugin_cmd = "/opt/spire/plugins/secretsmanager/upstream-secretsmanager"`.

### SPIRE Helm chart (`customPlugins`)

With the [hardened SPIRE Helm chart](https://github.com/spiffe/helm-charts-hardened), declare it as a custom plugin; the chart copies `plugin_cmd` out of the image into the server pod and points SPIRE at the copy:

```yaml
spire-server:
  customPlugins:
    upstreamAuthority:
      secretsmanager:
        image:
          registry: ghcr.io
          repository: bpalermo/spire-upstream-secretsmanager
          tag: "<version>"
        plugin_cmd: /upstream-secretsmanager
        plugin_checksum: "<SHA-256 of upstream-secretsmanager for the nodes' architecture>"
        plugin_data:
          region: us-east-1
          secret_id: arn:aws:secretsmanager:us-east-1:111122223333:secret:example
          cache_path: /run/spire/data/upstream-secretsmanager.json
          root_sha256: "<hex SHA-256 of the root certificate's DER>"
```

`/run/spire/data` is the chart's persistent volume, so the cache survives a restart. Give the server's service account the IAM permissions above (for example with IRSA).

### Docker Compose

The image has no shell, so it installs itself: `upstream-secretsmanager install <dir>` copies its own executable to `<dir>/upstream-secretsmanager` with mode 0755 and exits.

```yaml
services:
  install-upstream-secretsmanager:
    image: ghcr.io/bpalermo/spire-upstream-secretsmanager:<version>
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

## Secret format

See [docs/secret-format.md](docs/secret-format.md). The producer, [kms-intermediate-rotator](https://github.com/bpalermo/kms-intermediate-rotator), is a separate repository; the format document is the contract between the two.

## Build

Everything is built with [Bazel](https://bazel.build) (bzlmod); the version is pinned in `.bazelversion`, so [Bazelisk](https://github.com/bazelbuild/bazelisk) picks the right one. No Go toolchain is needed on the host: Bazel downloads the pinned one.

```bash
bazel build //...                                  # the plugin binary and the image
bazel test //...                                   # unit tests, and a real SPIRE server against a fake Secrets Manager
bazel run //cmd/upstream-secretsmanager -- --version
bazel run //:gazelle                               # after adding, removing or renaming Go files
bazel run //:format                                # format Go, Starlark and shell
bazel build --config=ci //...                      # what CI builds: static analysis, shellcheck, gocognit
```

Release binaries for the two supported platforms, statically linked and stamped with the version:

```bash
bazel build //cmd/upstream-secretsmanager:upstream-secretsmanager_linux_amd64 \
            //cmd/upstream-secretsmanager:upstream-secretsmanager_linux_arm64
```

The OCI image (`ghcr.io/bpalermo/spire-upstream-secretsmanager`, multi-arch) contains only the binary, at `/upstream-secretsmanager`, so that it can be mounted into a SPIRE server pod as a Kubernetes image volume. Load it into a local Docker daemon with:

```bash
bazel run //cmd/upstream-secretsmanager:image_load
```

## Releases

Pushing a tag `v<VERSION>` (see `VERSION`) publishes the binaries, `checksums.txt`, an SBOM and the image, all signed with cosign keyless signatures, and creates the GitHub Release. SPIRE's `plugin_checksum` is the SHA-256 of the plugin binary; the release notes list it for each architecture.

## License

Apache-2.0, see [LICENSE](LICENSE). The CSR signing (`pkg/upstreamca`) and parts of the plugin are adapted from [SPIRE](https://github.com/spiffe/spire) v1.15.5, also Apache-2.0, as noted in the source.
