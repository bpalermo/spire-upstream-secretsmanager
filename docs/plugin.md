# upstream-secretsmanager: the SPIRE plugin

An external SPIRE plugin (built on the
[SPIRE plugin SDK](https://github.com/spiffe/spire-plugin-sdk)): one statically
linked binary, `upstream-secretsmanager`, that the SPIRE server executes.

## Why

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

## Plugin configuration

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
| `secret_id` | | ARN or name of a secret in [format v1](secret-format.md). |
| `cert_file_arn`, `key_file_arn`, `bundle_file_arn` | | Instead of `secret_id`: the three-secret layout of `awssecret`, each secret's `SecretString` being PEM, read exactly as `awssecret` reads them. `cert_file_arn` holds the CA certificate, optionally followed by intermediates; `key_file_arn` its key; `bundle_file_arn` the root(s). `bundle_file_arn` may be left out only if `cert_file_arn` is one self-signed certificate. |
| `cache_path` | none | File where the last good intermediate is kept (a `cache.v1.CacheEntry`, mode 0600). Optional but recommended: without it a restarted server cannot mint while Secrets Manager is unreachable. |
| `root_sha256` | **required** | Hex SHA-256 of the root certificate's DER, or a list of them. An intermediate under any other root is refused, whether read from Secrets Manager or from the cache. A list stages a root rotation: pin the new root next to the old one, then switch the secret. |
| `fetch_timeout` | `10s` | Time limit for the Secrets Manager reads of one mint. It is also the timeout of every HTTP request of the AWS client (Secrets Manager, STS and the other credential endpoints), so a hung request cannot outlive a mint. |
| `min_remaining` | `1h` | An intermediate (fetched or cached) with less than this left before its `NotAfter` is not used. |

Set either `secret_id` or the `awssecret` layout, not both. Unknown keys are
refused, so a misspelt key (`root_sha265`) fails the configuration instead of
disabling a check. `plugin_data` may be HCL or JSON; either way it is read as
the protobuf JSON of `Config` in
[plugin/v1/config.proto](../plugin/v1/config.proto), whose protovalidate rules
are its reference (a single `root_sha256` string is a list of one, and the
pins may be upper or lower case). The SPIRE server's `trust_domain` is used to check CSRs and
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

## Plugin IAM permissions

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

## Behaviour at each mint

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
   hour if SPIRE gives none), but never after the intermediate's `NotAfter`.
   The subject is the CSR's, which is SPIRE's `ca_subject`: with a DNS name
   constraint on the intermediate, keep its `common_name` inside the
   constraint or leave it out, because Java and IAM Roles Anywhere check a
   CA's CN against DNS constraints (the probe of step 2 uses Go, which does
   not, so it cannot catch this; see
   [Name constraints and the SPIRE CA's CN](rotator.md#name-constraints-and-the-spire-cas-cn));
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

Beyond what [the specification](secret-format.md) requires of every
reader, the plugin refuses an intermediate whose root is not one of
`root_sha256`, one with less than `min_remaining` of its lifetime left, and
one that cannot sign a CA for the SPIRE trust domain that SPIRE accepts (path
length, name constraints). The cache file is the protobuf JSON of a
`CacheEntry` ([cache/v1/cache.proto](../cache/v1/cache.proto)): the secret, in
the format, and, with the awssecret layout, the whole bundle
(`upstream_bundle`). It is read strictly: a file with an unknown field, or one
in the layout of earlier versions, is ignored with a warning and replaced at
the next successful mint.

## Cache and slack

The cache bounds how long SPIRE can keep minting while Secrets Manager is
unreachable: until the cached intermediate has less than `min_remaining` left.
With intermediates valid for 90 days that are rotated well before they expire,
an outage has weeks of slack. SPIRE's own CA is capped at the intermediate's
`NotAfter`, so an intermediate close to its end yields correspondingly short
CAs; `min_remaining` sets the point where the plugin stops using it. Choose
`min_remaining` at least as large as SPIRE's `ca_ttl` if every CA must get its
full lifetime.

## Cold start / seeding the cache

The plugin makes no AWS call at Configure. Every `MintX509CA` fetches
`AWSCURRENT`, validates it, and writes it to `cache_path` (atomically, mode
0600); the cache is what lets a server mint while Secrets Manager is
unreachable. A server that starts with no valid cache and cannot reach AWS
has nothing to mint with: every mint fails and SPIRE keeps retrying. That is
a deadlock when the server's AWS credentials depend on that same server, for
example a workload identity that needs an SVID it issues.

To break it, seed the cache before the first start: write the secret, wrapped
in a `CacheEntry`, to `cache_path`, mode 0600, owned by the uid the SPIRE
server runs as. For a secret in format v1 the entry is
`{"secret": <the secret's SecretString, as a JSON object>}`:

```bash
cache=/opt/spire/data/server/upstream-secretsmanager.json
(
  umask 077
  aws secretsmanager get-secret-value \
    --secret-id arn:aws:secretsmanager:us-east-1:111122223333:secret:example \
    --query SecretString --output text |
    jq '{secret: .}' >"${cache}"
)
chown <server uid>:<server gid> "${cache}"
```

The SecretString goes in as an object (`jq '{secret: .}'`), not as a string
(`jq -Rs`), which is not a cache entry. The cache is read more strictly than
the secret: a SecretString with a field outside the format (the rotator
writes none) makes the seeded file one that is ignored with a warning. A
seeded entry is validated at Configure and at every use exactly as a cached
one (the root pin, `min_remaining`, the trust domain), and the first
successful mint replaces it. The file holds the private key: pipe it as
above rather than leaving a copy elsewhere. With the `awssecret` layout the
entry also needs `upstream_bundle`; copy a cache file a server has written
instead of building one.
