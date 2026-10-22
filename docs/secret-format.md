# Secret format v1 (`intermediate-ca/v1`)

This is the contract between this plugin, which reads the secret, and the
rotation function that writes it
([bpalermo/kms-intermediate-rotator](https://github.com/bpalermo/kms-intermediate-rotator)).
The two share no code; this document is the interface.

`SecretString` is JSON:

```json
{
  "format": "intermediate-ca/v1",
  "cert":  "-----BEGIN CERTIFICATE-----\n...",      // the intermediate CA, PEM, exactly one cert
  "key":   "-----BEGIN PRIVATE KEY-----\n...",      // its private key, PKCS#8 PEM
  "chain": "",                                       // PEM certs between cert and root, may be empty
  "root":  "-----BEGIN CERTIFICATE-----\n..."       // the trust anchor, PEM, exactly one cert
}
```

Readers MUST reject an unknown `format`, a `cert` whose public key does not match `key`, and
a `cert` that does not verify to `root` through `chain`. Unknown extra fields are ignored.

## How this plugin reads it

In addition to the rules above, the plugin refuses an intermediate that is not
a CA certificate (basic constraints `CA:TRUE`, and `keyCertSign` if key usage
is present), one whose root is not one of the configured `root_sha256`, one
with less than `min_remaining` of its lifetime left, and one that cannot sign a
CA for the SPIRE trust domain that SPIRE accepts (path length, name
constraints). `chain` is ordered from the certificate that signed `cert`
towards the root. The plugin's cache file (`cache_path`) is written in this
same format; with the awssecret layout it adds an `x_upstream_bundle` field
holding the whole bundle, which the plugin reads only from its cache, never
from a secret.
