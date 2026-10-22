# Secret format v1 (`intermediate-ca/v1`)

This is the specification of the format, and the contract between the programs
that write it (a rotator that keeps an intermediate CA in a secret store) and
the programs that read it (a certificate authority plugin, a proxy). This
repository holds one of each, the rotator Lambda (`rotator/`) and the SPIRE
plugin (`upstream-secretsmanager/`), but they are released and deployed
separately and read each other's data for years, and implementations in other
languages are expected: this document is normative,
`intermediateca/v1/secret.proto` is its machine-readable schema, and
`intermediateca/testdata/` holds documents every implementation must accept or
refuse. The Go package `intermediateca`
(`github.com/bpalermo/spire-upstream-secretsmanager/intermediateca`) is the
reference implementation.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## Format

A secret is a JSON document (RFC 8259, UTF-8) holding one object:

```json
{
  "format": "intermediate-ca/v1",
  "cert":  "-----BEGIN CERTIFICATE-----\n...",      // the intermediate CA, PEM, exactly one cert
  "key":   "-----BEGIN PRIVATE KEY-----\n...",      // its private key, PKCS#8 PEM
  "chain": "",                                       // PEM certs between cert and root, may be empty
  "root":  "-----BEGIN CERTIFICATE-----\n..."       // the trust anchor, PEM, exactly one cert
}
```

(The comments are not JSON; a secret has none.) The object is the protobuf
JSON mapping of `intermediateca.v1.Secret`. Every field name is one word, so
the names are the same in the protobuf, the Go and the JSON mappings.

| Field    | Content                                                                 | Required | Limit   |
|----------|-------------------------------------------------------------------------|----------|---------|
| `format` | The string `intermediate-ca/v1`.                                        | yes      |         |
| `cert`   | The intermediate CA's certificate: exactly one PEM `CERTIFICATE` block. | yes      | 16 KiB  |
| `key`    | `cert`'s private key: exactly one PEM `PRIVATE KEY` block (PKCS#8).     | yes      | 16 KiB  |
| `chain`  | The certificates between `cert` and `root`: zero or more PEM `CERTIFICATE` blocks. | no (`""`) | 64 KiB |
| `root`   | The trust anchor: exactly one PEM `CERTIFICATE` block.                  | yes      | 16 KiB  |

Limits are in bytes of the string's UTF-8 encoding.

### Rules for the values

- Every value is a string. `cert`, `key` and `root` MUST start with the
  `-----BEGIN` line of their block type (`CERTIFICATE`, `PRIVATE KEY`,
  `CERTIFICATE`); `chain` MUST be empty or start with `-----BEGIN CERTIFICATE-----`.
- A PEM block is the RFC 7468 one: `-----BEGIN <type>-----`, base64 of the DER,
  `-----END <type>-----`. A block MUST NOT carry headers (so no encrypted
  keys). Line endings are `\n` or `\r\n`; white space between blocks is
  allowed, and anything else before, between or after blocks is not.
- `cert`, `chain` and `root` hold DER X.509 certificates (RFC 5280). `key` is
  an unencrypted PKCS#8 `PrivateKeyInfo` (RFC 5958). A `PRIVATE KEY` block that
  holds another structure (SEC1, PKCS#1) is not PKCS#8 and is refused, as is
  a `EC PRIVATE KEY` or `RSA PRIVATE KEY` block.
- The missing field and the empty string are the same thing for `chain`, and
  an error for the other four.
- `chain` is in no required order. A writer SHOULD list the certificate that
  signed `cert` first and continue towards the root; a reader MUST NOT depend
  on the order. `chain` does not contain `cert`, and SHOULD NOT contain `root`.

## What a reader does

Readers MUST reject an unknown `format`, a `cert` whose public key does not
match `key`, and a `cert` that does not verify to `root` through `chain`.
Unknown extra fields are ignored. In full, in this order (the order only
decides which error a document with several problems gets; every step is
required):

1. **Schema.** The input is a JSON object; the fields that exist have the
   types above; the field rules above hold (`format`, presence, prefixes,
   limits). Unknown fields are ignored, whatever their value. A duplicate
   key of a defined field is an error. Error category: `invalid`.
2. **Parsing.** `cert` and `root` each hold exactly one certificate, `chain`
   any number, and `key` exactly one PKCS#8 private key of a type that can
   sign. `invalid`.
3. **Key match.** The public key of `key` equals the certificate's public key.
   `key_mismatch`.
4. **CA.** `cert` has BasicConstraints with `CA:TRUE`, and, if it has a
   KeyUsage extension, that includes `keyCertSign`. `not_ca`.
5. **Chain.** `cert` verifies to `root` as a trust anchor, with `chain` as the
   untrusted intermediates, at the current time (or the time the caller gives),
   for any extended key usage (RFC 5280 section 6; signatures, validity
   periods, basic constraints and path lengths, name constraints). If a
   certificate on the path is not valid at that time: `expired` (this includes
   not yet valid). Any other failure: `chain`.

A reader MAY additionally apply its own policy (a pinned root, a minimum
remaining lifetime, the constraints it needs), and SHOULD pin the root: the
secret store is the only thing that vouches for `root`, so a reader that is
meant to trust one anchor compares the SHA-256 of the DER of `root` with the
anchor it expects, and refuses a secret whose root differs.

A reader MUST NOT include any part of the secret, and above all of `key`, in an
error, a log line or a metric. The Go implementation's errors name the field
and the rule and nothing of the value.

### Error categories

| Category       | Go sentinel      | Meaning                                                          |
|----------------|------------------|------------------------------------------------------------------|
| `invalid`      | `ErrInvalid`     | Not JSON, wrong schema, unparsable PEM, X.509 or PKCS#8.         |
| `key_mismatch` | `ErrKeyMismatch` | `key` is not the private key of `cert`.                          |
| `not_ca`       | `ErrNotCA`       | `cert` may not sign certificates.                                |
| `chain`        | `ErrChain`       | `cert` does not verify to `root` through `chain`.                |
| `expired`      | `ErrExpired`     | A certificate on the path is expired or not yet valid.           |

## What a writer does

Writers MUST produce a document that satisfies every rule above, and SHOULD
produce the exact form below, so that the same certificates always give the
same bytes:

- Exactly the five fields, in the order `format`, `cert`, `key`, `chain`,
  `root`, with `chain` present even when empty (`""`).
- Compact: no white space outside strings. PEM line breaks are `\n`, written as
  the JSON escape `\n`; every block ends with a final `\n`.
- `key` is an unencrypted PKCS#8 block.

A writer MAY add fields of its own whose names start with `x_`; readers ignore
them. Version 1 will never define a field with that prefix. (One reader uses
`x_upstream_bundle` in its own cache file.) Anything else added to the object is
a change of the format.

A writer SHOULD decode what it wrote with a reader's rules before it makes it
current.

## Versioning and stability

Version 1 is frozen: no field is renamed, renumbered, retyped or removed, no
rule is loosened or tightened, and no field is added with a meaning (other than
`x_`-prefixed ones, which have none). The protobuf schema is checked for
this on every pull request with `buf breaking` against `main`. A change that
needs any of those is a new format with its own `format` value
(`intermediate-ca/v2`) and its own package (`intermediateca/v2`); readers of v1
refuse it by `format`, as the rules above say.

Corrections to this text that do not change what is accepted are not changes
of the format.

## Test data

`intermediateca/testdata/manifest.json` lists the documents under
`intermediateca/testdata/valid` and `intermediateca/testdata/invalid`, the time
to decode them at (`decode_at`; their certificates are valid for a hundred
years or, for the expired ones, not at all), the SHA-256 of the DER of each
valid document's root, and for each invalid document the error category it must
be refused with. An implementation passes if it accepts every valid document,
with that root hash, and refuses every invalid one with that category. Several
documents have more than one problem only where the earlier step in "What a
reader does" is the one named.

The keys in the files are derived from public labels: they are test keys, and
the files hold nothing secret. They are produced by `bazel run
//internal/gentestdata`.

## Security considerations

- The secret holds a CA private key. It is protected by whatever protects the
  secret store (encryption at rest, access policy); this format adds nothing.
  Keep the intermediate name-constrained and short-lived, so that a leak is
  bounded.
- `cert` carries the constraints that bound what the key may be used for
  (path length, name constraints); readers apply them by verifying
  certificates issued from it, and the checks above do not replace that.
- The size limits exist so a hostile document cannot make a reader parse
  megabytes; they are not a bound on any valid document.
