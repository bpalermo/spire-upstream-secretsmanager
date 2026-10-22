# Releases

One version for everything (`VERSION`). Pushing a tag `v<VERSION>` (or
`v<VERSION>-rc.<n>`) on a commit of main publishes, on the GitHub Release:

- `upstream-secretsmanager_<version>_linux_amd64` and `_linux_arm64`, the
  plugin binaries, statically linked and reporting the tag with `--version`;
- `kms-intermediate-rotator_<version>_linux_amd64.zip` and `_linux_arm64.zip`,
  each holding one statically linked executable, `bootstrap`;
- `<file>.spdx.json`, an SPDX SBOM of each of those four (syft, from the Go
  build information: the modules and the Go version linked in);
- `checksums.txt` (SHA-256 of all eight), signed keyless with cosign
  (`checksums.txt.sigstore.json`);

and pushes the multi-arch plugin image,
`quay.io/palermo/spire-upstream-secretsmanager`, tagged with the release and
signed keyless with cosign (the index and each platform's manifest). The
release notes list the plugin's `plugin_checksum` for each architecture, the
image digest and the SHA-256 of each Lambda archive.

Only the release workflow, run for a `v*` tag, signs. Verify the image (by the
digest the release notes give):

```bash
cosign verify quay.io/palermo/spire-upstream-secretsmanager@sha256:<digest> \
  --certificate-identity 'https://github.com/bpalermo/spire-upstream-secretsmanager/.github/workflows/release.yml@refs/tags/v<version>' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

and a download the same way, with `cosign verify-blob checksums.txt --bundle
checksums.txt.sigstore.json` and the same two flags, then `sha256sum
--ignore-missing -c checksums.txt`. `bazel run //bazel/cosign -- ...` runs
the cosign this repository pins.
