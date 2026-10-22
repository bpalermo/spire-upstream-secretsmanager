# spire-upstream-secretsmanager

SPIRE UpstreamAuthority plugin that reads its intermediate CA from AWS Secrets Manager at every mint, with a validated local cache.

The plugin is an external SPIRE plugin: a statically linked binary that the SPIRE server executes. This repository currently holds the build, test and release skeleton; the plugin itself is added in later changes.

## Build

Everything is built with [Bazel](https://bazel.build) (bzlmod); the version is pinned in `.bazelversion`, so [Bazelisk](https://github.com/bazelbuild/bazelisk) picks the right one. No Go toolchain is needed on the host: Bazel downloads the pinned one.

```bash
bazel build //...                                  # the plugin binary and the image
bazel test //...                                   # unit tests
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

Apache-2.0, see [LICENSE](LICENSE).
