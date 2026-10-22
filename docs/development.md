# Development

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
up by the CA SPIRE prepares next. See [AGENTS.md](../AGENTS.md) for the layout
and the rest of the commands.

## Layout

| Directory | Contents |
| --- | --- |
| `upstream-secretsmanager/` | the plugin binary, its release builds and image |
| `rotator/` | the Lambda binary (`bootstrap`) and its release archives |
| `plugin/`, `secret/`, `cache/`, `upstreamca/` | the plugin's libraries |
| `config/` (with `config/v1`), `intermediate/`, `kmssigner/`, `rotation/` | the rotator's libraries |
| `intermediateca/` (with `v1/` and `testdata/`) | the secret format |
| `internal/` | the version, and test helpers |
| `integration/` | the SPIRE server test and the end-to-end test |
| `verifiers/` | which verifiers enforce name constraints ([RESULTS](../verifiers/RESULTS.md)) |
| `docs/` | the documentation: plugin, rotator, secret format, deployment, releases, development |
| `bazel/` | build rules and CI scripts |
