# AGENTS.md

Guidance for agents working in this repository.

## What this is

A SPIRE UpstreamAuthority plugin that reads its intermediate CA from AWS
Secrets Manager at every mint, with a validated local cache. It is an external
plugin (built on `github.com/spiffe/spire-plugin-sdk`): one statically linked
binary, `upstream-secretsmanager`, that the SPIRE server executes. The
repository is public: no account IDs, ARNs, key IDs, personal domains or
cluster names anywhere, and examples use `example.org`.

The secret format the plugin reads is `docs/secret-format.md`, the contract
with the producer (a separate repository, kms-intermediate-rotator); change it
only together with the producer. Behaviour follows SPIRE's built-in `disk` and
`awssecret` UpstreamAuthority plugins (v1.15.5) unless the README says
otherwise.

## Build and test

Never run the host `go` tool: Bazel downloads the pinned SDK (from `go.mod`).

```bash
bazel test //...                  # builds and runs the unit tests
bazel run //:gazelle              # after adding, removing or renaming any .go file
bazel run //:format               # format Go, Starlark and shell; CI runs //:format.check
bazel mod tidy                    # after changing go.mod or a bazel_dep
bazel build --config=ci //...     # what CI builds: lockfile must be current, shellcheck and gocognit on
bazel run //cmd/upstream-secretsmanager -- --version
```

Add a Go dependency with `bazel run @rules_go//go -- get <module>@<version>`,
then `bazel mod tidy`, then `bazel run //:gazelle`. A dependency whose
checked-in BUILD files regenerate Go from `.proto` sources (the SPIRE plugin
SDK is one) needs a `go_deps.gazelle_override` with
`gazelle:proto disable_global` in MODULE.bazel, as the other repositories do.

`user.bazelrc` is local and untracked. It points Bazel's Go module fetches at
the public proxy; a `Duplicate rc file: user.bazelrc` warning is harmless.

## Layout

- `cmd/upstream-secretsmanager/`: the plugin binary (`go_binary`, pure Go, CGO
  off), its release builds for linux/amd64 and linux/arm64
  (`upstream-secretsmanager_linux_<arch>`) and its image.
- `pkg/plugin/`: the plugin (Configure, Validate, MintX509CAAndSubscribe), its
  HCL configuration and the AWS client, behind the narrow `SecretsClient`
  interface so tests use fakes.
- `pkg/secret/`: parsing and validation of format v1 and of the awssecret
  three-secret layout.
- `pkg/cache/`: the on-disk cache (atomic 0600 write, load and validate).
- `pkg/upstreamca/`: CSR signing, adapted from SPIRE's `x509svid.UpstreamCA`.
- `internal/testpki/`, `internal/fakesm/` (testonly): test certificate
  hierarchies and an in-process fake Secrets Manager (HTTP).
- `integration/spireserver/`: runs the SPIRE server release pinned in
  MODULE.bazel (`@spire_linux_<arch>`, checksummed) with the plugin against
  the fake Secrets Manager. No network beyond loopback.
- `common/version/`: the version, stamped at link time from the workspace
  status.
- `bazel/`: `workspace_status.sh` (stamping from `VERSION` and git tags),
  `ci-impacted-targets.sh` (bazel-diff target determination), `registry.bzl`
  (where the image is published, named once), `image/defs.bzl` (`go_image`),
  `lint/` (shellcheck and gocognit aspects), `nogo/` (staticcheck analyzers),
  `format/` (gofumpt, shfmt, buildifier), `cosign/` (the pinned cosign CLI),
  `platforms/`.
- `.github/workflows/ci.yml` (pull requests and main) and `release.yml` (tags
  `v*`).

## Static analysis and lint

- nogo (`//:nogo`) runs `go vet`'s analyzers, the rest of the x/tools set and
  staticcheck's SA and S checks while compiling this module's packages.
- `--config=lint` (on in `--config=ci`) runs shellcheck on scripts and gocognit
  on `go_library` and `go_binary` targets. The gocognit threshold is 15, in
  `bazel/lint/linters.bzl`; it never goes up.

## Images and versions

The image `ghcr.io/bpalermo/spire-upstream-secretsmanager` has no base image:
its only content is the binary at `/upstream-secretsmanager`, mode 0755, so it
has no shell and no libc. SPIRE server pods mount it as a Kubernetes image
volume and exec the file, so keep the binary statically linked (`pure = "on"`).

`VERSION` is the release being worked towards. A commit tagged `v<VERSION>` (or
`v<VERSION>-rc.<n>`) is that release; any other commit is a snapshot. The tag
triggers `release.yml`, which builds both binaries, writes `checksums.txt`
(SPIRE's `plugin_checksum` is the SHA-256 of the binary; the release notes list
it per architecture), an SBOM and cosign keyless signatures, pushes the image,
and creates the GitHub Release. Do not push tags unless asked.

## CI

`ci.yml` has a `diff` job that computes, with bazel-diff, the targets a change
impacts (`bazel/ci-impacted-targets.sh`), so a documentation-only change builds
nothing. Anything it cannot decide is a full run. The formatter and Gazelle
checks always run, in `lint`. The `ci` job is the single required check. The
bazel-diff seed files in the script (`.bazelrc`, `MODULE.bazel`, the lint
`.bzl` files, ...) are the CI inputs that no target depends on: add a new one
there.

## Pull requests

One topic per pull request, squash-merged. Run `bazel run //:gazelle`,
`bazel run //:format` and `bazel build --config=ci //... && bazel test //...`
before pushing.
