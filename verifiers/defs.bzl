"""Shared attributes of the verifier tests that drive real software."""

# The tests that start containers (and, for the image volume test, a kind
# cluster) on the local Docker daemon. `manual`: `bazel test //...` and CI
# leave them out; run them with verifiers/run.sh. `local`: no sandbox, so the
# docker CLI reaches the daemon's socket. `exclusive`: one at a time, nothing
# else running beside them. `external`: never cached, every run asks the
# software again.
DOCKER_TEST_TAGS = [
    "exclusive",
    "external",
    "local",
    "manual",
    "requires-docker",
]
