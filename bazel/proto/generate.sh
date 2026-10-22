#!/usr/bin/env bash
# Copy a generated .pb.go over the committed one:
#   bazel run //<package>:generate
# Arguments (from bazel/proto/defs.bzl): the generated file, and where it goes
# relative to the workspace root.
set -euo pipefail

generated="$1"
destination="${BUILD_WORKSPACE_DIRECTORY:?run this with bazel run}/$2"

install -m 0644 "${generated}" "${destination}"
echo "wrote ${destination}"
