#!/usr/bin/env bash
# Fail if a committed .pb.go is not what its .proto generates.
# Arguments (from bazel/proto/defs.bzl): the generated file, the committed one,
# and the target that regenerates it.
set -euo pipefail

generated="$1"
committed="$2"
generator="$3"

if ! diff -u "${committed}" "${generated}"; then
	echo "${committed} is stale; run 'bazel run ${generator}'" >&2
	exit 1
fi
echo "${committed} is up to date"
