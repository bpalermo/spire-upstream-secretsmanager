#!/usr/bin/env bash
# Runs every verifier test and prints their verdicts: Go's crypto/x509, then
# Envoy, MySQL and Kafka in containers, then the image volume test in a kind
# cluster. All but the first are tagged manual (verifiers/defs.bzl), so
# `bazel test //...` and CI never run them.
#
# Needs: a local Docker daemon, kind on PATH, network access to pull the
# digest-pinned images. Every network, container and cluster is named susm-*
# and removed when its test ends; the script reports any that are left.
#
#   verifiers/run.sh                  # all of them
#   bazel run //verifiers:run         # the same
#   verifiers/run.sh //verifiers/kafka:kafka_test
#   BAZEL=/usr/local/bin/bazel verifiers/run.sh
#
# Output: one `RESULT <verifier> <case> <verdict> (RFC 5280: <verdict>)
# <error>` line per row, and the same rows as TSV in
# bazel-testlogs/verifiers/<name>/<name>_test/test.outputs/. A test fails when
# a verdict differs from the one it expects (RFC 5280, or a deviation listed
# in the test and explained in verifiers/RESULTS.md).
set -uo pipefail

cd "${BUILD_WORKSPACE_DIRECTORY:-$(dirname "$0")/..}" || exit 1
bazel="${BAZEL:-bazel}"

targets=("$@")
if [ "${#targets[@]}" -eq 0 ]; then
	targets=(
		//verifiers/gox509:gox509_test
		//verifiers/envoy:envoy_test
		//verifiers/mysql:mysql_test
		//verifiers/kafka:kafka_test
		//verifiers/imagevolume:imagevolume_test
	)
fi

status=0
"${bazel}" test --test_output=errors "${targets[@]}" || status=$?

testlogs="$("${bazel}" info bazel-testlogs 2>/dev/null)"
for target in "${targets[@]}"; do
	pkg="${target#//}"
	log="${testlogs}/${pkg%%:*}/${pkg##*:}/test.log"
	[ -f "${log}" ] && grep -h 'RESULT ' "${log}" | sed 's/^ *[a-z_0-9]*\.go:[0-9]*: //'
done

leftovers="$(
	docker ps -a --filter name=susm- --format '{{.Names}}'
	docker network ls --filter name=susm- --format '{{.Name}}'
	kind get clusters 2>/dev/null | grep '^susm-'
)"
if [ -n "${leftovers}" ]; then
	echo "left behind (remove with docker rm -f / docker network rm / kind delete cluster --name):" >&2
	echo "${leftovers}" >&2
	status=1
fi
exit "${status}"
