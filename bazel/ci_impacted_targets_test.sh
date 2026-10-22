#!/usr/bin/env bash
# The decision of ci-impacted-targets.sh after bazel-diff: `classify` turns
# an impacted list and the two candidate lists into impacted_build.txt and
# impacted_test.txt and the flags has_any and has_test. Fed with fixture
# lists, so the logic is covered without bazel-diff or Bazel.
set -euo pipefail

script="$(cd "$(dirname "$0")" && pwd)/ci-impacted-targets.sh"
[ -r "${script}" ] || script="${TEST_SRCDIR}/_main/bazel/ci-impacted-targets.sh"
# The script is linted on its own, through //bazel:scripts.
# shellcheck source=/dev/null
source "${script}"

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

# The candidate lists, as the queries would answer them: the buildable rules
# (no `manual` rule, so no //:gazelle) and the tests `bazel test //...` runs.
cat >"${work}/rules.txt" <<'EOF'
//integration/e2e:e2e_test
//internal/version:version
//internal/version:version_test
//intermediateca/v1:intermediatecav1_proto_lint_test
//intermediateca/v1:intermediateca
//rotator:rotator
//rotator:rotator_test
//rotator:zip_linux_amd64
//upstream-secretsmanager:image_load
//upstream-secretsmanager:image_push
//upstream-secretsmanager:upstream-secretsmanager
//upstream-secretsmanager:upstream-secretsmanager_test
EOF
cat >"${work}/tests.txt" <<'EOF'
//integration/e2e:e2e_test
//internal/version:version_test
//intermediateca/v1:intermediatecav1_proto_lint_test
//rotator:rotator_test
//upstream-secretsmanager:upstream-secretsmanager_test
EOF

fail=0
# expect <case> <impacted lines> <want build> <want test>: runs
# classify over the fixture lists and compares the three lists and flags.
# The lists are given one label per line, as bazel-diff sorts them.
expect() {
	local name="$1" impacted="$2" want_build="$3" want_test="$4"
	local out="${work}/${name}" want_any want_has_test
	mkdir -p "${out}"
	printf '%s' "${impacted}" >"${out}/impacted.txt"
	has_any='' has_test=''
	if ! classify "${out}/impacted.txt" "${work}/rules.txt" "${work}/tests.txt" "${out}"; then
		echo "FAIL: ${name}: classify failed" >&2
		fail=1
		return
	fi
	check_list "${name}" impacted_build.txt "${out}" "${want_build}"
	check_list "${name}" impacted_test.txt "${out}" "${want_test}"
	want_any=false
	[ -n "${want_build}" ] && want_any=true
	want_has_test=false
	[ -n "${want_test}" ] && want_has_test=true
	check_flag "${name}" has_any "${has_any}" "${want_any}"
	check_flag "${name}" has_test "${has_test}" "${want_has_test}"
}
check_list() { # case file dir want
	local got
	got="$(cat "$3/$2")"
	if [ "${got}" != "$4" ]; then
		echo "FAIL: $1: $2 is:" >&2
		sed 's/^/    /' "$3/$2" >&2
		echo "  want:" >&2
		printf '%s\n' "$4" | sed 's/^/    /' >&2
		fail=1
	fi
}
check_flag() { # case name got want
	if [ "$3" != "$4" ]; then
		echo "FAIL: $1: $2 is '$3', want '$4'" >&2
		fail=1
	fi
}

# Nothing impacted (a documentation-only change): every list empty, every
# flag false, and it is the classification saying so, not a failure.
expect nothing "" "" ""

# A change to the plugin's main package: its library, binary, test and
# image, and the end-to-end test that runs the binary. Source-file labels
# (main.go), a rule in no candidate list (image_index) and a `manual` rule
# (//:gazelle) are dropped.
expect plugin "//:gazelle
//integration/e2e:e2e_test
//upstream-secretsmanager:image_index
//upstream-secretsmanager:image_load
//upstream-secretsmanager:image_push
//upstream-secretsmanager:main.go
//upstream-secretsmanager:upstream-secretsmanager
//upstream-secretsmanager:upstream-secretsmanager_test
" "//integration/e2e:e2e_test
//upstream-secretsmanager:image_load
//upstream-secretsmanager:image_push
//upstream-secretsmanager:upstream-secretsmanager
//upstream-secretsmanager:upstream-secretsmanager_test" "//integration/e2e:e2e_test
//upstream-secretsmanager:upstream-secretsmanager_test"

# A change to the Lambda: its binary, zip and test, and the end-to-end test
# that runs its rotation code; nothing of the plugin.
expect rotator "//integration/e2e:e2e_test
//rotator:main.go
//rotator:rotator
//rotator:rotator_test
//rotator:zip_linux_amd64
" "//integration/e2e:e2e_test
//rotator:rotator
//rotator:rotator_test
//rotator:zip_linux_amd64" "//integration/e2e:e2e_test
//rotator:rotator_test"

# A change to the secret format's proto: its buf lint test runs; the source
# file's label is dropped.
expect proto "//intermediateca/v1:intermediatecav1_proto_lint_test
//intermediateca/v1:secret.proto
" "//intermediateca/v1:intermediatecav1_proto_lint_test" "//intermediateca/v1:intermediatecav1_proto_lint_test"

# A rule that is not a test: built, nothing tested.
expect image "//upstream-secretsmanager:image_load
" "//upstream-secretsmanager:image_load" ""

# Labels in no candidate list (an external target, a removed-looking label):
# nothing to build, and still a classification.
expect foreign "@rules_go//go:def.bzl
//gone:gone
" "" ""

# An impacted label is matched whole: //internal/version:version is not
# matched by the prefix of //internal/version:version_test, and the reverse.
expect whole "//internal/version:version
" "//internal/version:version" ""

# classify fails, rather than answering, when a candidate list is unreadable.
if classify "${work}/plugin/impacted.txt" "${work}/missing.txt" "${work}/tests.txt" "${work}/plugin" 2>/dev/null; then
	echo "FAIL: classify succeeded with a missing candidate list" >&2
	fail=1
fi

[ "${fail}" -eq 0 ] || exit 1
echo PASS
