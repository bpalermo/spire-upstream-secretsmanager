#!/usr/bin/env bash
# The registry is ONE setting: bazel/registry.bzl.
#
# Moving registries is only a one-file edit while nothing else spells the
# registry out, and a review cannot be trusted to keep that true: a literal
# pasted into a workflow keeps working until the day a move leaves it pointing
# at the old registry. So this asserts, on every change:
#
#   1. bazel/registry.sh parses the setting.
#   2. Every image a BUILD file publishes (`image_repository("<name>")`) is
#      one bazel/registry.sh prints as <NAME>_IMAGE: the release workflow
#      pushes, signs and verifies what that prints, so an image missing from
#      it is published by nothing.
#   3. No tracked file outside the allow-list contains `<host>/<namespace>`,
#      computed from the setting, not typed here.
#
# The literal hunt runs a positive control first, so it cannot pass by matching
# nothing.
#
# ALLOW-LIST:
#   bazel/registry.bzl             the setting
#   bazel/registry.sh              its usage text
#   bazel/check-registry-config.sh
#   README.md                      install commands people copy
# Other documentation is not exempt by default: add it here, with the reason,
# when it first needs the literal.
#
# Run from a checkout: the hunt is a `git grep` over the tracked files of the
# repository this script is in (the `lint` job of ci.yml runs it on every
# change; //bazel:check_registry_config_test runs it on fixtures). No network,
# no Bazel. Exit 0 clean, 1 on a violation, 2 when the check itself cannot run.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2

fail=0
bad() {
	echo "::error::$*"
	fail=1
}

component=spire-upstream-secretsmanager

# --- 1. the setting parses ---------------------------------------------------
if ! host="$(bazel/registry.sh host)" || ! image="$(bazel/registry.sh ref "${component}")" ||
	! ns_repo="$(bazel/registry.sh repo "${component}")" || [ -z "$host" ] || [ -z "$image" ]; then
	echo "::error::bazel/registry.sh cannot parse bazel/registry.bzl" >&2
	exit 2
fi
namespace="${ns_repo%/"${component}"}"
echo "setting: ${host}/${namespace}"

esc() { printf '%s' "$1" | sed -E 's/[][\.^$*+?(){}|/]/\\&/g'; }

# --- 2. every published image is in registry.sh's environment ---------------
if ! env_lines="$(bazel/registry.sh)"; then
	echo "::error::bazel/registry.sh cannot print its environment" >&2
	exit 2
fi
components="$(git grep -hoP -- 'image_repository\("\K[a-z0-9._-]+(?="\))' -- '*BUILD.bazel' '*BUILD' | sort -u)"
if [ -z "$components" ]; then
	echo "::error::no BUILD file publishes an image with image_repository(...) -- the search is broken" >&2
	exit 2
fi
for c in $components; do
	key="$(printf '%s' "$c" | tr 'a-z.-' 'A-Z__')_IMAGE"
	want="${key}=${host}/${namespace}/${c}"
	if ! grep -qxF -- "$want" <<<"$env_lines"; then
		bad "a BUILD file publishes image_repository(\"${c}\"), but bazel/registry.sh does not print ${want}: add it, and the image to the lists of ci.yml and release.yml"
	else
		echo "ok: bazel/registry.sh prints ${key}"
	fi
done

# --- 3. no literal outside the allow-list ------------------------------------
allow=(
	':(exclude)bazel/registry.bzl'
	':(exclude)bazel/registry.sh'
	':(exclude)bazel/check-registry-config.sh'
	# People copy install commands from the README, so it may spell the
	# registry out. Moving registries is bazel/registry.bzl plus this file.
	':(exclude)README.md'
)
pattern="$(esc "${host}/${namespace}")(?![[:alnum:]_.-])"
for probe in "registry: ${host}/${namespace}" "image=${image}@sha256:0"; do
	if ! printf '%s\n' "$probe" | grep -qP -- "$pattern"; then
		echo "::error::the literal hunt does not match '${probe}' -- the pattern is broken" >&2
		exit 2
	fi
done
hits="$(git grep -nP -- "$pattern" -- . "${allow[@]}")"
rc=$?
case "$rc" in
0)
	bad "the registry is spelled out outside bazel/registry.bzl. Derive it (Bazel: load //bazel:registry.bzl; shell and workflows: bazel/registry.sh), or add the path to the allow-list in bazel/check-registry-config.sh with a reason:"
	printf '%s\n' "$hits" | sed 's/^/  /'
	;;
1) echo "ok: no registry literal outside the allow-list" ;;
*)
	echo "::error::git grep failed (exit ${rc})" >&2
	exit 2
	;;
esac

[ "$fail" -eq 0 ] || exit 1
echo "registry config: one setting, bazel/registry.bzl"
