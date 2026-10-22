#!/usr/bin/env bash
# Fail if the protos in this checkout break the contract of an earlier commit:
# a field renumbered, retyped or reused, something deleted without its number
# reserved, a JSON name changed. The rules are `breaking` in buf.yaml. Every
# proto_library of this repository is checked: the secret format
# (intermediateca/v1, read and written by programs released separately), the
# rotator's configuration (config/v1) and whatever else is added.
#
# Both sides are compiled by Bazel, each from its own tree, and compared by
# the buf that MODULE.bazel pins; buf compiles nothing. The earlier commit is
# checked out into a git worktree outside this one, always at the same path so
# that its Bazel output base is reused.
#
# Usage:
#   bazel/proto/breaking.sh [<ref>] [<bazel flag>...]
#
# <ref> is what to compare against, by default origin/main. The comparison is
# with the commit this checkout branched from it, so a branch behind <ref> is
# not blamed for what <ref> has gained since.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

ref="origin/main"
if [[ $# -gt 0 && "$1" != -* ]]; then
	ref="$1"
	shift
fi
base="$(git merge-base HEAD "${ref}")"

# image <tree> <output> [<bazel flag>...] writes the descriptors of the
# tree's own protos and of everything they import, as one FileDescriptorSet:
# buf resolves the imports from its input.
image() {
	local tree="$1" output="$2"
	shift 2
	(
		cd "${tree}"
		local roots labels query
		# The tree's own proto_library targets, named: they are cquery's
		# universe, so nothing else of the tree is configured.
		mapfile -t roots < <(bazel query "$@" "kind('^proto_library rule\$', //...)" --output=label 2>/dev/null)
		[[ ${#roots[@]} -gt 0 ]] || {
			echo "breaking: no proto_library in ${tree}" >&2
			exit 2
		}
		# In the target configuration only: after a build, cquery also
		# answers with the configurations other rules built the same protos
		# in, and each file would be in the image once per configuration.
		query="config(kind('^proto_library rule$', deps(set(${roots[*]}))), target)"
		mapfile -t labels < <(bazel cquery "$@" "${query}" --output=label 2>/dev/null | cut -d' ' -f1)
		bazel build "$@" -- "${labels[@]}"
		# A serialized message with one repeated field: concatenating merges.
		bazel cquery "$@" "${query}" --output=files 2>/dev/null | xargs cat >"${output}"
	)
	[[ -s "${output}" ]] || {
		echo "breaking: no descriptors were built in ${tree}" >&2
		exit 2
	}
}

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

baseline="${XDG_CACHE_HOME:-${HOME}/.cache}/spire-upstream-secretsmanager/proto-baseline"
if [[ -e "${baseline}/.git" ]]; then
	git -C "${baseline}" checkout --quiet --detach "${base}"
else
	mkdir -p "$(dirname "${baseline}")"
	git worktree prune
	git worktree add --quiet --detach "${baseline}" "${base}"
fi

# This checkout's proto packages. One the earlier commit does not have has no
# contract to break yet: it is new, or it was moved (a renamed proto package
# is a new API).
mapfile -t packages < <(bazel query "$@" "kind('^proto_library rule\$', //...)" --output=package 2>/dev/null | sort -u)
[[ ${#packages[@]} -gt 0 ]] || {
	echo "breaking: no proto_library in this checkout" >&2
	exit 2
}
compared=()
for p in "${packages[@]}"; do
	if compgen -G "${baseline}/${p}/*.proto" >/dev/null; then
		compared+=("${p}")
	fi
done
if [[ ${#compared[@]} -eq 0 ]]; then
	echo "breaking: ${base:0:12} has none of ${packages[*]}, nothing to compare"
	exit 0
fi

image "${baseline}" "${work}/base.binpb" "$@"
image "${PWD}" "${work}/head.binpb" "$@"

# --path keeps the check to this repository's own files: the images also hold
# what they import, and a dependency's change is not ours to refuse.
paths=()
for p in "${compared[@]}"; do
	paths+=(--path "${p}")
done
bazel run "$@" @rules_buf_toolchains//:buf -- breaking "${work}/head.binpb" \
	--against "${work}/base.binpb" --config "${PWD}/buf.yaml" "${paths[@]}"
echo "breaking: no breaking change in ${compared[*]} since ${base:0:12}"
