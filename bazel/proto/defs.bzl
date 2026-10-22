"""The generated Go of this repository's protos, committed next to them."""

load("@protobuf//bazel:proto_library.bzl", "proto_library")
load("@rules_buf//buf:defs.bzl", "buf_lint_test")
load("@rules_go//proto:def.bzl", "go_proto_library")
load("@rules_shell//shell:sh_binary.bzl", "sh_binary")
load("@rules_shell//shell:sh_test.bzl", "sh_test")

def committed_go_proto(name, src, importpath, deps = [], go_deps = []):
    """A proto, its buf lint, and the generator and freshness test of its .pb.go.

    The generated <src basename>.pb.go is committed, and the go_library that
    Gazelle generates of it (next to this macro, in the same package) is what
    imports of `importpath` mean. The proto rules are hand-written, under
    `# gazelle:proto disable`:

      bazel run //<package>:generate          regenerates the .pb.go
      bazel test //<package>:generated_test   fails if it is stale

    Args:
      name: the proto_library, `<name>`; the generator is `<name>_go_proto`.
      src: the .proto file.
      importpath: the Go import path of the generated package.
      deps: the proto_library targets `src` imports.
      go_deps: the Go packages of those imports, for the generator.
    """
    pb_go = src.removesuffix(".proto") + ".pb.go"

    proto_library(
        name = name,
        srcs = [src],
        visibility = ["//visibility:public"],
        deps = deps,
    )

    # protoc with protoc-gen-go, as rules_go runs them. Only the generated
    # source is ever used, never this target's compiled Go.
    go_proto_library(
        name = name.removesuffix("_proto") + "_go_proto",
        importpath = importpath,
        proto = ":" + name,
        tags = ["manual"],
        deps = go_deps,
    )

    native.filegroup(
        name = "generated",
        srcs = [":" + name.removesuffix("_proto") + "_go_proto"],
        output_group = "go_generated_srcs",
        tags = ["manual"],
    )

    sh_binary(
        name = "generate",
        srcs = ["//bazel/proto:generate.sh"],
        args = [
            "$(rootpath :generated)",
            native.package_name() + "/" + pb_go,
        ],
        data = [":generated"],
        tags = ["manual"],
    )

    sh_test(
        name = "generated_test",
        size = "small",
        srcs = ["//bazel/proto:generated_test.sh"],
        args = [
            "$(rootpath :generated)",
            "$(rootpath " + pb_go + ")",
            "//" + native.package_name() + ":generate",
        ],
        data = [
            pb_go,
            ":generated",
        ],
    )

    buf_lint_test(
        name = name + "_lint_test",
        size = "small",
        config = "//:buf.yaml",
        targets = [":" + name],
    )
