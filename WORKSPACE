workspace(name = "org_iota_client")

load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

#maybe(
#    http_archive,
#    name = "bazel_skylib",
#    sha256 = "1dde365491125a3db70731e25658dfdd3bc5dbdfd11b840b3e987ecf043c7ca0",
#    url = "https://github.com/bazelbuild/bazel-skylib/releases/download/0.9.0/bazel_skylib-0.9.0.tar.gz",
#)
#
#load("@bazel_skylib//:workspace.bzl", "bazel_skylib_workspace")
#
#bazel_skylib_workspace()

git_repository(
    name = "org_iota_common",
    commit = "6ef2af84950f56c8489623e9672c4ac882bb3961",
    remote = "git@github.com:iotaledger/iota_common.git",
)

#local_repository(
#    name = "org_iota_common",
#    path = "iota_core",
#)

git_repository(
    name = "rules_iota",
    commit = "e08b0038f376d6c82b80f5283bb0a86648bb58dc",
    remote = "https://github.com/iotaledger/rules_iota.git",
)

load("@rules_iota//:defs.bzl", "iota_deps")
iota_deps()
