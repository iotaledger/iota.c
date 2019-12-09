workspace(name = "org_iota_client")

load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

git_repository(
    name = "org_iota_common",
    commit = "29269df072c793eeb545cc918c19535e9e52a1ee",
    remote = "git@github.com:iotaledger/iota_common.git",
)

git_repository(
    name = "rules_iota",
    commit = "e08b0038f376d6c82b80f5283bb0a86648bb58dc",
    remote = "https://github.com/iotaledger/rules_iota.git",
)

load("@rules_iota//:defs.bzl", "iota_deps")
iota_deps()
