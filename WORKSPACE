workspace(name = "org_iota_client")

load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

git_repository(
    name = "org_iota_common",
    commit = "f4959c5b4985135139bfe3e1ab44472e859d065f",
    remote = "https://github.com/iotaledger/iota_common.git",
)

git_repository(
    name = "rules_iota",
    commit = "e08b0038f376d6c82b80f5283bb0a86648bb58dc",
    remote = "https://github.com/iotaledger/rules_iota.git",
)

git_repository(
    name = "iota_toolchains",
    commit = "700904f445d15ef948d112bf0bccf7dd3814ae5c",
    remote = "https://github.com/iotaledger/toolchains.git",
)

load("@rules_iota//:defs.bzl", "iota_deps")

iota_deps()

load("@iota_toolchains//:toolchains.bzl", "setup_initial_deps")

setup_initial_deps()

load("@iota_toolchains//:defs.bzl", "setup_toolchains_repositories")

setup_toolchains_repositories()
