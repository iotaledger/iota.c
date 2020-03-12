workspace(name = "org_iota_client")

load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

git_repository(
    name = "org_iota_common",
    commit = "1b56a5282933fb674181001630e7b2e2c33b5eea",
    remote = "https://github.com/iotaledger/iota_common.git",
)

git_repository(
    name = "rules_iota",
    commit = "2d15c55f12cff0db106f45866312f61314c583cd",
    remote = "https://github.com/iotaledger/rules_iota.git",
)

git_repository(
    name = "iota_toolchains",
    commit = "700904f445d15ef948d112bf0bccf7dd3814ae5c",
    remote = "https://github.com/iotaledger/toolchains.git",
)

load("@rules_iota//:defs.bzl", "iota_client_external")

iota_client_external()

load("@iota_toolchains//:toolchains.bzl", "setup_initial_deps")

setup_initial_deps()

load("@iota_toolchains//:defs.bzl", "setup_toolchains_repositories")

setup_toolchains_repositories()
