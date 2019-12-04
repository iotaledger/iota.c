cc_library(
    name = "requests",
    srcs = glob([
        "*.c",
    ]),
    hdrs = glob([
        "*.h",
    ]),
    visibility = ["//visibility:public"],
    deps = [
        "@org_iota_common//common:errors",
        "@org_iota_common//common/model:transaction",
        "@org_iota_common//utils/containers/hash:hash243_queue",
        "@org_iota_common//utils/containers/hash:hash81_queue",
        "@org_iota_common//utils/containers/hash:hash_array",
    ],
)
