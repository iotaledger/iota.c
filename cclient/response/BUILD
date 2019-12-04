cc_library(
    name = "responses",
    srcs = glob([
        "*.c",
    ]),
    hdrs = glob([
        "*.h",
    ]),
    visibility = ["//visibility:public"],
    deps = [
        "@org_iota_common//common:errors",
        "@org_iota_common//utils:char_buffer",
        "@org_iota_common//utils/containers/hash:hash243_queue",
        "@org_iota_common//utils/containers/hash:hash243_stack",
        "@org_iota_common//utils/containers/hash:hash8019_queue",
        "@org_iota_common//utils/containers/hash:hash_array",
    ],
)
