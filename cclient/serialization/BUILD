cc_library(
    name = "serializer_json",
    srcs = glob([
        "json/*.c",
    ]),
    hdrs = glob([
        "json/*.h",
    ]),
    visibility = ["//visibility:public"],
    deps = [
        ":serializer",
        "@cJSON",
        "@com_github_uthash//:uthash",
        "@org_iota_common//utils:logger_helper",
        "@org_iota_common//utils/containers/hash:hash243_queue",
        "@org_iota_common//utils/containers/hash:hash243_stack",
        "@org_iota_common//utils/containers/hash:hash8019_queue",
        "@org_iota_common//utils/containers/hash:hash8019_stack",
        "@org_iota_common//utils/containers/hash:hash81_queue",
        "@org_iota_common//utils/containers/hash:hash_array",
    ],
    alwayslink = True,
)

cc_library(
    name = "serializer",
    hdrs = glob([
        "serializer.h",
    ]),
    visibility = ["//visibility:public"],
    deps = [
        "//cclient/request:requests",
        "//cclient/response:responses",
    ],
)
