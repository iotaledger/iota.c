cc_library(
    name = "api_core",
    srcs = glob([
        "core/*.c",
        "core/*.h",
    ]),
    visibility = ["//visibility:private"],
    deps = [
        "//cclient:service",
        "//cclient/http",
        "@org_iota_common//common:version",
        "@org_iota_common//common/helpers",
        "@org_iota_common//common/model:bundle",
        "@org_iota_common//utils:logger_helper",
    ],
)

cc_library(
    name = "api_extended",
    srcs = glob([
        "extended/*.c",
        "extended/*.h",
    ]),
    visibility = ["//visibility:private"],
    deps = [
        ":api_core",
        "@org_iota_common//common/model:inputs",
        "@org_iota_common//common/model:transfer",
        "@org_iota_common//utils:time",
    ],
)

cc_library(
    name = "api",
    hdrs = glob([
        "core/core_api.h",
        "extended/extended_api.h",
    ]),
    visibility = ["//visibility:public"],
    deps = [
        ":api_extended",
    ],
)

cc_binary(
    name = "libcclient.so",
    linkshared = True,
    visibility = ["//visibility:public"],
    deps = [":api"],
)
