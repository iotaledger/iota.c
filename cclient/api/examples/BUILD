package(default_visibility = ["//visibility:public"])

cc_binary(
    name = "cclient_examples",
    srcs = glob([
        "*.c",
        "*.h",
    ]),
    deps = [
        "//cclient/api",
        "@org_iota_common//utils:logger_helper",
    ],
)
