package(default_visibility = ["//visibility:public"])

exports_files([
    "LICENSE.MIT",
    "NOTICE"
])

load(":nlohmann_json.bzl", "nlohmann_json_hdrs", "nlohmann_json_srcs")

cc_library(
    name = "nlohmann_json",
    srcs = nlohmann_json_srcs,
    hdrs = nlohmann_json_hdrs,
    deps = [],
)
