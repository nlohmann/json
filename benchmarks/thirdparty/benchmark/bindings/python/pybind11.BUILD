cc_library(
    name = "pybind11",
    hdrs = glob(
        include = [
            "include/pybind11/*.h",
            "include/pybind11/detail/*.h",
        ],
        exclude = [
            "include/pybind11/common.h",
            "include/pybind11/eigen.h",
        ],
    ),
    copts = [
        "-fexceptions",
        "-Wno-undefined-inline",
        "-Wno-pragma-once-outside-header",
    ],
    includes = ["include"],
    visibility = ["//visibility:public"],
)
