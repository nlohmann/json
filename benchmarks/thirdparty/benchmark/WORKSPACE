workspace(name = "com_github_google_benchmark")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "rules_cc",
    strip_prefix = "rules_cc-a508235df92e71d537fcbae0c7c952ea6957a912",
    urls = ["https://github.com/bazelbuild/rules_cc/archive/a508235df92e71d537fcbae0c7c952ea6957a912.zip"],
)

http_archive(
    name = "com_google_absl",
    sha256 = "f41868f7a938605c92936230081175d1eae87f6ea2c248f41077c8f88316f111",
    strip_prefix = "abseil-cpp-20200225.2",
    urls = ["https://github.com/abseil/abseil-cpp/archive/20200225.2.tar.gz"],
)

http_archive(
    name = "com_google_googletest",
    strip_prefix = "googletest-3f0cf6b62ad1eb50d8736538363d3580dd640c3e",
    urls = ["https://github.com/google/googletest/archive/3f0cf6b62ad1eb50d8736538363d3580dd640c3e.zip"],
)

http_archive(
    name = "pybind11",
    build_file = "@//bindings/python:pybind11.BUILD",
    sha256 = "1eed57bc6863190e35637290f97a20c81cfe4d9090ac0a24f3bbf08f265eb71d",
    strip_prefix = "pybind11-2.4.3",
    urls = ["https://github.com/pybind/pybind11/archive/v2.4.3.tar.gz"],
)

new_local_repository(
    name = "python_headers",
    build_file = "@//bindings/python:python_headers.BUILD",
    path = "/usr/include/python3.6",  # May be overwritten by setup.py.
)
