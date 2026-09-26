# generate Bazel BUILD file
#
# usage: cmake -P cmake/scripts/gen_bazel_build_file.cmake (or: make BUILD.bazel)
#
# The header list of the "json" target is derived from the files in include/. Everything else is fixed text below,
# so edit this script rather than BUILD.bazel.

get_filename_component(PROJECT_ROOT "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
set(BUILD_FILE "${PROJECT_ROOT}/BUILD.bazel")

file(GLOB_RECURSE HEADERS LIST_DIRECTORIES false RELATIVE "${PROJECT_ROOT}" "${PROJECT_ROOT}/include/*.hpp")
list(SORT HEADERS)

set(CONTENT [=[
load("@rules_cc//cc:cc_library.bzl", "cc_library")
load("@rules_license//rules:license.bzl", "license")

package(
    default_applicable_licenses = [":license"],
)

exports_files([
    "LICENSE.MIT",
])

license(
    name = "license",
    license_kinds = ["@rules_license//licenses/spdx:MIT"],
    license_text = "LICENSE.MIT",
)

cc_library(
    name = "json",
    hdrs = [
]=])

foreach(header ${HEADERS})
    string(APPEND CONTENT "        \"${header}\",\n")
endforeach()

string(APPEND CONTENT [=[
    ],
    includes = ["include"],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "singleheader-json",
    hdrs = [
        "single_include/nlohmann/json.hpp",
    ],
    includes = ["single_include"],
    visibility = ["//visibility:public"],
)
]=])

file(WRITE "${BUILD_FILE}" "${CONTENT}")
