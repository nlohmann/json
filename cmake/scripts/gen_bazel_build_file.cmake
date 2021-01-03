# generate Bazel BUILD file

set(PROJECT_ROOT "${CMAKE_CURRENT_LIST_DIR}/../..")
set(BUILD_FILE "${PROJECT_ROOT}/BUILD.bazel")

file(GLOB_RECURSE HEADERS LIST_DIRECTORIES false RELATIVE "${PROJECT_ROOT}" "include/*.hpp")

file(WRITE "${BUILD_FILE}" [=[
cc_library(
    name = "json",
    hdrs = [
]=])

foreach(header ${HEADERS})
    file(APPEND "${BUILD_FILE}" "        \"${header}\",\n")
endforeach()

file(APPEND "${BUILD_FILE}" [=[
    ],
    includes = ["include"],
    visibility = ["//visibility:public"],
    alwayslink = True,
)
]=])
