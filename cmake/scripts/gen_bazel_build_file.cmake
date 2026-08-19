# Re-generate Bazel BUILD file.

set(PROJECT_ROOT "${CMAKE_CURRENT_LIST_DIR}/../..")
set(BUILD_FILE "${PROJECT_ROOT}/BUILD.bazel")

# Find the current set of header file names.
file(GLOB_RECURSE HEADERS LIST_DIRECTORIES false RELATIVE "${PROJECT_ROOT}" "include/*.hpp")
list(SORT HEADERS CASE SENSITIVE)

# Read the existing BUILD file.
file(READ "${BUILD_FILE}" BUILD_CONTENT)

# Generate the replacement content.
set(START_MARKER "# BEGIN GENERATED HDRS LIST")
set(END_MARKER "# END GENERATED HDRS LIST")
set(REPLACEMENT "${START_MARKER}\n    hdrs = [\n")
foreach(header ${HEADERS})
    string(APPEND REPLACEMENT "        \"${header}\",\n")
endforeach()
string(APPEND REPLACEMENT "    ],\n    ${END_MARKER}")

# Find the existing PREFIX and SUFFIX surrounding the content.
string(FIND "${BUILD_CONTENT}" "${START_MARKER}" START_POS)
string(FIND "${BUILD_CONTENT}" "${END_MARKER}" END_POS)
if(START_POS EQUAL -1 OR END_POS EQUAL -1)
    message(FATAL_ERROR "Markers not found in BUILD.bazel")
endif()
string(SUBSTRING "${BUILD_CONTENT}" 0 ${START_POS} PREFIX)
string(LENGTH "${END_MARKER}" END_MARKER_LEN)
math(EXPR SUFFIX_POS "${END_POS} + ${END_MARKER_LEN}")
string(SUBSTRING "${BUILD_CONTENT}" ${SUFFIX_POS} -1 SUFFIX)

# Write out the updated file (or fail when in CHECK mode).
set(NEW_BUILD_CONTENT "${PREFIX}${REPLACEMENT}${SUFFIX}")
if("${BUILD_CONTENT}" STREQUAL "${NEW_BUILD_CONTENT}")
    message(STATUS "BUILD.bazel is up to date.")
else()
    if(CHECK)
        message(FATAL_ERROR "BUILD.bazel is stale. Run 'make update_bazel' to update it.")
    else()
        file(WRITE "${BUILD_FILE}" "${NEW_BUILD_CONTENT}")
        message(STATUS "Updated ${BUILD_FILE}")
    endif()
endif()
