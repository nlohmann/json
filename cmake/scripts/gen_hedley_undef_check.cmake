# Shared extractor for JSON_HEDLEY_* names defined in hedley.hpp.
#
#   MODE=checks (default): doctest FAIL_CHECKs written to OUTPUT
#   MODE=undef:            hedley_undef.hpp written to OUTPUT (SPDX header
#                          plus #pragma once plus one #undef per name)
#
# Used by tests/CMakeLists.txt and `make update_hedley_undef` so the leak
# checks and the undef list cannot drift apart.

if(NOT DEFINED HEDLEY_HPP OR NOT DEFINED OUTPUT)
    message(FATAL_ERROR "HEDLEY_HPP and OUTPUT must be set")
endif()

if(NOT EXISTS "${HEDLEY_HPP}")
    message(FATAL_ERROR "Hedley header not found: ${HEDLEY_HPP}")
endif()

if(NOT DEFINED MODE)
    set(MODE checks)
endif()

if(NOT MODE STREQUAL "checks" AND NOT MODE STREQUAL "undef")
    message(FATAL_ERROR "MODE must be checks or undef, got: ${MODE}")
endif()

# Line-anchored, like grep ^[[:blank:]]*#[[:blank:]]*define. Unanchored
# MATCHALL would also see the same names in today's hedley.hpp, but a
# mention inside a comment or string should not become an #undef.
file(STRINGS "${HEDLEY_HPP}" hedley_lines)
set(macro_names)
foreach(line IN LISTS hedley_lines)
    if("${line}" MATCHES "^[ \t]*#[ \t]*define[ \t]+(JSON_HEDLEY_[A-Z0-9_]+)")
        list(APPEND macro_names "${CMAKE_MATCH_1}")
    endif()
endforeach()

if(NOT macro_names)
    message(FATAL_ERROR "No JSON_HEDLEY_* macros found in ${HEDLEY_HPP}")
endif()

list(REMOVE_DUPLICATES macro_names)
# Lexicographic, locale-independent (ASCII names only). Matches LC_ALL=C sort.
list(SORT macro_names COMPARE STRING)
list(LENGTH macro_names macro_count)

if(MODE STREQUAL "undef")
    # Same header `make reuse` would stamp, so the recipe is self-contained
    # and its output is byte-stable.
    set(generated "")
    string(APPEND generated "//     __ _____ _____ _____\n")
    string(APPEND generated "//  __|  |   __|     |   | |  JSON for Modern C++\n")
    string(APPEND generated "// |  |  |__   |  |  | | | |  version 3.12.0\n")
    string(APPEND generated "// |_____|_____|_____|_|___|  https://github.com/nlohmann/json\n")
    string(APPEND generated "//\n")
    string(APPEND generated "// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>\n")
    string(APPEND generated "// SPDX-License-Identifier: MIT\n")
    string(APPEND generated "\n")
    string(APPEND generated "#pragma once\n")
    string(APPEND generated "\n")
    foreach(name IN LISTS macro_names)
        string(APPEND generated "#undef ${name}\n")
    endforeach()
else()
    set(generated "// This file is generated from include/nlohmann/thirdparty/hedley/hedley.hpp.\n")
    string(APPEND generated "// Do not edit it by hand. ${macro_count} macros.\n\n")
    foreach(name IN LISTS macro_names)
        string(APPEND generated "#ifdef ${name}\n")
        string(APPEND generated "    FAIL_CHECK(\"${name} leaked after including nlohmann/json.hpp\");\n")
        string(APPEND generated "#endif\n")
    endforeach()
endif()

get_filename_component(output_dir "${OUTPUT}" DIRECTORY)
if(output_dir)
    file(MAKE_DIRECTORY "${output_dir}")
endif()
file(WRITE "${OUTPUT}" "${generated}")
