# Generate doctest checks that every JSON_HEDLEY_* macro defined in hedley.hpp
# is undefined after including nlohmann/json.hpp.

if(NOT DEFINED HEDLEY_HPP OR NOT DEFINED OUTPUT)
    message(FATAL_ERROR "HEDLEY_HPP and OUTPUT must be set")
endif()

if(NOT EXISTS "${HEDLEY_HPP}")
    message(FATAL_ERROR "Hedley header not found: ${HEDLEY_HPP}")
endif()

file(READ "${HEDLEY_HPP}" hedley_content)

set(macro_names)
string(REGEX MATCHALL "[ \t]*#[ \t]*define[ \t]+JSON_HEDLEY_[A-Z0-9_]+" defines "${hedley_content}")
foreach(define ${defines})
    string(REGEX REPLACE ".*define[ \t]+(JSON_HEDLEY_[A-Z0-9_]+).*" "\\1" name "${define}")
    list(APPEND macro_names "${name}")
endforeach()

if(NOT macro_names)
    message(FATAL_ERROR "No JSON_HEDLEY_* macros found in ${HEDLEY_HPP}")
endif()

list(REMOVE_DUPLICATES macro_names)
list(SORT macro_names)
list(LENGTH macro_names macro_count)

set(generated "// This file is generated from include/nlohmann/thirdparty/hedley/hedley.hpp.\n")
string(APPEND generated "// Do not edit it by hand. ${macro_count} macros.\n\n")
foreach(name ${macro_names})
    string(APPEND generated "#ifdef ${name}\n")
    string(APPEND generated "    FAIL_CHECK(\"${name} leaked after including nlohmann/json.hpp\");\n")
    string(APPEND generated "#endif\n")
endforeach()

get_filename_component(output_dir "${OUTPUT}" DIRECTORY)
file(MAKE_DIRECTORY "${output_dir}")
file(WRITE "${OUTPUT}" "${generated}")
