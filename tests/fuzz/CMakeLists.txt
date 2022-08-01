set(JSON_FUZZ_ENGINE "afl++" CACHE STRING "The engine to use for fuzz testing.")
set(JSON_FUZZ_TARGETS "json;bjdata;bson;cbor;msgpack;ubjson" CACHE STRING "List of targets/formats to fuzz test.")
set(JSON_FUZZ_SANITIZERS "asan+cfisan+lsan+ubsan;msan" CACHE STRING "List of sanitizers/combinations of sanitizers to build fuzzers for.")
set(JSON_FUZZ_CORPUS_MAX_SIZE "5k" CACHE STRING "Maximum file size for corpus data.")
option(JSON_FUZZ_MINIMIZE_CORPUS "Minimize the corpa generated from test data." ON)
set(JSON_FUZZ_TEMP_DIR "" CACHE PATH "Path to temporary directory. Should be on a tmpfs or equivalent (AFL++).")
set(JSON_FUZZ_NUM_JOBS 8 CACHE STRING "Number of parallel fuzzing jobs.")
set(JSON_FUZZ_AFL_DIR "" CACHE PATH "Path to AFL++.")
set(JSON_FUZZ_AFL_INSTRUMENTATIONS "laf-intel;complog" CACHE STRING "List of AFL++ instrumentations to build fuzzers for.")

option(JSON_FUZZ_AFL_EXIT_WHEN_DONE "Exit fuzzer when no new paths have been discovered for a while." ON)

set(JSON_FUZZ_MAX_TIME "" ON)

include(fuzz)

# find_program() requires permission to execute but not to read
cmake_policy(SET CMP0109 NEW)

#############################################################################
# validate settings
#############################################################################

# check fuzz engine
string(TOLOWER "${JSON_FUZZ_ENGINE}" fuzz_engine)
if(NOT "${fuzz_engine}" STREQUAL "afl++")
    message(FATAL_ERROR "Unsupoorted fuzz engine: ${fuzz_engine}")
endif()
set(JSON_FUZZ_ENGINE "${fuzz_engine}" CACHE STRING "" FORCE)

if(${JSON_FUZZ_ENGINE} STREQUAL afl++)
    # find compiler
    find_program (JSON_FUZZ_CXX_COMPILER
        NAMES afl-clang-lto++ afl-clang-fast++
        DOC "AFL++ C++ compiler" REQUIRED)
    find_program (JSON_FUZZ_AFL_FUZZ
        NAMES afl-fuzz
        DOC "AFL++ fuzzer runner" REQUIRED)
    if(JSON_FUZZ_MINIMIZE_CORPUS)
        find_program (JSON_FUZZ_AFL_CMIN
            NAMES afl-cmin
            DOC "AFL++ corpus minimizer" REQUIRED)
    endif()
elseif(${JSON_FUZZ_ENGINE} STREQUAL libfuzzer)
    if(CMAKE_CXX_COMPILER_ID STREQUAL Clang)
        set(JSON_FUZZ_CXX_COMPILER "${CMAKE_CXX_COMPILER}")
    endif()
    find_program (JSON_FUZZ_CXX_COMPILER
        NAMES clang++
        DOC "Clang C++ compiler" REQUIRED)
endif()

# TODO does libFuzzer hammer the disk as much as AFL++?
if(${JSON_FUZZ_ENGINE} STREQUAL afl++)
    if(NOT JSON_FUZZ_TEMP_DIR)
        # try to default AFL++ temp. directory to XDG_RUNTIME_DIR on Linux
        if(UNIX AND NOT APPLE AND DEFINED ENV{XDG_RUNTIME_DIR})
            find_program(mount_program mount)
            if(mount_program)
                execute_process(COMMAND ${mount_program}
                    OUTPUT_VARIABLE mount_output
                    ERROR_QUIET)
                string(REGEX MATCH "[^ ]+ on $ENV{XDG_RUNTIME_DIR}(/[^ ]*)? type tmpfs" mount_match "${mount_output}")
                if(mount_match)
                    string(RANDOM suffix)
                    set(temp_dir "$ENV{XDG_RUNTIME_DIR}/json_fuzz_tmp.${suffix}")
                    set(JSON_FUZZ_TEMP_DIR "${temp_dir}" CACHE PATH "" FORCE)
                endif()
            endif()
        endif()
    endif()

    if(NOT JSON_FUZZ_TEMP_DIR)
        message(WARNING "JSON_FUZZ_TEMP_DIR should point to a directory on an in-memory file system.")
        string(RANDOM suffix)
        set(temp_dir "$ENV{CMAKE_CURRENT_BINARY_DIR}/json_fuzz_tmp.${suffix}")
        set(JSON_FUZZ_TEMP_DIR "${temp_dir}" CACHE PATH "" FORCE)
    endif()

    message(STATUS "Temporary directory for fuzzing: ${JSON_FUZZ_TEMP_DIR}")
endif()

#############################################################################
# set up fuzzing
#############################################################################

foreach(target ${JSON_FUZZ_TARGETS})
    json_fuzz_add_fuzzers(${target}
        SOURCES src/fuzzer-parse_${target}.cpp
        ENGINE ${JSON_FUZZ_ENGINE}
        SANITIZERS ${JSON_FUZZ_SANITIZERS}
        INSTRUMENTATIONS ${JSON_FUZZ_AFL_INSTRUMENTATIONS})

    json_fuzz_add_corpus(${target} GLOB "**/*.${target}"
        MAX_SIZE ${JSON_FUZZ_CORPUS_MAX_SIZE})

    if(JSON_FUZZ_MINIMIZE_CORPUS)
        json_fuzz_minimize_corpus(${target}
            ENGINE ${JSON_FUZZ_ENGINE})
    endif()

    json_fuzz_add_fuzz_run_target(${target}
        TEMP_DIR "${JSON_FUZZ_TEMP_DIR}")
endforeach()
