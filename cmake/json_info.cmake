#############################################################################
# cmake info
#############################################################################

message(STATUS "[nohmann_json]: CMake ${CMAKE_VERSION}")

#############################################################################
# system info
#############################################################################

set(distrib_name "")
if(CMAKE_VERSION VERSION_EQUAL "3.22" OR CMAKE_VERSION VERSION_GREATER "3.22")
    cmake_host_system_information(RESULT distrib_name QUERY DISTRIB_PRETTY_NAME)
    if(distrib_name)
        set(distrib_name " (${distrib_name})")
    endif()
endif()

message(STATUS "[nohmann_json]: Host system: ${CMAKE_HOST_SYSTEM}${distrib_name}")
if(NOT CMAKE_SYSTEM STREQUAL CMAKE_HOST_SYSTEM)
    message(STATUS "[nohmann_json]: Target system: ${CMAKE_SYSTEM}")
endif()

if(DEFINED ENV{CI})
    # print additional info in CI environment
    cmake_host_system_information(RESULT num_cores QUERY NUMBER_OF_PHYSICAL_CORES)
    cmake_host_system_information(RESULT num_threads QUERY NUMBER_OF_LOGICAL_CORES)
    if(num_threads)
        set(num_threads " (${num_threads})")
    endif()
    if(num_cores)
        message(STATUS "[nohmann_json]: Processor cores: ${num_cores}${num_threads}")
    endif()
endif()

#############################################################################
# compiler info
#############################################################################

execute_process(COMMAND ${CMAKE_CXX_COMPILER} --version OUTPUT_VARIABLE cxx_version_result OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_VARIABLE cxx_version_result_error ERROR_STRIP_TRAILING_WHITESPACE)
if(NOT cxx_version_result_error)
    string(REGEX REPLACE ";" "\\\\;" cxx_version_result "${cxx_version_result}")
    string(REGEX REPLACE "\n" ";" cxx_version_result "${cxx_version_result}")
    list(GET cxx_version_result 0 cxx_version_result)
    message(STATUS "[nohmann_json]: C++ compiler: ${cxx_version_result}")
endif()

if(MSVC)
    message(STATUS "[nohmann_json]: MSVC version: ${MSVC_VERSION}")
    message(STATUS "[nohmann_json]: MSVC toolset version: ${MSVC_TOOLSET_VERSION}")
endif()
