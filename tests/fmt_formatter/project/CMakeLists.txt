cmake_minimum_required(VERSION 3.14)

project(FmtFormatterTest CXX)

include(FetchContent)

get_filename_component(GIT_REPOSITORY_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../../.. ABSOLUTE)
FetchContent_Declare(json GIT_REPOSITORY ${GIT_REPOSITORY_DIRECTORY} GIT_TAG HEAD)

set(FMT_TEST OFF CACHE BOOL "" FORCE)
set(FMT_DOC OFF CACHE BOOL "" FORCE)
set(FMT_INSTALL OFF CACHE BOOL "" FORCE)
FetchContent_Declare(fmt
  GIT_REPOSITORY https://github.com/fmtlib/fmt.git
  GIT_TAG 12.2.0
  GIT_SHALLOW TRUE
)

FetchContent_MakeAvailable(json fmt)

if(MSVC)
  add_compile_options(/EHsc)
endif()

add_executable(fmt_formatter_test main.cpp)
target_link_libraries(fmt_formatter_test PRIVATE nlohmann_json::nlohmann_json fmt::fmt)
target_compile_features(fmt_formatter_test PRIVATE cxx_std_17)

# Fail the build itself (and therefore the ctest "build" step that drives it) if the
# recipe's runtime assertions don't hold -- there is no separate "run" step, since the
# executable's location varies by platform/generator, but CMake resolves a target name
# passed to a custom command's COMMAND for us.
add_custom_command(TARGET fmt_formatter_test POST_BUILD
  COMMAND fmt_formatter_test
  COMMENT "Running fmt::formatter<nlohmann::json> recipe test"
)
