# CMake

You can also use the `nlohmann_json::nlohmann_json` interface target in CMake.  This target populates the appropriate usage requirements for `INTERFACE_INCLUDE_DIRECTORIES` to point to the appropriate include directories and `INTERFACE_COMPILE_FEATURES` for the necessary C++11 flags.

## External

To use this library from a CMake project, you can locate it directly with `find_package()` and use the namespaced imported target from the generated package configuration:

```cmake
# CMakeLists.txt
find_package(nlohmann_json 3.2.0 REQUIRED)
...
add_library(foo ...)
...
target_link_libraries(foo PRIVATE nlohmann_json::nlohmann_json)
```

The package configuration file, `nlohmann_jsonConfig.cmake`, can be used either from an install tree or directly out of the build tree.

## Embedded

To embed the library directly into an existing CMake project, place the entire source tree in a subdirectory and call `add_subdirectory()` in your `CMakeLists.txt` file:

```cmake
# Typically you don't care so much for a third party library's tests to be
# run from your own project's code.
set(JSON_BuildTests OFF CACHE INTERNAL "")

# If you only include this third party in PRIVATE source files, you do not
# need to install it when your main project gets installed.
# set(JSON_Install OFF CACHE INTERNAL "")

# Don't use include(nlohmann_json/CMakeLists.txt) since that carries with it
# unintended consequences that will break the build.  It's generally
# discouraged (although not necessarily well documented as such) to use
# include(...) for pulling in other CMake projects anyways.
add_subdirectory(nlohmann_json)
...
add_library(foo ...)
...
target_link_libraries(foo PRIVATE nlohmann_json::nlohmann_json)
```

## Embedded (FetchContent)

Since CMake v3.11,
[FetchContent](https://cmake.org/cmake/help/v3.11/module/FetchContent.html) can
be used to automatically download the repository as a dependency at configure type.

Example:
```cmake
include(FetchContent)

FetchContent_Declare(json
  GIT_REPOSITORY https://github.com/nlohmann/json
  GIT_TAG v3.7.3)

FetchContent_GetProperties(json)
if(NOT json_POPULATED)
  FetchContent_Populate(json)
  add_subdirectory(${json_SOURCE_DIR} ${json_BINARY_DIR} EXCLUDE_FROM_ALL)
endif()

target_link_libraries(foo PRIVATE nlohmann_json::nlohmann_json)
```

!!! Note
	The repository <https://github.com/nlohmann/json> download size is huge.
	It contains all the dataset used for the benchmarks. You might want to depend on
	a smaller repository. For instance, you might want to replace the URL above by
	<https://github.com/ArthurSonzogni/nlohmann_json_cmake_fetchcontent>.

## Supporting Both

To allow your project to support either an externally supplied or an embedded JSON library, you can use a pattern akin to the following:

``` cmake
# Top level CMakeLists.txt
project(FOO)
...
option(FOO_USE_EXTERNAL_JSON "Use an external JSON library" OFF)
...
add_subdirectory(thirdparty)
...
add_library(foo ...)
...
# Note that the namespaced target will always be available regardless of the
# import method
target_link_libraries(foo PRIVATE nlohmann_json::nlohmann_json)
```
```cmake
# thirdparty/CMakeLists.txt
...
if(FOO_USE_EXTERNAL_JSON)
  find_package(nlohmann_json 3.2.0 REQUIRED)
else()
  set(JSON_BuildTests OFF CACHE INTERNAL "")
  add_subdirectory(nlohmann_json)
endif()
...
```

`thirdparty/nlohmann_json` is then a complete copy of this source tree.
