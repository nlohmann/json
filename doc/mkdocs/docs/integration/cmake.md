# CMake

## Integration

You can also use the `nlohmann_json::nlohmann_json` interface target in CMake.  This target populates the appropriate usage requirements for `INTERFACE_INCLUDE_DIRECTORIES` to point to the appropriate include directories and `INTERFACE_COMPILE_FEATURES` for the necessary C++11 flags.

### External

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

### Embedded

To embed the library directly into an existing CMake project, place the entire source tree in a subdirectory and call `add_subdirectory()` in your `CMakeLists.txt` file:

```cmake
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

### Embedded (FetchContent)

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
	The repository <https://github.com/nlohmann/json> download size is quite large.
	You might want to depend on a smaller repository. For instance, you might want to replace the URL above by
	<https://github.com/ArthurSonzogni/nlohmann_json_cmake_fetchcontent>.

### Supporting Both

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

## CMake Options

### `JSON_BuildTests`

Build the unit tests when [`BUILD_TESTING`](https://cmake.org/cmake/help/latest/command/enable_testing.html) is enabled. This option is `ON` by default if the library's CMake project is the top project. That is, when integrating the library as described above, the test suite is not built unless explicitly switched on with this option.

### `JSON_CI`

Enable CI build targets. The exact targets are used during the several CI steps and are subject to change without notice. This option is `OFF` by default.

### `JSON_Diagnostics`

Enable [extended diagnostic messages](../home/exceptions.md#extended-diagnostic-messages) by defining macro [`JSON_DIAGNOSTICS`](../features/macros.md#json_diagnostics). This option is `OFF` by default.

### `JSON_FastTests`

Skip expensive/slow test suites. This option is `OFF` by default. Depends on `JSON_BuildTests`.

### `JSON_ImplicitConversions`

Enable implicit conversions by defining macro [`JSON_USE_IMPLICIT_CONVERSIONS`](../features/macros.md#json_use_implicit_conversions). This option is `ON` by default.

### `JSON_Install`

Install CMake targets during install step. This option is `ON` by default if the library's CMake project is the top project.

### `JSON_MultipleHeaders`

Use non-amalgamated version of the library. This option is `OFF` by default.

### `JSON_SystemInclude`

Treat the library headers like system headers (i.e., adding `SYSTEM` to the [`target_include_directories`](https://cmake.org/cmake/help/latest/command/target_include_directories.html) call) to checks for this library by tools like Clang-Tidy. This option is `OFF` by default.

### `JSON_Valgrind`

Execute test suite with [Valgrind](https://valgrind.org). This option is `OFF` by default. Depends on `JSON_BuildTests`.
