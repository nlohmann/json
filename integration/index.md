# Integration

There are several ways to add this header-only library to a C++ project. The following flowchart summarizes how to pick one:

```
flowchart TD
    A[Add the library to a C++ project] --> B{Already using CMake?}
    B -- no --> C{Using pkg-config or plain Makefiles?}
    C -- yes --> D[pkg-config]
    C -- no --> E[Copy the single header]
    B -- yes --> F{Library installed system-wide?}
    F -- yes --> G["find_package()"]
    F -- no --> H{Use a package manager?}
    H -- yes --> I[Package manager]
    H -- no --> J["add_subdirectory() or FetchContent"]
```

- **Copy the single header**, as described [below](#header-only) — no build-system integration required.
- **CMake**: use [`find_package()`](https://json.nlohmann.me/integration/cmake/#external) if the library is already installed, [`add_subdirectory()`](https://json.nlohmann.me/integration/cmake/#embedded) to embed the source tree, or [`FetchContent`](https://json.nlohmann.me/integration/cmake/#fetchcontent) to download it at configure time; see [CMake](https://json.nlohmann.me/integration/cmake/index.md).
- **Package managers**: install the library with a package manager such as Homebrew, Conan, or vcpkg; see [Package Managers](https://json.nlohmann.me/integration/package_managers/index.md).
- **pkg-config**: if you use bare Makefiles instead of CMake, [pkg-config](https://json.nlohmann.me/integration/pkg-config/index.md) can supply the include flags for an already-installed library.

Once the library is integrated, see the [Migration Guide](https://json.nlohmann.me/integration/migration_guide/index.md) for how to keep your code future-proof across releases.

## Header only

[`json.hpp`](https://github.com/nlohmann/json/blob/develop/single_include/nlohmann/json.hpp) is the single required file in `single_include/nlohmann` or [released here](https://github.com/nlohmann/json/releases). You need to add

```
#include <nlohmann/json.hpp>

// for convenience
using nlohmann::json;
```

to the files you want to process JSON and set the necessary switches to enable C++11 (e.g., `-std=c++11` for GCC and Clang).

Which file do I download?

For a project without a package manager, the library itself, including the `_json` literals, is **one file**: [`json.hpp`](https://github.com/nlohmann/json/releases/latest/download/json.hpp) from the [releases page](https://github.com/nlohmann/json/releases). You do not need to clone the repository, build anything, or link a library. Put the file in a directory named `nlohmann` that is on your include path (for example `third_party/nlohmann/json.hpp` with `-I third_party`), so that `#include <nlohmann/json.hpp>` works. Download the companion headers listed below only if you use them: `json_view.hpp` for the [zero-copy views](https://json.nlohmann.me/features/json_view/index.md), `json_fwd.hpp` for forward declarations, and `json_literals.hpp` if you define `JSON_NO_AUTOMATIC_UDLS`. Keep them in the same `nlohmann` directory.

Do not copy only parts of the repository's `include/` directory: the headers in it include each other and must be kept together. If your IDE reports "cannot open source file" while the compiler succeeds, the compiler's include path is set correctly but the IDE's is not; add the same directory to the IDE's include paths.

You can further use file [`single_include/nlohmann/json_fwd.hpp`](https://github.com/nlohmann/json/blob/develop/single_include/nlohmann/json_fwd.hpp) for forward declarations (see [Compile times](https://json.nlohmann.me/integration/compile_times/index.md)), and file [`single_include/nlohmann/json_literals.hpp`](https://github.com/nlohmann/json/blob/develop/single_include/nlohmann/json_literals.hpp) for the user-defined string literals if you define [`JSON_NO_AUTOMATIC_UDLS`](https://json.nlohmann.me/api/macros/json_no_automatic_udls/index.md).

For the read-only, non-owning [`basic_json_document`](https://json.nlohmann.me/api/basic_json_document/index.md)/[`basic_json_view`](https://json.nlohmann.me/api/basic_json_view/index.md) types, additionally include [`single_include/nlohmann/json_view.hpp`](https://github.com/nlohmann/json/blob/develop/single_include/nlohmann/json_view.hpp); see [Zero-copy JSON views](https://json.nlohmann.me/features/json_view/index.md).

## Notes for builds and distribution

**Reproducible and path-independent builds.** The runtime assertions use `assert`, which embeds the name of the source file (`__FILE__`) in the binary. Release builds do not contain them, because they define `NDEBUG`. If you compile with assertions enabled and need binaries that do not depend on the build directory, either define `NDEBUG` or map the prefix of the path with the compiler option `-ffile-prefix-map=<old>=<new>` (GCC 8 and later, Clang 10 and later). See [Runtime assertions](https://json.nlohmann.me/features/assertions/index.md).

**There is no separate source file to compile.** The library is header-only, so there is no `.cpp` that could be built with different options than the code that includes it. It is also not available as a precompiled library. To compile the library with optimizations in an otherwise unoptimized build (for example to parse large files in a debug build, which is slow because of the unoptimized code and the checks of the debug standard library), keep the code that uses `json` in a separate source file and set the options for that file only. [Compile times](https://json.nlohmann.me/integration/compile_times/index.md) shows how to [instantiate `basic_json` once](https://json.nlohmann.me/integration/compile_times/#instantiate-basic_json-once).

**Debugger visualization.** The Natvis file works with the Visual Studio debugger, including the `cppvsdbg` engine in Visual Studio Code, but not with debuggers that wrap LLDB, such as `codelldb`; see [Debugging](https://json.nlohmann.me/home/debugging/index.md).

## See also

- [CMake](https://json.nlohmann.me/integration/cmake/index.md) - integrate the library into a CMake project
- [Package managers](https://json.nlohmann.me/integration/package_managers/index.md)
- [pkg-config](https://json.nlohmann.me/integration/pkg-config/index.md)
- [Compile times](https://json.nlohmann.me/integration/compile_times/index.md) - reduce the compile time overhead
- [Migration guide](https://json.nlohmann.me/integration/migration_guide/index.md) - upgrade from an earlier version
- [Releases](https://json.nlohmann.me/home/releases/index.md)
