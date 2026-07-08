# Package Managers

[**Homebrew**](#homebrew) `nlohmann-json`    [**Meson**](#meson) `nlohmann_json`    [**Bazel**](#bazel) `nlohmann_json`\
[**Conan**](#conan) `nlohmann_json`    [**Spack**](#spack) `nlohmann-json`   [**Hunter**](#hunter) `nlohmann_json`\
[**vcpkg**](#vcpkg) `nlohmann-json`   [**cget**](#cget) `nlohmann/json`    [**Swift Package Manager**](#swift-package-manager) `nlohmann/json`\
[**NuGet**](#nuget) `nlohmann.json`    [**Conda**](#conda) `nlohmann_json`    [**MacPorts**](#macports) `nlohmann-json`\
[**CPM.cmake**](#cpmcmake) `gh:nlohmann/json`    [**xmake**](#xmake) `nlohmann_json`

## Running example

Throughout this page, we will describe how to compile the example file `example.cpp` below.

```
#include <nlohmann/json.hpp>
#include <iostream>
#include <iomanip>

using json = nlohmann::json;

int main()
{
    std::cout << std::setw(4) << json::meta() << std::endl;
}
```

When executed, this program should create output similar to

```
{
    "compiler": {
        "c++": "201103",
        "family": "gcc",
        "version": "12.4.0"
    },
    "copyright": "(C) 2013-2026 Niels Lohmann",
    "name": "JSON for Modern C++",
    "platform": "apple",
    "url": "https://github.com/nlohmann/json",
    "version": {
        "major": 3,
        "minor": 12,
        "patch": 0,
        "string": "3.12.0"
    }
}
```

## Homebrew

Summary

formula: [**`nlohmann-json`**](https://formulae.brew.sh/formula/nlohmann-json)

- Available versions: current version and development version (with `--HEAD` parameter)
- The formula is updated with every release.
- Maintainer: Niels Lohmann
- File issues at the [Homebrew issue tracker](https://github.com/Homebrew/homebrew-core/issues)
- [Homebrew website](https://brew.sh)

If you are using [Homebrew](http://brew.sh), you can install the library with

```
brew install nlohmann-json
```

The header can be used directly in your code or via CMake.

Example: Raw compilation

1. Create the following file:

   example.cpp

   ```
   #include <nlohmann/json.hpp>
   #include <iostream>
   #include <iomanip>

   using json = nlohmann::json;

   int main()
   {
       std::cout << std::setw(4) << json::meta() << std::endl;
   }
   ```

1. Install the package:

   ```
   brew install nlohmann-json
   ```

1. Compile the code and pass the Homebrew prefix to the include path such that the library can be found:

   ```
   c++ example.cpp -I$(brew --prefix nlohmann-json)/include -std=c++11 -o example
   ```

Example: CMake

1. Create the following files:

   example.cpp

   ```
   #include <nlohmann/json.hpp>
   #include <iostream>
   #include <iomanip>

   using json = nlohmann::json;

   int main()
   {
       std::cout << std::setw(4) << json::meta() << std::endl;
   }
   ```

   CMakeLists.txt

   ```
   cmake_minimum_required(VERSION 3.15)
   project(json_example)

   find_package(nlohmann_json CONFIG REQUIRED)

   add_executable(json_example example.cpp)
   target_link_libraries(json_example PRIVATE nlohmann_json::nlohmann_json)
   ```

1. Install the package:

   ```
   brew install nlohmann-json
   ```

1. Compile the code and pass the Homebrew prefix to CMake to find installed packages via `find_package`:

   ```
   CMAKE_PREFIX_PATH=$(brew --prefix) cmake -S . -B build
   cmake --build build
   ```

## Meson

Summary

wrap: **`nlohmann_json`**

- Available versions: current version and select older versions (see [WrapDB](https://mesonbuild.com/Wrapdb-projects.html))
- The package is updated automatically from file [`meson.build`](https://github.com/nlohmann/json/blob/develop/meson.build).
- File issues at the [library issue tracker](https://github.com/nlohmann/json/issues)
- [Meson website](https://mesonbuild.com/index.html)

If you are using the [Meson Build System](http://mesonbuild.com), add this source tree as a [meson subproject](https://mesonbuild.com/Subprojects.html#using-a-subproject). You may also use the `include.zip` published in this project's [Releases](https://github.com/nlohmann/json/releases) to reduce the size of the vendored source tree. Alternatively, you can get a wrap file by downloading it from [Meson WrapDB](https://mesonbuild.com/Wrapdb-projects.html), or use

```
meson wrap install nlohmann_json
```

Please see the Meson project for any issues regarding the packaging.

The provided `meson.build` can also be used as an alternative to CMake for installing `nlohmann_json` system-wide in which case a pkg-config file is installed. To use it, have your build system require the `nlohmann_json` pkg-config dependency. In Meson, it is preferred to use the [`dependency()`](https://mesonbuild.com/Reference-manual.html#dependency) object with a subproject fallback, rather than using the subproject directly.

Example: Wrap

1. Create the following files:

   meson.build

   ```
   project('json_example', 'cpp',
     version: '1.0',
     default_options: ['cpp_std=c++11']
   )

   dependency_json = dependency('nlohmann_json', required: true)

   executable('json_example',
     sources: ['example.cpp'],
     dependencies: [dependency_json],
     install: true
   )
   ```

   example.cpp

   ```
   #include <nlohmann/json.hpp>
   #include <iostream>
   #include <iomanip>

   using json = nlohmann::json;

   int main()
   {
       std::cout << std::setw(4) << json::meta() << std::endl;
   }
   ```

1. Use the Meson WrapDB to fetch the nlohmann/json wrap:

   ```
   mkdir subprojects
   meson wrap install nlohmann_json
   ```

1. Build:

   ```
   meson setup build
   meson compile -C build
   ```

## Bazel

Summary

use `bazel_dep`, `git_override`, or `local_path_override`

- Any version, that is available via [Bazel Central Registry](https://registry.bazel.build/modules/nlohmann_json)
- File issues at the [library issue tracker](https://github.com/nlohmann/json/issues)
- [Bazel website](https://bazel.build)

This repository provides a [Bazel](https://bazel.build/) `MODULE.bazel` and a corresponding `BUILD.bazel` file. Therefore, this repository can be referenced within a `MODULE.bazel` by rules such as `archive_override`, `git_override`, or `local_path_override`. To use the library, you need to depend on the target `@nlohmann_json//:json` (i.e., via `deps` attribute).

Example

1. Create the following files:

   BUILD

   ```
   cc_binary(
       name = "main",
       srcs = ["example.cpp"],
       deps = ["@nlohmann_json//:json"],
   )
   ```

   WORKSPACE

   ```
   bazel_dep(name = "nlohmann_json", version = "3.11.3.bcr.1")
   ```

   example.cpp

   ```
   #include <nlohmann/json.hpp>
   #include <iostream>
   #include <iomanip>

   using json = nlohmann::json;

   int main()
   {
       std::cout << std::setw(4) << json::meta() << std::endl;
   }
   ```

1. Build and run:

   ```
   bazel build //:main
   bazel run //:main
   ```

## Conan

Summary

recipe: [**`nlohmann_json`**](https://conan.io/center/recipes/nlohmann_json)

- Available versions: current version and older versions (see [Conan Center](https://conan.io/center/recipes/nlohmann_json))
- The package is updated automatically via [this recipe](https://github.com/conan-io/conan-center-index/tree/master/recipes/nlohmann_json).
- File issues at the [Conan Center issue tracker](https://github.com/conan-io/conan-center-index/issues)
- [Conan website](https://conan.io)

If you are using [Conan](https://www.conan.io/) to manage your dependencies, merely add `nlohmann_json/x.y.z` to your `conanfile`'s requires, where `x.y.z` is the release version you want to use.

Example

1. Create the following files:

   Conanfile.txt

   ```
   [requires]
   nlohmann_json/3.12.0

   [generators]
   CMakeToolchain
   CMakeDeps
   ```

   CMakeLists.txt

   ```
   cmake_minimum_required(VERSION 3.15)
   project(json_example)

   find_package(nlohmann_json REQUIRED)

   add_executable(json_example example.cpp)
   target_link_libraries(json_example PRIVATE nlohmann_json::nlohmann_json)
   ```

   example.cpp

   ```
   #include <nlohmann/json.hpp>
   #include <iostream>
   #include <iomanip>

   using json = nlohmann::json;

   int main()
   {
       std::cout << std::setw(4) << json::meta() << std::endl;
   }
   ```

1. Call Conan:

   ```
   conan install . --output-folder=build --build=missing
   ```

1. Build:

   ```
   cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE="conan_toolchain.cmake" -DCMAKE_BUILD_TYPE=Release
   cmake --build build
   ```

## Spack

Summary

package: [**`nlohmann-json`**](https://packages.spack.io/package.html?name=nlohmann-json)

- Available versions: current version and older versions (see [Spack package](https://packages.spack.io/package.html?name=nlohmann-json))
- The package is updated with every release.
- Maintainer: [Axel Huebl](https://github.com/ax3l)
- File issues at the [Spack issue tracker](https://github.com/spack/spack/issues)
- [Spack website](https://spack.io)

If you are using [Spack](https://www.spack.io/) to manage your dependencies, you can use the [`nlohmann-json` package](https://packages.spack.io/package.html?name=nlohmann-json) via

```
spack install nlohmann-json
```

Please see the [Spack project](https://github.com/spack/spack) for any issues regarding the packaging.

Example

1. Create the following files:

   CMakeLists.txt

   ```
   cmake_minimum_required(VERSION 3.15)
   project(json_example)

   find_package(nlohmann_json REQUIRED)

   add_executable(json_example example.cpp)
   target_link_libraries(json_example PRIVATE nlohmann_json::nlohmann_json)
   ```

   example.cpp

   ```
   #include <nlohmann/json.hpp>
   #include <iostream>
   #include <iomanip>

   using json = nlohmann::json;

   int main()
   {
       std::cout << std::setw(4) << json::meta() << std::endl;
   }
   ```

1. Install the library:

   ```
   spack install nlohmann-json
   ```

1. Load the environment for your Spack-installed packages:

   ```
   spack load nlohmann-json
   ```

1. Build the project with CMake:

   ```
   cmake -S . -B build -DCMAKE_PREFIX_PATH=$(spack location -i nlohmann-json)
   cmake --build build
   ```

## Hunter

Summary

package: [**`nlohmann_json`**](https://hunter.readthedocs.io/en/latest/packages/pkg/nlohmann_json.html)

- Available versions: current version and older versions (see [Hunter package](https://hunter.readthedocs.io/en/latest/packages/pkg/nlohmann_json.html))
- The package is updated with every release.
- File issues at the [Hunter issue tracker](https://github.com/cpp-pm/hunter/issues)
- [Hunter website](https://hunter.readthedocs.io/en/latest/)

If you are using [Hunter](https://github.com/cpp-pm/hunter) on your project for external dependencies, then you can use the [nlohmann_json package](https://hunter.readthedocs.io/en/latest/packages/pkg/nlohmann_json.html) via

```
hunter_add_package(nlohmann_json)
```

Please see the Hunter project for any issues regarding the packaging.

Example

1. Create the following files:

   CMakeLists.txt

   ```
   cmake_minimum_required(VERSION 3.15)

   include("cmake/HunterGate.cmake")
   HunterGate(
       URL "https://github.com/cpp-pm/hunter/archive/v0.23.297.tar.gz"
       SHA1 "3319fe6a3b08090df7df98dee75134d68e2ef5a3"
   )

   project(json_example)

   hunter_add_package(nlohmann_json)
   find_package(nlohmann_json CONFIG REQUIRED)

   add_executable(json_example example.cpp)
   target_link_libraries(json_example PRIVATE nlohmann_json::nlohmann_json)
   ```

   example.cpp

   ```
   #include <nlohmann/json.hpp>
   #include <iostream>
   #include <iomanip>

   using json = nlohmann::json;

   int main()
   {
       std::cout << std::setw(4) << json::meta() << std::endl;
   }
   ```

1. Download required files

   ```
   mkdir cmake
   wget https://raw.githubusercontent.com/cpp-pm/gate/master/cmake/HunterGate.cmake -O cmake/HunterGate.cmake
   ```

1. Build the project with CMake:

   ```
   cmake -S . -B build
   cmake --build build
   ```

## vcpkg

Summary

package: [**`nlohmann-json`**](https://github.com/Microsoft/vcpkg/tree/master/ports/nlohmann-json)

- Available versions: current version
- The package is updated with every release.
- File issues at the [vcpkg issue tracker](https://github.com/microsoft/vcpkg/issues)
- [vcpkg website](https://vcpkg.io/)

If you are using [vcpkg](https://github.com/Microsoft/vcpkg/) on your project for external dependencies, then you can install the [nlohmann-json package](https://github.com/Microsoft/vcpkg/tree/master/ports/nlohmann-json) with

```
vcpkg install nlohmann-json
```

and follow the then displayed descriptions. Please see the vcpkg project for any issues regarding the packaging.

Example

1. Create the following files:

   CMakeLists.txt

   ```
   cmake_minimum_required(VERSION 3.15)
   project(json_example)

   find_package(nlohmann_json CONFIG REQUIRED)

   add_executable(json_example example.cpp)
   target_link_libraries(json_example PRIVATE nlohmann_json::nlohmann_json)
   ```

   example.cpp

   ```
   #include <nlohmann/json.hpp>
   #include <iostream>
   #include <iomanip>

   using json = nlohmann::json;

   int main()
   {
       std::cout << std::setw(4) << json::meta() << std::endl;
   }
   ```

1. Install package:

   ```
   vcpkg install nlohmann-json
   ```

1. Build:

   ```
   cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake
   cmake --build build
   ```

## cget

Summary

package: [**`nlohmann/json`**](https://github.com/pfultz2/cget-recipes/blob/master/recipes/nlohmann/json/package.txt)

- Available versions: current version and older versions
- The package is updated with every release.
- File issues at the [cget issue tracker](https://github.com/pfultz2/cget-recipes/issues)
- [cget website](https://cget.readthedocs.io/)

If you are using [cget](http://cget.readthedocs.io/en/latest/), you can install the latest `master` version with

```
cget install nlohmann/json
```

A specific version can be installed with `cget install nlohmann/json@v3.12.0`. Also, the multiple header version can be installed by adding the `-DJSON_MultipleHeaders=ON` flag (i.e., `cget install nlohmann/json -DJSON_MultipleHeaders=ON`).

Example

1. Create the following files:

   CMakeLists.txt

   ```
   cmake_minimum_required(VERSION 3.15)
   project(json_example)

   find_package(nlohmann_json CONFIG REQUIRED)

   add_executable(json_example example.cpp)
   target_link_libraries(json_example PRIVATE nlohmann_json::nlohmann_json)
   ```

   example.cpp

   ```
   #include <nlohmann/json.hpp>
   #include <iostream>
   #include <iomanip>

   using json = nlohmann::json;

   int main()
   {
       std::cout << std::setw(4) << json::meta() << std::endl;
   }
   ```

1. Initialize cget

   ```
   cget init
   ```

1. Install the library

   ```
   cget install nlohmann/json
   ```

1. Build

   ```
   cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=cget/cget/cget.cmake
   cmake --build build
   ```

## Swift Package Manager

Summary

package: **`nlohmann/json`**

- Available versions: current version and older versions
- The package is updated with every release.
- File issues at the [library issue tracker](https://github.com/nlohmann/json/issues)
- [Xcode documentation](https://developer.apple.com/documentation/xcode/adding-package-dependencies-to-your-app)

## NuGet

Summary

package: [**`nlohmann.json`**](https://www.nuget.org/packages/nlohmann.json/)

- Available versions: current and previous versions
- The package is updated with every release.
- Maintainer: [Hani Kaabi](https://github.com/hnkb)
- File issues at the [maintainer's issue tracker](https://github.com/hnkb/nlohmann-json-nuget/issues)
- [NuGet website](https://www.nuget.org)

If you are using [NuGet](https://www.nuget.org), you can use the package [nlohmann.json](https://www.nuget.org/packages/nlohmann.json/) with

```
dotnet add package nlohmann.json
```

Example

Probably the easiest way to use NuGet packages is through Visual Studio graphical interface. Right-click on a project (any C++ project would do) in “Solution Explorer” and select “Manage NuGet Packages…”

Now you can click on “Browse” tab and find the package you like to install.

Most of the packages in NuGet gallery are .NET packages and would not be useful in a C++ project. Microsoft recommends adding “native” and “nativepackage” tags to C++ NuGet packages to distinguish them, but even adding “native” to search query would still show many .NET-only packages in the list.

Nevertheless, after finding the package you want, click on “Install” button and accept confirmation dialogs. After the package is successfully added to the projects, you should be able to build and execute the project without the need for making any more changes to build settings.

Note

A few notes:

- NuGet packages are installed per project and not system-wide. The header and binaries for the package are only available to the project it is added to, and not other projects (obviously unless we add the package to those projects as well)
- One of the many great things about your elegant work is that it is a header-only library, which makes deployment very straightforward. In case of libraries which need binary deployment (`.lib`, `.dll` and `.pdb` for debug info) the different binaries for each supported compiler version must be added to the NuGet package. Some library creators cram binary versions for all supported Visual C++ compiler versions in the same package, so a single package will support all compilers. Some others create a different package for each compiler version (and you usually see things like “v140” or “vc141” in package name to clarify which VC++ compiler this package supports).
- Packages can have dependency to other packages, and in this case, NuGet will install all dependencies as well as the requested package recursively.

**What happens behind the scenes**

After you add a NuGet package, three changes occur in the project source directory. Of course, we could make these changes manually instead of using GUI:

1. A `packages.config` file will be created (or updated to include the package name if one such file already exists). This file contains a list of the packages required by this project (name and minimum version) and must be added to the project source code repository, so if you move the source code to a new machine, MSBuild/NuGet knows which packages it has to restore (which it does automatically before each build).

   ```
   <?xml version="1.0" encoding="utf-8"?>
   <packages>
     <package id="nlohmann.json" version="3.5.0" targetFramework="native" />
   </packages>
   ```

1. A `packages` folder which contains actual files in the packages (these are header and binary files required for a successful build, plus a few metadata files). In case of this library for example, it contains `json.hpp`:

   Note

   This directory should not be added to the project source code repository, as it will be restored before each build by MSBuild/NuGet. If you go ahead and delete this folder, then build the project again, it will magically re-appear!

1. Project MSBuild makefile (which for Visual C++ projects has a .vcxproj extension) will be updated to include settings from the package.

   The important bit for us here is line 170, which tells MSBuild to import settings from `packages\nlohmann.json.3.5.0\build\native\nlohmann.json.targets` file. This is a file the package creator created and added to the package (you can see it is one of the two files I created in this repository, the other just contains package attributes like name and version number). What does it contain?

   For our header-only repository, the only setting we need is to add our include directory to the list of `AdditionalIncludeDirectories`:

   ```
   <?xml version="1.0" encoding="utf-8"?>
   <Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
       <ItemDefinitionGroup>
           <ClCompile>
               <AdditionalIncludeDirectories>$(MSBuildThisFileDirectory)include;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
           </ClCompile>
       </ItemDefinitionGroup>
   </Project>
   ```

   For libraries with binary files, we will need to add `.lib` files to linker inputs and add settings to copy `.dll` and other redistributable files to output directory, if needed.

   There are other changes to the makefile as well:

   - Lines 165-167 add the `packages.config` as one of project files (so it is shown in Solution Explorer tree view). It is added as None (no build action) and removing it wouldn’t affect build.
   - Lines 172-177 check to ensure the required packages are present. This will display a build error if package directory is empty (for example when NuGet cannot restore packages because Internet connection is down). Again, if you omit this section, the only change in build would be a more cryptic error message if build fails.

   Note

   Changes to .vcxproj makefile should also be added to project source code repository.

As you can see, the mechanism NuGet uses to modify project settings is through MSBuild makefiles, so using NuGet with other build systems and compilers (like CMake) as a dependency manager is either impossible or more problematic than useful.

Please refer to [this extensive description](https://github.com/nlohmann/json/issues/1132#issuecomment-452250255) for more information.

## Conda

Summary

package: [**`nlohmann_json`**](https://anaconda.org/conda-forge/nlohmann_json)

- Available versions: current and previous versions
- The package is updated with every release.
- File issues at the [feedstock's issue tracker](https://github.com/conda-forge/nlohmann_json-feedstock/issues)
- [Conda documentation](https://docs.conda.io/projects/conda/en/stable/user-guide/getting-started.html)

If you are using [conda](https://conda.io/), you can use the package [nlohmann_json](https://anaconda.org/conda-forge/nlohmann_json) from [conda-forge](https://conda-forge.org) executing

```
conda install -c conda-forge nlohmann_json
```

Example

1. Create the following file:

   example.cpp

   ```
   #include <nlohmann/json.hpp>
   #include <iostream>
   #include <iomanip>

   using json = nlohmann::json;

   int main()
   {
       std::cout << std::setw(4) << json::meta() << std::endl;
   }
   ```

1. Create and activate an environment `json`:

   ```
   conda create -n json
   conda activate json
   ```

1. Install the package:

   ```
   conda install -c conda-forge nlohmann_json
   ```

1. Build the code:

   ```
   g++ -std=c++11 -I$(conda info --base)/envs/json/include example.cpp -o example
   ```

## MSYS2

If you are using [MSYS2](http://www.msys2.org/), you can use the [mingw-w64-nlohmann-json](https://packages.msys2.org/base/mingw-w64-nlohmann-json) package, type `pacman -S mingw-w64-i686-nlohmann-json` or `pacman -S mingw-w64-x86_64-nlohmann-json` for installation. Please file issues [here](https://github.com/msys2/MINGW-packages/issues/new?title=%5Bnlohmann-json%5D) if you experience problems with the packages.

The [package](https://packages.msys2.org/base/mingw-w64-nlohmann-json) is updated automatically.

## MacPorts

Summary

port: [**`nlohmann-json`**](https://ports.macports.org/port/nlohmann-json/)

- Available versions: current version
- The port is updated with every release.
- File issues at the [MacPorts issue tracker](https://trac.macports.org/newticket?port=nlohmann-json)
- [MacPorts website](https://www.macports.org)

If you are using [MacPorts](https://ports.macports.org), execute

```
sudo port install nlohmann-json
```

to install the [nlohmann-json](https://ports.macports.org/port/nlohmann-json/) package.

Example: Raw compilation

1. Create the following file:

   example.cpp

   ```
   #include <nlohmann/json.hpp>
   #include <iostream>
   #include <iomanip>

   using json = nlohmann::json;

   int main()
   {
       std::cout << std::setw(4) << json::meta() << std::endl;
   }
   ```

1. Install the package:

   ```
   sudo port install nlohmann-json
   ```

1. Compile the code and pass the MacPorts prefix to the include path such that the library can be found:

   ```
   c++ example.cpp -I/opt/local/include -std=c++11 -o example
   ```

Example: CMake

1. Create the following files:

   example.cpp

   ```
   #include <nlohmann/json.hpp>
   #include <iostream>
   #include <iomanip>

   using json = nlohmann::json;

   int main()
   {
       std::cout << std::setw(4) << json::meta() << std::endl;
   }
   ```

   CMakeLists.txt

   ```
   cmake_minimum_required(VERSION 3.15)
   project(json_example)

   find_package(nlohmann_json CONFIG REQUIRED)

   add_executable(json_example example.cpp)
   target_link_libraries(json_example PRIVATE nlohmann_json::nlohmann_json)
   ```

1. Install the package:

   ```
   sudo port install nlohmann-json
   ```

1. Compile the code:

   ```
   cmake -S . -B build
   cmake --build build
   ```

## build2

Summary

package: **`nlohmann-json`** library target: **`nlohmann-json%lib{json}`** available in package repositories:

- [`cppget.org` (recommended)](https://cppget.org/nlohmann-json)

- [package's sources (for advanced users)](https://github.com/build2-packaging/nlohmann-json/)

- Available versions: current version and older versions since `3.7.3` (see [cppget.org](https://cppget.org/nlohmann-json))

- The package is maintained and published by the `build2` community in [this repository](https://github.com/build2-packaging/nlohmann-json/).

- File issues at the [package source repository](https://github.com/build2-packaging/nlohmann-json/issues/)

- [`build2` website](https://build2.org)

Note: [`build2`](https://build2.org) should not be considered as a standalone package-manager. It is a build-system + package manager + project manager, a set of tools that work hand-in-hand. `build2`-based projects do not rely on existing `CMake` scripts and the build scripts defining the project's targets are specific to `build2`.

To use this package in an existing [`build2`](https://build2.org) project, the general steps are:

1. Make the package available to download from a package repository that provides it.

   Your project's `repositories.manifest` specifies where the package manager will try to acquire packages by default. Make sure one of the repositories specified in this file provides `nlohmann-json` package. The recommended open-source repository is [`cppget.org`](https://cppget.org/).

   If the project has been created using [`bdep new`](https://build2.org/bdep/doc/bdep-new.xhtml), `cppget.org` is already specified in `repositories.manifest` but commented, just uncomment these lines:

   ```
   :
   role: prerequisite
   location: https://pkg.cppget.org/1/stable
   ```

1. Add this package as dependency of your project.

   In your project's `manifest` add the dependency to the package using `depends: nlohmann-json`. You could also add some [version constraints](https://build2.org/build2-toolchain/doc/build2-toolchain-intro.xhtml#guide-add-remove-deps). For example, to depend on the latest version available:

   ```
   depends: nlohmann-json
   ```

1. Add this library as dependency of your target that uses it.

   In the `buildfile` defining the target that will use this library:

   ````
   - import the target `lib{json}` from the `nlohmann-json` package, for example:
       ```
       import nljson = nlohmann-json%lib{json}
       ```

   - then add the library's target as requirement for your target using it, for example:
       ```
       exe{example} : ... $nljson
       ```
   ````

1. Use the library in your project's code and build it.

   At this point, assuming your project is initialized in a build-configuration, any `b` or `bdep update` command that will update/build the project will also acquire the missing dependency automatically, then build it and link it with your target.

   If you just want to synchronize dependencies for all your configurations to download the ones you just added:

   ```
   bdep sync -af
   ```

Example: from scratch, using `build2`'s [`bdep new` command](https://build2.org/bdep/doc/bdep-new.xhtml)

1. Create a new executable project "example" (see [`bdep new` command details](https://build2.org/bdep/doc/bdep-new.xhtml) for the various options to create a new project):

   ```
   bdep new example
   ```

1. Edit these files by replacing their content:

   - `example/repositories.manifest`: Enable acquiring packages from <https://cppget.org> by uncommenting the related lines:

     project's `repositories.manifest`

     ```
     : 1
     summary: example project repository

     :
     role: prerequisite
     location: https://pkg.cppget.org/1/stable
     #trust: ...

     #:
     #role: prerequisite
     #location: https://git.build2.org/hello/libhello.git
     ```

   - `example/manifest`: Add the latest version of the `nlohmann-json` package as dependency to the project:

     project's `manifest`

     ```
     name: example
     version: 0.1.0-a.0.z
     language: c++
     summary: example C++ executable
     license: other: proprietary ; Not free/open source.
     description-file: README.md
     url: https://example.org/example
     email: your@emailprovider.com
     #build-error-email: your@emailprovider.com
     depends: * build2 >= 0.16.0
     depends: * bpkg >= 0.16.0
     #depends: libhello ^1.0.0

     depends: nlohmann-json
     ```

   - `example/example/buildfile`: import the library's target to be used as requirement for building the executable target `exe{example}`:

     project's `buildfile`

     ```
     libs =
     import libs = nlohmann-json%lib{json}

     exe{example}: {hxx ixx txx cxx}{**} $libs testscript

     cxx.poptions =+ "-I$out_root" "-I$src_root"
     ```

   - `example/example/example.cxx`: `bdep new` generates a "hello world" by default, replace it by this:

     example.cxx

     ```
     #include <nlohmann/json.hpp>
     #include <iostream>
     #include <iomanip>

     using json = nlohmann::json;

     int main()
     {
         std::cout << std::setw(4) << json::meta() << std::endl;
     }
     ```

   - `example/example/testscript`: (optional) if you want to be able to test that executable's output is correct using `b test`:

     `testscript` checking the output of the program

     ```
     : json basics
     :
     $* >>~/EOO/
     {
         "compiler": {
     /        "c\+\+": "\d+",/
     /        "family": "[\w\d]+",/
     /        "version": \d+/
         },
     /    "copyright": "\(C\) 2013-\d+ Niels Lohmann",/
         "name": "JSON for Modern C++",
     /    "platform": "[\w\d]+",/
         "url": "https://github.com/nlohmann/json",
         "version": {
             "major": 3,
     /        "minor": \d+,/
     /        "patch": \d+,/
     /        "string": "3\.\d+\.\d+"/
         }
     }
     EOO
     ```

1. Initialize the project in a default C/C++ build configuration directory, then build and test:

   ```
   cd example/

   # create default C/C++ build configuration in ../example-myconfig/, initialize the project in it (downloads it's dependencies in it too)
   bdep init -C @myconfig cc

   # build only,
   b

   # or build and test the executable's output, will only work if the `testscript` is correct
   b test
   ```

## CPM.cmake

Summary

package: **`gh:nlohmann/json`**

- Available versions: current and previous versions
- The package is updated with every release.
- File issues at the [CPM.cmake issue tracker](https://github.com/cpm-cmake/CPM.cmake/issues)
- [CPM.cmake website](https://github.com/cpm-cmake/CPM.cmake)

If you are using [`CPM.cmake`](https://github.com/TheLartians/CPM.cmake), add the [CPM.cmake script](https://github.com/TheLartians/CPM.cmake#adding-cpm) and the following snippet to your CMake project:

```
CPMAddPackage("gh:nlohmann/json@3.12.0")
```

Example

1. Create the following files:

   example.cpp

   ```
   #include <nlohmann/json.hpp>
   #include <iostream>
   #include <iomanip>

   using json = nlohmann::json;

   int main()
   {
       std::cout << std::setw(4) << json::meta() << std::endl;
   }
   ```

   CMakeLists.txt

   ```
   cmake_minimum_required(VERSION 3.15)
   project(json_example)

   include(${CMAKE_SOURCE_DIR}/cmake/CPM.cmake)

   CPMAddPackage("gh:nlohmann/json@3.12.0")

   add_executable(json_example example.cpp)
   target_link_libraries(json_example PRIVATE nlohmann_json::nlohmann_json)
   ```

1. Download CPM.cmake

   ```
   mkdir -p cmake
   wget -O cmake/CPM.cmake https://github.com/cpm-cmake/CPM.cmake/releases/latest/download/get_cpm.cmake
   ```

1. Build

   ```
   cmake -S . -B build
   cmake --build build
   ```

## xmake

Summary

package: [**`nlohmann_json`**](https://github.com/xmake-io/xmake-repo/blob/master/packages/n/nlohmann_json/xmake.lua)

- Available versions: current and previous versions
- The package is updated with every release.
- File issues at the [xmake issue tracker](https://github.com/xmake-io/xmake-repo/issues)
- [xmake website](https://xmake.io/#/)

Example

1. Create the following files:

   example.cpp

   ```
   #include <nlohmann/json.hpp>
   #include <iostream>
   #include <iomanip>

   using json = nlohmann::json;

   int main()
   {
       std::cout << std::setw(4) << json::meta() << std::endl;
   }
   ```

   xmake.lua

   ```
   add_requires("nlohmann_json")

   add_rules("mode.debug", "mode.release")
   target("xm")
       set_kind("binary")
       add_files("example.cpp")
       add_packages("nlohmann_json")
       set_languages("cxx11")
   ```

1. Build

   ```
   xmake
   ```

1. Run

   ```
   xmake run
   ```

______________________________________________________________________

## Other package managers

The library is also contained in many other package repositories:

Package version overview

______________________________________________________________________

## Buckaroo

If you are using [Buckaroo](https://buckaroo.pm), you can install this library's module with `buckaroo add github.com/buckaroo-pm/nlohmann-json`. There is a demo repo [here](https://github.com/njlr/buckaroo-nholmann-json-example).

Warning

The module is outdated as the respective [repository](https://github.com/buckaroo-pm/nlohmann-json) has not been updated in years.

## CocoaPods

If you are using [CocoaPods](https://cocoapods.org), you can use the library by adding pod `"nlohmann_json", '~>3.1.2'` to your podfile (see [an example](https://bitbucket.org/benman/nlohmann_json-cocoapod/src/master/)). Please file issues [here](https://bitbucket.org/benman/nlohmann_json-cocoapod/issues?status=new&status=open).

Warning

The module is outdated as the respective [pod](https://cocoapods.org/pods/nlohmann_json) has not been updated in years.
