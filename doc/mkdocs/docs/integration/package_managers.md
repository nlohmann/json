# Package Managers

Throughout this page, we will describe how to compile the example file `example.cpp` below.

```cpp
--8<-- "integration/example.cpp"
```

When executed, this program should create output similar to

```json
--8<-- "../../examples/meta.output"
```

## Homebrew

If you are using OS X and [Homebrew](http://brew.sh), just type

```sh
brew install nlohmann-json
```

and you're set. If you want the bleeding edge rather than the latest release, use

```sh
brew install nlohmann-json --HEAD
```

instead. See [nlohmann-json](https://formulae.brew.sh/formula/nlohmann-json) for more information.

??? example

	1. Create the following file:

        ```cpp title="example.cpp"
        --8<-- "integration/example.cpp"
        ```

	2. Install the package

		```sh
		brew install nlohmann-json
		```

	3. Determine the include path, which defaults to `/usr/local/Cellar/nlohmann-json/$version/include`, where `$version` is the version of the library, e.g. `3.7.3`. The path of the library can be determined with

		```sh
		brew list nlohmann-json
		```

	4. Compile the code. For instance, the code can be compiled using Clang with

		```sh
		clang++ example.cpp -I/usr/local/Cellar/nlohmann-json/3.7.3/include -std=c++11 -o example
		```

:material-update: The [formula](https://formulae.brew.sh/formula/nlohmann-json) is updated automatically.

## Meson

If you are using the [Meson Build System](http://mesonbuild.com), add this source tree as a [meson subproject](https://mesonbuild.com/Subprojects.html#using-a-subproject). You may also use the `include.zip` published in this project's [Releases](https://github.com/nlohmann/json/releases) to reduce the size of the vendored source tree. Alternatively, you can get a wrap file by downloading it from [Meson WrapDB](https://wrapdb.mesonbuild.com/nlohmann_json), or simply use `meson wrap install nlohmann_json`. Please see the meson project for any issues regarding the packaging.

The provided `meson.build` can also be used as an alternative to cmake for installing `nlohmann_json` system-wide in which case a pkg-config file is installed. To use it, simply have your build system require the `nlohmann_json` pkg-config dependency. In Meson, it is preferred to use the [`dependency()`](https://mesonbuild.com/Reference-manual.html#dependency) object with a subproject fallback, rather than using the subproject directly.

## Conan

If you are using [Conan](https://www.conan.io/) to manage your dependencies, merely add `nlohmann_json/x.y.z` to your `conanfile`'s requires, where `x.y.z` is the release version you want to use. Please file issues [here](https://github.com/conan-io/conan-center-index/issues) if you experience problems with the packages.

??? example

	1. Create the following files:

        ```ini title="Conanfile.txt"
        --8<-- "integration/conan/Conanfile.txt"
        ```

        ```cmake title="CMakeLists.txt"
        --8<-- "integration/conan/CMakeLists.txt"
        ```

        ```cpp title="example.cpp"
        --8<-- "integration/conan/example.cpp"
        ```

	2. Build:

		```sh
		mkdir build
		cd build
		conan install ..
		cmake ..
		cmake --build .
		```

:material-update: The [package](https://conan.io/center/nlohmann_json) is updated automatically.

## Spack

If you are using [Spack](https://www.spack.io/) to manage your dependencies, you can use the [`nlohmann-json` package](https://spack.readthedocs.io/en/latest/package_list.html#nlohmann-json). Please see the [spack project](https://github.com/spack/spack) for any issues regarding the packaging.

## Hunter

If you are using [hunter](https://github.com/cpp-pm/hunter) on your project for external dependencies, then you can use the [nlohmann_json package](https://hunter.readthedocs.io/en/latest/packages/pkg/nlohmann_json.html). Please see the hunter project for any issues regarding the packaging.

## Buckaroo

If you are using [Buckaroo](https://buckaroo.pm), you can install this library's module with `buckaroo add github.com/buckaroo-pm/nlohmann-json`. Please file issues [here](https://github.com/buckaroo-pm/nlohmann-json). There is a demo repo [here](https://github.com/njlr/buckaroo-nholmann-json-example).

## vcpkg

If you are using [vcpkg](https://github.com/Microsoft/vcpkg/) on your project for external dependencies, then you can install the [nlohmann-json package](https://github.com/Microsoft/vcpkg/tree/master/ports/nlohmann-json) with `vcpkg install nlohmann-json` and follow the then displayed descriptions. Please see the vcpkg project for any issues regarding the packaging.

??? example

	1. Create the following files:

        ```cmake title="CMakeLists.txt"
        --8<-- "integration/vcpkg/CMakeLists.txt"
        ```
    
        ```cpp title="example.cpp"
        --8<-- "integration/vcpkg/example.cpp"
        ```

    2. Install package:

        ```sh
        vcpkg install nlohmann-json
        ```

	3. Build:

		```sh
		mkdir build
		cd build
		cmake .. -DCMAKE_TOOLCHAIN_FILE=/path/to/vcpkg/scripts/buildsystems/vcpkg.cmake
		cmake --build .
		```

    Note you need to adjust `/path/to/vcpkg/scripts/buildsystems/vcpkg.cmake` to your system.

## cget

If you are using [cget](http://cget.readthedocs.io/en/latest/), you can install the latest development version with `cget install nlohmann/json`. A specific version can be installed with `cget install nlohmann/json@v3.1.0`. Also, the multiple header version can be installed by adding the `-DJSON_MultipleHeaders=ON` flag (i.e., `cget install nlohmann/json -DJSON_MultipleHeaders=ON`).

:material-update: cget reads directly from the [GitHub repository](https://github.com/nlohmann/json) and is always up-to-date.

## CocoaPods

If you are using [CocoaPods](https://cocoapods.org), you can use the library by adding pod `"nlohmann_json", '~>3.1.2'` to your podfile (see [an example](https://bitbucket.org/benman/nlohmann_json-cocoapod/src/master/)). Please file issues [here](https://bitbucket.org/benman/nlohmann_json-cocoapod/issues?status=new&status=open).

## NuGet

If you are using [NuGet](https://www.nuget.org), you can use the package [nlohmann.json](https://www.nuget.org/packages/nlohmann.json/). Please check [this extensive description](https://github.com/nlohmann/json/issues/1132#issuecomment-452250255) on how to use the package. Please file issues [here](https://github.com/hnkb/nlohmann-json-nuget/issues).

## Conda

If you are using [conda](https://conda.io/), you can use the package [nlohmann_json](https://github.com/conda-forge/nlohmann_json-feedstock) from [conda-forge](https://conda-forge.org) executing `conda install -c conda-forge nlohmann_json`. Please file issues [here](https://github.com/conda-forge/nlohmann_json-feedstock/issues).

## MSYS2

If you are using [MSYS2](http://www.msys2.org/), you can use the [mingw-w64-nlohmann-json](https://packages.msys2.org/base/mingw-w64-nlohmann-json) package, just type `pacman -S mingw-w64-i686-nlohmann-json` or `pacman -S mingw-w64-x86_64-nlohmann-json` for installation. Please file issues [here](https://github.com/msys2/MINGW-packages/issues/new?title=%5Bnlohmann-json%5D) if you experience problems with the packages.

:material-update: The [package](https://packages.msys2.org/base/mingw-w64-nlohmann-json) is updated automatically.

## MacPorts

If you are using [MacPorts](https://ports.macports.org), execute `sudo port install nlohmann-json` to install the [nlohmann-json](https://ports.macports.org/port/nlohmann-json/) package.

:material-update: The [package](https://ports.macports.org/port/nlohmann-json/) is updated automatically.

## build2

If you are using [`build2`](https://build2.org), you can use the [`nlohmann-json`](https://cppget.org/nlohmann-json) package from the public repository <http://cppget.org> or directly from the [package's sources repository](https://github.com/build2-packaging/nlohmann-json). In your project's `manifest` file, just add `depends: nlohmann-json` (probably with some [version constraints](https://build2.org/build2-toolchain/doc/build2-toolchain-intro.xhtml#guide-add-remove-deps)). If you are not familiar with using dependencies in `build2`, [please read this introduction](https://build2.org/build2-toolchain/doc/build2-toolchain-intro.xhtml).
Please file issues [here](https://github.com/build2-packaging/nlohmann-json) if you experience problems with the packages.

:material-update: The [package](https://cppget.org/nlohmann-json) is updated automatically.

## wsjcpp

If you are using [`wsjcpp`](http://wsjcpp.org), you can use the command `wsjcpp install "https://github.com/nlohmann/json:develop"` to get the latest version. Note you can change the branch ":develop" to an existing tag or another branch.

:material-update: wsjcpp reads directly from the [GitHub repository](https://github.com/nlohmann/json) and is always up-to-date.

## CPM.cmake

If you are using [`CPM.cmake`](https://github.com/TheLartians/CPM.cmake), you can check this [`example`](https://github.com/TheLartians/CPM.cmake/tree/master/examples/json). After [adding CPM script](https://github.com/TheLartians/CPM.cmake#adding-cpm) to your project, implement the following snippet to your CMake:

```cmake
CPMAddPackage(
    NAME nlohmann_json
    GITHUB_REPOSITORY nlohmann/json
    VERSION 3.9.1)
```
