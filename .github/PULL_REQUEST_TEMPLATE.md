
## Files to change

There are currently two files which need to be edited:

1. [`src/json.hpp`](https://github.com/nlohmann/json/blob/master/src/json.hpp)

2. [`test/src/unit.cpp`](https://github.com/nlohmann/json/blob/master/test/unit.cpp) - This contains the [Catch](https://github.com/philsquared/Catch) unit tests which currently cover [100 %](https://coveralls.io/github/nlohmann/json) of the library's code.

   If you add or change a feature, please also add a unit test to this file. The unit tests can be compiled and executed with

   ```sh
   make check
   ```

   The test cases are also executed with several different compilers on [Travis](https://travis-ci.org/nlohmann/json) once you open a pull request.


## Note

- If you open a pull request, the code will be automatically tested with [Valgrind](http://valgrind.org)'s Memcheck tool to detect memory leaks. Please be aware that the execution with Valgrind _may_ in rare cases yield different behavior than running the code directly. This can result in failing unit tests which run successfully without Valgrind.

## Please don't

- The C++11 support varies between different **compilers** and versions. Please note the [list of supported compilers](https://github.com/nlohmann/json/blob/master/README.md#supported-compilers). Some compilers like GCC 4.8 (and earlier), Clang 3.3 (and earlier), or Microsoft Visual Studio 13.0 and earlier are known not to work due to missing or incomplete C++11 support. Please refrain from proposing changes that work around these compiler's limitations with `#ifdef`s or other means.
- Specifically, I am aware of compilation problems with **Microsoft Visual Studio** (there even is an [issue label](https://github.com/nlohmann/json/issues?utf8=✓&q=label%3A%22visual+studio%22+) for these kind of bugs). I understand that even in 2016, complete C++11 support isn't there yet. But please also understand that I do not want to drop features or uglify the code just to make Microsoft's sub-standard compiler happy. The past has shown that there are ways to express the functionality such that the code compiles with the most recent MSVC - unfortunately, this is not the main objective of the project.
- Please refrain from proposing changes that would **break [JSON](http://json.org) conformance**. If you propose a conformant extension of JSON to be supported by the library, please motivate this extension.
- Please do not open pull requests that address **multiple issues**.
