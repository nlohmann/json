
## Files to change

There are currently two files which need to be edited:

1. [`src/json.hpp.re2c`](https://github.com/nlohmann/json/blob/master/src/json.hpp.re2c) (note the `.re2c` suffix) - This file contains a comment section which describes the JSON lexic. This section is translated by [`re2c`](http://re2c.org) into file [`src/json.hpp`](https://github.com/nlohmann/json/blob/master/src/json.hpp) which is plain "vanilla" C++11 code. (In fact, the generated lexer consists of some hundred lines of `goto`s, which is a hint you never want to edit this file...).

   If you only edit file `src/json.hpp` (without the `.re2c` suffix), your changes will be overwritten as soon as the lexer is touched again. To generate the `src/json.hpp` file which is actually used during compilation of the tests and all other code, please execute

   ```sh
   make re2c
   ```

   To run [`re2c`](http://re2c.org) and generate/overwrite file `src/json.hpp` with your changes in file `src/json.hpp.re2c`.


2. [`test/src/unit.cpp`](https://github.com/nlohmann/json/blob/master/test/unit.cpp) - This contains the [Catch](https://github.com/philsquared/Catch) unit tests which currently cover [100 %](https://coveralls.io/github/nlohmann/json) of the library's code.

   If you add or change a feature, please also add a unit test to this file. The unit tests can be compiled with

   ```sh
   make
   ```

   and can be executed with

   ```sh
   ./json_unit
   ```

   The test cases are also executed with several different compilers on [Travis](https://travis-ci.org/nlohmann/json) once you open a pull request.

Please understand that I cannot accept pull requests changing only file `src/json.hpp`.


## Note

- If you open a pull request, the code will be automatically tested with [Valgrind](http://valgrind.org)'s Memcheck tool to detect memory leaks. Please be aware that the execution with Valgrind _may_ in rare cases yield different behavior than running the code directly. This can result in failing unit tests which run successfully without Valgrind.

## Please don't

- Only make changes to file `src/json.hpp` -- please read the paragraph above and understand why `src/json.hpp.re2c` exists.
- The C++11 support varies between different **compilers** and versions. Please note the [list of supported compilers](https://github.com/nlohmann/json/blob/master/README.md#supported-compilers). Some compilers like GCC 4.8 (and earlier), Clang 3.3 (and earlier), or Microsoft Visual Studio 13.0 and earlier are known not to work due to missing or incomplete C++11 support. Please refrain from proposing changes that work around these compiler's limitations with `#ifdef`s or other means.
- Specifically, I am aware of compilation problems with **Microsoft Visual Studio** (there even is an [issue label](https://github.com/nlohmann/json/issues?utf8=✓&q=label%3A%22visual+studio%22+) for these kind of bugs). I understand that even in 2016, complete C++11 support isn't there yet. But please also understand that I do not want to drop features or uglify the code just to make Microsoft's sub-standard compiler happy. The past has shown that there are ways to express the functionality such that the code compiles with the most recent MSVC - unfortunately, this is not the main objective of the project.
- Please refrain from proposing changes that would **break [JSON](http://json.org) conformance**. If you propose a conformant extension of JSON to be supported by the library, please motivate this extension.
- Please do not open pull requests that address **multiple issues**.
