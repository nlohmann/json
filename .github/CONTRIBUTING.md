[![Issue Stats](http://issuestats.com/github/nlohmann/json/badge/pr?style=flat)](http://issuestats.com/github/nlohmann/json) [![Issue Stats](http://issuestats.com/github/nlohmann/json/badge/issue?style=flat)](http://issuestats.com/github/nlohmann/json)

# How to contribute

This project started as a little excuse to exercise some of the cool new C++11 features. Over time, people actually started to use the JSON library (yey!) and started to help improve it by proposing features, finding bugs, or even fixing my mistakes. I am really [thankful](https://github.com/nlohmann/json/blob/master/README.md#thanks) for this and try to keep track of all the helpers.

To make it as easy as possible for you to contribute and for me to keep an overview, here are a few guidelines which should help us avoid all kinds of unnecessary work or disappointment. And of course, this document is subject to discussion, so please [create an issue](https://github.com/nlohmann/json/issues/new) or a pull request if you find a way to improve it!

## Prerequisites

Please [create an issue](https://github.com/nlohmann/json/issues/new), assuming one does not already exist, and describe your concern. Note you need a [GitHub account](https://github.com/signup/free) for this.

If you want propose changes to the code, you need to download the [`re2c`](http://re2c.org) tool.

## Describe your issue

Clearly describe the issue:

- If it is a bug, please describe how to **reproduce** it. If possible, attach a complete example which demonstrates the error. Please also state what you **expected** to happen instead of the error.
- If you propose a change or addition, try to give an **example** how the improved code could look like or how to use it.
- If you found a compilation error, please tell us which **compiler** (version and operating system) you used and paste the (relevant part of) the error messages to the ticket.

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

## Wanted

The following areas really need contribution:

- Extending the **continuous integration** toward more exotic compilers such as Android NDK, Intel's Compiler, or the bleeding-edge versions of GCC or Clang.
- Improving the efficiency of the **JSON parser**. The current parser is implemented as a naive recursive descent parser with hand coded string handling. More sophisticated approaches like LALR parsers would be really appreciated. That said, parser generators like Bison or ANTLR do not play nice with single-header files -- I really would like to keep the parser inside the `json.hpp` header, and I am not aware of approaches similar to [`re2c`](http://re2c.org) for parsing.
- Extending and updating existing **benchmarks** to include (the most recent version of) this library. Though efficiency is not everything, speed and memory consumption are very important characteristics for C++ developers, so having proper comparisons would be interesting.
