[Describe your pull request here. Please read the text below the line, and make sure you follow the checklist.]

* * *

## Pull request checklist

Read the [Contribution Guidelines](https://github.com/nlohmann/json/blob/develop/.github/CONTRIBUTING.md) for detailed information.

- [ ]  Changes are described in the pull request, or an [existing issue is referenced](https://github.com/nlohmann/json/issues).
- [ ]  The test suite [compiles and runs](https://github.com/nlohmann/json/blob/develop/README.md#execute-unit-tests) without error.
- [ ]  [Code coverage](https://coveralls.io/github/nlohmann/json) is 100%. Test cases can be added by editing the [test suite](https://github.com/nlohmann/json/tree/develop/test/src).
- [ ]  The source code is amalgamated; that is, after making changes to the sources in the `include/nlohmann` directory, run `make amalgamate` to create the single-header file `single_include/nlohmann/json.hpp`. The whole process is described [here](https://github.com/nlohmann/json/blob/develop/.github/CONTRIBUTING.md#files-to-change).

## Please don't

- The C++11 support varies between different **compilers** and versions. Please note the [list of supported compilers](https://github.com/nlohmann/json/blob/master/README.md#supported-compilers). Some compilers like GCC 4.7 (and earlier), Clang 3.3 (and earlier), or Microsoft Visual Studio 13.0 and earlier are known not to work due to missing or incomplete C++11 support. Please refrain from proposing changes that work around these compiler's limitations with `#ifdef`s or other means.
- Specifically, I am aware of compilation problems with **Microsoft Visual Studio** (there even is an [issue label](https://github.com/nlohmann/json/issues?utf8=✓&q=label%3A%22visual+studio%22+) for these kind of bugs). I understand that even in 2016, complete C++11 support isn't there yet. But please also understand that I do not want to drop features or uglify the code just to make Microsoft's sub-standard compiler happy. The past has shown that there are ways to express the functionality such that the code compiles with the most recent MSVC - unfortunately, this is not the main objective of the project.
- Please refrain from proposing changes that would **break [JSON](https://json.org) conformance**. If you propose a conformant extension of JSON to be supported by the library, please motivate this extension.
- Please do not open pull requests that address **multiple issues**.
