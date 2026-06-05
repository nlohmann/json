# Contribution Guidelines

Thank you for your interest in contributing to this project! What began as an exercise to explore the exciting features
of C++11 has evolved into a [widely used](https://json.nlohmann.me/home/customers/) JSON library. I truly appreciate all
the contributions from the community, whether it's proposing features, identifying bugs, or fixing mistakes! To ensure
that our collaboration is efficient and effective, please follow these guidelines.

Feel free to discuss or suggest improvements to this document
[by submitting a pull request](https://github.com/nlohmann/json/edit/develop/.github/CONTRIBUTING.md).

## Ways to Contribute

There are multiple ways to contribute.

### Reporting an issue

Please [create an issue](https://github.com/nlohmann/json/issues/new/choose), assuming one does not already exist, and
describe your concern. Note you need a [GitHub account](https://github.com/signup/free) for this.

Clearly describe the issue:

- If it is a bug, please describe how to **reproduce** it. If possible, attach a _complete example_ which demonstrates
  the error. Please also state what you **expected** to happen instead of the error.
- If you propose a change or addition, try to give an **example** what the improved code could look like or how to use
  it.
- If you found a compilation error, please tell us which **compiler** (version and operating system) you used and paste
  the (relevant part of) the error messages to the ticket.

Please stick to the provided issue template
[bug report](https://github.com/nlohmann/json/blob/develop/.github/ISSUE_TEMPLATE/bug.yaml) if possible.

### Reporting a security vulnerability

You can report a security vulnerability according to our
[security policy](https://github.com/nlohmann/json/security/policy).

### Discussing a new feature

For questions, feature or support requests, please
[open a discussion](https://github.com/nlohmann/json/discussions/new). If you find a proposed answer satisfactory,
please use the "Mark as answer" button to make it easier for readers to see what helped and for the community to filter
for open questions.

### Proposing a fix or an improvement

Join an ongoing discussion or comment on an existing issue before starting to code. This can help to avoid duplicate
efforts or other frustration during the later review.

Create a [pull request](https://github.com/nlohmann/json/pulls?q=sort%3Aupdated-desc+is%3Apr+is%3Aopen) against the
`develop` branch and follow the pull request template. In particular,

- describe the changes in detail, both the what and why,
- reference existing issues where applicable,
- add tests to maintain 100% test coverage,
- update the documentation as needed, and
- ensure the source code is amalgamated.

We describe all points in detail below.

All contributions (including pull requests) must agree to the
[Developer Certificate of Origin (DCO) version 1.1](https://developercertificate.org). This is exactly the same one
created and used by the Linux kernel developers and posted on http://developercertificate.org/. This is a developer's
certification that he or she has the right to submit the patch for inclusion into the project.

## How to...

### Describe your changes

This library is primarily maintained as a spare-time project. As such, I cannot make any guarantee how quickly changes
are merged and released. Therefore, it is very important to make the review as smooth as possible by explaining not only
_what_ you changed, but _why_. This rationale can be very valuable down the road when improvements or bugs are discussed
years later.

### Reference an existing issue

[Link a pull request to an issue](https://docs.github.com/en/issues/tracking-your-work-with-issues/using-issues/linking-a-pull-request-to-an-issue)
to clarify that a fix is forthcoming and which issue can be closed after merging. Only a few cases (e.g., fixing typos)
do not require prior discussions.

### Write tests

The library has an extensive test suite that currently covers [100 %](https://coveralls.io/github/nlohmann/json) of the
library's code. These tests are crucial to maintain API stability and give future contributors confidence that they do
not accidentally break things. As Titus Winters aptly put it:

> If you liked it, you should have put a test on it.

#### Run the tests

First, ensure the test suite runs before making any changes:

```sh
$ cmake -S. -B build
$ cmake --build build -j 10
$ ctest --test-dir build -j 10
```

The test suite should report:

```
100% tests passed, 0 tests failed out of 98
```

#### Add tests

The tests are located in [`tests/src/unit-*.cpp`](https://github.com/nlohmann/json/tree/develop/tests/src) and contain
[doctest assertions](https://github.com/doctest/doctest/blob/master/doc/markdown/assertions.md) like `CHECK`. The tests
are structured along the features of the library or the nature of the tests. Usually, it should be clear from the
context which existing file needs to be extended, and only very few cases require creating new test files.

When fixing a bug, edit `unit-regression2.cpp` and add a section referencing the fixed issue.

#### Exceptions

When you test exceptions, please use `CHECK_THROWS_WITH_AS` which also takes the `what()` argument of the thrown
exception into account.

#### Coverage

If test coverage decreases, an automatic warning comment will be posted on the pull request. You can access a code
coverage report as an artifact to the “Ubuntu” workflow.

### Update the documentation

The [main documentation](https://json.nlohmann.me) of the library is generated from the files
[`docs/mkdocs/docs`](https://github.com/nlohmann/json/blob/develop/docs/mkdocs/docs). This folder contains dedicated
pages for [certain features](https://github.com/nlohmann/json/tree/develop/docs/mkdocs/docs/features), a list of
[all exceptions](https://github.com/nlohmann/json/blob/develop/docs/mkdocs/docs/home/exceptions.md), and 
[extensive API documentation](https://github.com/nlohmann/json/tree/develop/docs/mkdocs/docs/api) with details on every
public API function.

Build the documentation locally using:

```shell
make install_venv -C docs/mkdocs
make serve -C docs/mkdocs
```

The documentation will then be available at <http://127.0.0.1:8000/>. See the documentation of
[mkdocs](https://www.mkdocs.org) and [Material for MkDocs](https://squidfunk.github.io/mkdocs-material/) for more
information.

### Amalgamate the source code

The single-header files
[`single_include/nlohmann/json.hpp`](https://github.com/nlohmann/json/blob/develop/single_include/nlohmann/json.hpp) and
[`single_include/nlohmann/json_fwd.hpp`](https://github.com/nlohmann/json/blob/develop/single_include/nlohmann/json_fwd.hpp)
are **generated** from the source files in the
[`include/nlohmann` directory](https://github.com/nlohmann/json/tree/develop/include/nlohmann). **Do not** edit the
files directly; instead, modify the include/nlohmann sources and regenerate the files by executing:

```shell
make amalgamate
```

Running `make amalgamate` will also apply automatic formatting to the source files using
[`Artistic Style`](https://astyle.sourceforge.net/). This formatting may modify your source files in-place. Be certain to review and commit any changes to avoid unintended formatting diffs in commits.

## Recommended documentation

- The library’s [README file](https://github.com/nlohmann/json/blob/master/README.md) is an excellent starting point to
  understand its functionality.
- The [documentation page](https://json.nlohmann.me) is the reference documentation of the library.
- [RFC 8259](https://datatracker.ietf.org/doc/html/rfc8259) is the reference for the JavaScript Object Notation (JSON)
  Data Interchange Format.

## Please don't...

Certain contributions are not helpful.

### Break the public API

We take pride in the library being used by
[numerous customers across various industries](https://json.nlohmann.me/home/customers/). They all rely on the
guarantees provided by [semantic versioning](https://semver.org). Please do not change the library such that the public
API of the 3.x.y version is broken. This includes:

- Changing function signatures (altering parameter types, return types, number of parameters) or changing the const-ness
  of member functions.
- Removing functions.
- Renaming functions or classes.
- Changing exception handling.
- Changing exception ids.
- Changing access specifiers.
- Changing default arguments.

Although these guidelines may seem restrictive, they are essential for maintaining the library’s utility.

Breaking changes may be introduced when they are guarded with a feature macro such as
[`JSON_USE_IMPLICIT_CONVERSIONS`](https://json.nlohmann.me/api/macros/json_use_implicit_conversions/) which allows 
selectively changing the behavior of the library. In next steps, the current behavior can then be deprecated. Using
feature macros then allows users to test their code against the library in the next major release.

### Break C++11 language conformance

This library is designed to work with C++11 and later. This means that any
[supported C++11 compiler](https://github.com/nlohmann/json/blob/master/README.md#supported-compilers) should compile
the library without problems. Some compilers like GCC 4.7 (and earlier), Clang 3.3 (and earlier), or Microsoft Visual
Studio 13.0 and earlier are known not to work due to missing or incomplete C++11 support.

Please do not add features that do not work with the mentioned supported compilers. Please guard features from C++14 and
later against the respective [`JSON_HAS_CPP_14`](https://json.nlohmann.me/api/macros/json_has_cpp_11/) macros.

### Break JSON conformance

Please refrain from proposing changes that would **break [JSON](https://datatracker.ietf.org/doc/html/rfc8259)
conformance**. If you propose a conformant extension of JSON to be supported by the library, please motivate this
extension.

## Wanted

The following areas really need contribution and are always welcomed:

- Extending the **continuous integration** toward more exotic compilers such as Android NDK, Intel's Compiler, or the
  bleeding-edge versions Clang.
- Improving the efficiency of the **JSON parser**. The current parser is implemented as a naive recursive descent parser
  with hand-coded string handling. More sophisticated approaches like LALR parsers would be really appreciated. That
  said, parser generators like Bison or ANTLR do not play nice with single-header files -- I really would like to keep
  the parser inside the `json.hpp` header, and I am not aware of approaches similar to [`re2c`](http://re2c.org) for
  parsing.
- Extending and updating existing **benchmarks** to include (the most recent version of) this library. Though efficiency
  is not everything, speed and memory consumption are very important characteristics for C++ developers, so having
  proper comparisons would be interesting.

We look forward to your contributions and collaboration to enhance the library!
