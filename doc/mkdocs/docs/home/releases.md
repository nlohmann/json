# Releases

## v3.7.3

!!! summary "Files"

    - [include.zip](https://github.com/nlohmann/json/releases/download/v3.7.3/include.zip) (274 KB)
    - [include.zip.asc](https://github.com/nlohmann/json/releases/download/v3.7.3/include.zip.asc) (1 KB)
    - [json.hpp](https://github.com/nlohmann/json/releases/download/v3.7.3/json.hpp) (791 KB)
    - [json.hpp.asc](https://github.com/nlohmann/json/releases/download/v3.7.3/json.hpp.asc) (1 KB)

Release date: 2019-11-17
SHA-256: 3b5d2b8f8282b80557091514d8ab97e27f9574336c804ee666fda673a9b59926 (json.hpp), 87b5884741427220d3a33df1363ae0e8b898099fbc59f1c451113f6732891014 (include.zip)

### Summary

This release fixes a bug introduced in release 3.7.2 which could yield quadratic complexity in destructor calls. All changes are backward-compatible.

### :bug: Bug Fixes

- Removed `reserve()` calls from the destructor which could lead to quadratic complexity. #1837 #1838

### :fire: Deprecated functions

This release does not deprecate any functions. As an overview, the following functions have been deprecated in earlier versions and will be removed in the next major version (i.e., 4.0.0):

- Function [`iterator_wrapper`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_af1592a06bc63811886ade4f9d965045e.html#af1592a06bc63811886ade4f9d965045e) are deprecated. Please use the member function [`items()`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_afe3e137ace692efa08590d8df40f58dd.html#afe3e137ace692efa08590d8df40f58dd) instead.
- Functions [`friend std::istream& operator<<(basic_json&, std::istream&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_ab7285a92514fcdbe6de505ebaba92ea3.html#ab7285a92514fcdbe6de505ebaba92ea3) and [`friend std::ostream& operator>>(const basic_json&, std::ostream&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_a9e06deabe69262c3ffc5533d32856983.html#a9e06deabe69262c3ffc5533d32856983) are deprecated. Please use [`friend std::istream&  operator>>(std::istream&, basic_json&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_aaf363408931d76472ded14017e59c9e8.html#aaf363408931d76472ded14017e59c9e8) and [`friend operator<<(std::ostream&, const basic_json&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_a5e34c5435e557d0bf666bd7311211405.html#a5e34c5435e557d0bf666bd7311211405) instead.


## v3.7.2

!!! summary "Files"

    - [include.zip](https://github.com/nlohmann/json/releases/download/v3.7.2/include.zip) (274 KB)
    - [include.zip.asc](https://github.com/nlohmann/json/releases/download/v3.7.2/include.zip.asc) (1 KB)
    - [json.hpp](https://github.com/nlohmann/json/releases/download/v3.7.2/json.hpp) (791 KB)
    - [json.hpp.asc](https://github.com/nlohmann/json/releases/download/v3.7.2/json.hpp.asc) (1 KB)

Release date: 2019-11-10
SHA-256: 0a65fcbbe1b334d3f45c9498e5ee28c3f3b2428aea98557da4a3ff12f0f14ad6 (json.hpp), 67f69c9a93b7fa0612dc1b6273119d2c560317333581845f358aaa68bff8f087 (include.zip)

### Summary

Project [bad_json_parsers](https://github.com/lovasoa/bad_json_parsers) tested how JSON parser libraries react on **deeply nested inputs**. It turns out that this library segfaulted at a certain nesting depth. This bug was fixed with this release. **Now the parsing is only bounded by the available memory.** All changes are backward-compatible.

### :bug: Bug Fixes

* Fixed a bug that lead to stack overflow for deeply nested JSON values (objects, array) by changing the implementation of the destructor from a recursive to an iterative approach. #832, #1419, #1835

### :hammer: Further Changes

* Added WhiteStone Bolt. #1830

### :fire: Deprecated functions

This release does not deprecate any functions. As an overview, the following functions have been deprecated in earlier versions and will be removed in the next major version (i.e., 4.0.0):

- Function [`iterator_wrapper`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_af1592a06bc63811886ade4f9d965045e.html#af1592a06bc63811886ade4f9d965045e) are deprecated. Please use the member function [`items()`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_afe3e137ace692efa08590d8df40f58dd.html#afe3e137ace692efa08590d8df40f58dd) instead.
- Functions [`friend std::istream& operator<<(basic_json&, std::istream&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_ab7285a92514fcdbe6de505ebaba92ea3.html#ab7285a92514fcdbe6de505ebaba92ea3) and [`friend std::ostream& operator>>(const basic_json&, std::ostream&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_a9e06deabe69262c3ffc5533d32856983.html#a9e06deabe69262c3ffc5533d32856983) are deprecated. Please use [`friend std::istream&  operator>>(std::istream&, basic_json&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_aaf363408931d76472ded14017e59c9e8.html#aaf363408931d76472ded14017e59c9e8) and [`friend operator<<(std::ostream&, const basic_json&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_a5e34c5435e557d0bf666bd7311211405.html#a5e34c5435e557d0bf666bd7311211405) instead.

## v3.7.1

!!! summary "Files"

    - [include.zip](https://github.com/nlohmann/json/releases/download/v3.7.1/include.zip) (273 KB)
    - [include.zip.asc](https://github.com/nlohmann/json/releases/download/v3.7.1/include.zip.asc) (1 KB)
    - [json.hpp](https://github.com/nlohmann/json/releases/download/v3.7.1/json.hpp) (789 KB)
    - [json.hpp.asc](https://github.com/nlohmann/json/releases/download/v3.7.1/json.hpp.asc) (1 KB)

Release date: 2019-11-06
SHA-256: b5ba7228f3c22a882d379e93d08eab4349458ee16fbf45291347994eac7dc7ce (json.hpp), 77b9f54b34e7989e6f402afb516f7ff2830df551c3a36973085e2c7a6b1045fe (include.zip)

### Summary

This release fixes several small bugs in the library. All changes are backward-compatible.

### :bug: Bug Fixes

- Fixed a segmentation fault when serializing `std::int64_t` minimum value. #1708 #1722
- Fixed the [`contains()`](https://nlohmann.github.io/json/classnlohmann_1_1basic__json_ab23b04802eb9da97dc3f664e54e09cb3.html#ab23b04802eb9da97dc3f664e54e09cb3) function for JSON Pointers. #1727 #1741
- Fixed too lax SFINAE guard for conversion from `std::pair` and `std::tuple` to `json`. #1805 #1806 #1825 #1826
- Fixed some regressions detected by UBSAN. Updated CI to use Clang-Tidy 7.1.0. #1716 #1728
- Fixed integer truncation in `iteration_proxy`. #1797
- Updated [Hedley](https://github.com/nemequ/hedley) to v11 to [fix a E2512 error](https://github.com/nemequ/hedley/issues/28) in MSVC. #1799
- Fixed a compile error in enum deserialization of non non-default-constructible types. #1647 #1821
- Fixed the conversion from `json` to `std::valarray`.

### :zap: Improvements

- The [`items()`](https://nlohmann.github.io/json/classnlohmann_1_1basic__json_afe3e137ace692efa08590d8df40f58dd.html#afe3e137ace692efa08590d8df40f58dd) function can now be used with a custom string type. #1765
- Made [`json_pointer::back`](https://nlohmann.github.io/json/classnlohmann_1_1json__pointer_a213bc67c32a30c68ac6bf06f5195d482.html#a213bc67c32a30c68ac6bf06f5195d482) `const`. #1764 #1769
- Meson is part of the release archive. #1672 #1694 
- Improved documentation on the Meson and Spack package manager. #1694 #1720

### :hammer: Further Changes

- Added GitHub Workflow with `ubuntu-latest`/GCC 7.4.0 as CI step.
- Added GCC 9 to Travis CI to compile with C++20 support. #1724
- Added MSVC 2019 to the AppVeyor CI. #1780
- Added badge to [fuzzing status](https://bugs.chromium.org/p/oss-fuzz/issues/list?sort=-opened&can=1&q=proj:json).
- Fixed some cppcheck warnings. #1760
- Fixed several typos in the documentation. #1720 #1767 #1803
- Added documentation on the `JSON_THROW_USER`, `JSON_TRY_USER`, and `JSON_CATCH_USER` macros to control user-defined exception handling.
- Used GitHub's [CODEOWNERS](https://github.com/nlohmann/json/blob/develop/.github/CODEOWNERS) and [SECURITY](https://github.com/nlohmann/json/blob/develop/.github/SECURITY.md) feature.
- Removed `GLOB` from CMake files. #1779
- Updated to [Doctest](https://github.com/onqtam/doctest) 2.3.5.

### :fire: Deprecated functions

This release does not deprecate any functions. As an overview, the following functions have been deprecated in earlier versions and will be removed in the next major version (i.e., 4.0.0):

- Function [`iterator_wrapper`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_af1592a06bc63811886ade4f9d965045e.html#af1592a06bc63811886ade4f9d965045e) are deprecated. Please use the member function [`items()`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_afe3e137ace692efa08590d8df40f58dd.html#afe3e137ace692efa08590d8df40f58dd) instead.
- Functions [`friend std::istream& operator<<(basic_json&, std::istream&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_ab7285a92514fcdbe6de505ebaba92ea3.html#ab7285a92514fcdbe6de505ebaba92ea3) and [`friend std::ostream& operator>>(const basic_json&, std::ostream&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_a9e06deabe69262c3ffc5533d32856983.html#a9e06deabe69262c3ffc5533d32856983) are deprecated. Please use [`friend std::istream&  operator>>(std::istream&, basic_json&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_aaf363408931d76472ded14017e59c9e8.html#aaf363408931d76472ded14017e59c9e8) and [`friend operator<<(std::ostream&, const basic_json&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_a5e34c5435e557d0bf666bd7311211405.html#a5e34c5435e557d0bf666bd7311211405) instead.

## v3.7.0

!!! summary "Files"

    - [include.zip](https://github.com/nlohmann/json/releases/download/v3.7.0/include.zip) (143 KB)
    - [include.zip.asc](https://github.com/nlohmann/json/releases/download/v3.7.0/include.zip.asc) (1 KB)
    - [json.hpp](https://github.com/nlohmann/json/releases/download/v3.7.0/json.hpp) (782 KB)
    - [json.hpp.asc](https://github.com/nlohmann/json/releases/download/v3.7.0/json.hpp.asc) (1 KB)

Release date: 2019-07-28
SHA-256: a503214947952b69f0062f572cb74c17582a495767446347ce2e452963fc2ca4 (json.hpp), 541c34438fd54182e9cdc68dd20c898d766713ad6d901fb2c6e28ff1f1e7c10d (include.zip)

### Summary

This release introduces a few convenience functions and performs a lot of house keeping (bug fixes and small improvements). All changes are backward-compatible.

### :sparkles: New Features

- Add overload of the **[`contains`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_ab23b04802eb9da97dc3f664e54e09cb3.html#ab23b04802eb9da97dc3f664e54e09cb3) function** to check if a JSON pointer is valid without throwing exceptions, just like its [counterpart for object keys](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_a9286acdc0578fc66e9346323e69fc0e3.html#a9286acdc0578fc66e9346323e69fc0e3). #1600
- Add a function **[`to_string`](http://nlohmann.github.io/json/doxygen/namespacenlohmann_a6ce645a0b8717757e096a5b5773b7a16.html#a6ce645a0b8717757e096a5b5773b7a16)** to allow for generic conversion to strings. #916 #1585
- Add **return value for the [`emplace_back`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_abf29131f898b05aad2c01a9c80e7a002.html#abf29131f898b05aad2c01a9c80e7a002) function**, returning a reference to the added element just like C++17 is [introducing this](https://en.cppreference.com/w/cpp/container/vector/emplace_back) for `std::vector`. #1609
- Add info how to use the library with the **[pacman](https://wiki.archlinux.org/index.php/pacman) package manager** on MSYS2. #1670

### :bug: Bug Fixes

- Fix an issue where typedefs with certain names yielded a compilation error. #1642 #1643
- Fix a conversion to `std::string_view` in the unit tests. #1634 #1639
- Fix MSVC Debug build. #1536 #1570 #1608
- Fix [`get_to`](https://nlohmann.github.io/json/classnlohmann_1_1basic__json_a65753c68f06639eda0d355f919564e01.html#a65753c68f06639eda0d355f919564e01) method to clear existing content before writing. #1511 #1555
- Fix a `-Wc++17-extensions` warning. `nodiscard` attributes are now only used with Clang when `-std=c++17` is used. #1535 #1551

### :zap: Improvements

- Switch from [Catch](https://github.com/philsquared/Catch) to **[doctest](https://github.com/onqtam/doctest)** for the unit tests which speeds up compilation and runtime of the 112,112,308 tests.
- Add an explicit section to the [README](https://github.com/nlohmann/json/blob/develop/README.md) about the **frequently addressed topics** [character encoding](https://github.com/nlohmann/json#character-encoding), [comments in JSON](https://github.com/nlohmann/json#comments-in-json), and the [order of object keys](https://github.com/nlohmann/json#order-of-object-keys).

### :hammer: Further Changes

- Use [`GNUInstallDirs`](https://cmake.org/cmake/help/v3.0/module/GNUInstallDirs.html) to set library install directories. #1673
- Fix links in the [README](https://github.com/nlohmann/json/blob/develop/README.md). #1620 #1621 #1622 #1623 #1625
- Mention [`json` type](http://nlohmann.github.io/json/doxygen/namespacenlohmann_a2bfd99e845a2e5cd90aeaf1b1431f474.html#a2bfd99e845a2e5cd90aeaf1b1431f474) on the [documentation start page](http://nlohmann.github.io/json/doxygen/index.html). #1616
- Complete documentation of [`value()` function](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_adcf8ca5079f5db993820bf50036bf45d.html#adcf8ca5079f5db993820bf50036bf45d) with respect to `type_error.302` exception. #1601
- Fix links in the documentation. #1598
- Add regression tests for MSVC. #1543 #1570
- Use **[CircleCI](http://circleci.com)** for [continuous integration](https://circleci.com/gh/nlohmann/json).
- Use **[Doozer](https://doozer.io)** for [continuous integration](https://doozer.io/nlohmann/json) on Linux (CentOS, Raspbian, Fedora)
- Add tests to check each CMake flag (`JSON_BuildTests`, `JSON_Install`, `JSON_MultipleHeaders`, `JSON_Sanitizer`, `JSON_Valgrind`, `JSON_NoExceptions`, `JSON_Coverage`).
- Use [Hedley](https://nemequ.github.io/hedley/) to avoid re-inventing several compiler-agnostic feature macros like `JSON_DEPRECATED`, `JSON_NODISCARD`, `JSON_LIKELY`, `JSON_UNLIKELY`, `JSON_HAS_CPP_14`, or `JSON_HAS_CPP_17`. Functions taking or returning pointers are annotated accordingly when a pointer will not be null.
- Build and run tests on [AppVeyor](https://ci.appveyor.com/project/nlohmann/json) in DEBUG and RELEASE mode.

### :fire: Deprecated functions

This release does not deprecate any functions. As an overview, the following functions have been deprecated in earlier versions and will be removed in the next major version (i.e., 4.0.0):

- Function [`iterator_wrapper`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_af1592a06bc63811886ade4f9d965045e.html#af1592a06bc63811886ade4f9d965045e) are deprecated. Please use the member function [`items()`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_afe3e137ace692efa08590d8df40f58dd.html#afe3e137ace692efa08590d8df40f58dd) instead.
- Functions [`friend std::istream& operator<<(basic_json&, std::istream&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_ab7285a92514fcdbe6de505ebaba92ea3.html#ab7285a92514fcdbe6de505ebaba92ea3) and [`friend std::ostream& operator>>(const basic_json&, std::ostream&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_a9e06deabe69262c3ffc5533d32856983.html#a9e06deabe69262c3ffc5533d32856983) are deprecated. Please use [`friend std::istream&  operator>>(std::istream&, basic_json&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_aaf363408931d76472ded14017e59c9e8.html#aaf363408931d76472ded14017e59c9e8) and [`friend operator<<(std::ostream&, const basic_json&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_a5e34c5435e557d0bf666bd7311211405.html#a5e34c5435e557d0bf666bd7311211405) instead.

## v3.6.1

!!! summary "Files"

    - [include.zip](https://github.com/nlohmann/json/releases/download/v3.6.1/include.zip) (136 KB)
    - [include.zip.asc](https://github.com/nlohmann/json/releases/download/v3.6.1/include.zip.asc) (1 KB)
    - [json.hpp](https://github.com/nlohmann/json/releases/download/v3.6.1/json.hpp) (711 KB)
    - [json.hpp.asc](https://github.com/nlohmann/json/releases/download/v3.6.1/json.hpp.asc) (1 KB)

Release date: 2019-03-20
SHA-256: d2eeb25d2e95bffeb08ebb7704cdffd2e8fca7113eba9a0b38d60a5c391ea09a (json.hpp), 69cc88207ce91347ea530b227ff0776db82dcb8de6704e1a3d74f4841bc651cf (include.zip)

### Summary

This release **fixes a regression and a bug** introduced by the earlier 3.6.0 release. All changes are backward-compatible.

### :bug: Bug Fixes

- Fixed regression of #590 which could lead to compilation errors with GCC 7 and GCC 8. #1530
- Fixed a compilation error when `<Windows.h>` was included. #1531

### :hammer: Further Changes

- Fixed a warning for missing field initializers. #1527

### :fire: Deprecated functions

This release does not deprecate any functions. As an overview, the following functions have been deprecated in earlier versions and will be removed in the next major version (i.e., 4.0.0):

- Function [`iterator_wrapper`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_af1592a06bc63811886ade4f9d965045e.html#af1592a06bc63811886ade4f9d965045e) are deprecated. Please use the member function [`items()`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_afe3e137ace692efa08590d8df40f58dd.html#afe3e137ace692efa08590d8df40f58dd) instead.
- Functions [`friend std::istream& operator<<(basic_json&, std::istream&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_ab7285a92514fcdbe6de505ebaba92ea3.html#ab7285a92514fcdbe6de505ebaba92ea3) and [`friend std::ostream& operator>>(const basic_json&, std::ostream&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_a9e06deabe69262c3ffc5533d32856983.html#a9e06deabe69262c3ffc5533d32856983) are deprecated. Please use [`friend std::istream&  operator>>(std::istream&, basic_json&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_aaf363408931d76472ded14017e59c9e8.html#aaf363408931d76472ded14017e59c9e8) and [`friend operator<<(std::ostream&, const basic_json&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_a5e34c5435e557d0bf666bd7311211405.html#a5e34c5435e557d0bf666bd7311211405) instead.

## v3.6.0

!!! summary "Files"

    - [include.zip](https://github.com/nlohmann/json/releases/download/v3.6.0/include.zip) (136 KB)
    - [include.zip.asc](https://github.com/nlohmann/json/releases/download/v3.6.0/include.zip.asc) (1 KB)
    - [json.hpp](https://github.com/nlohmann/json/releases/download/v3.6.0/json.hpp) (711 KB)
    - [json.hpp.asc](https://github.com/nlohmann/json/releases/download/v3.6.0/json.hpp.asc) (1 KB)

Release date: 2019-03-20
SHA-256: ce9839370f28094c71107c405affb3b08c4a098154988014cbb0800b1c44a831 (json.hpp), 237c5e66e7f8186a02804ce9dbd5f69ce89fe7424ef84adf6142e973bd9532f4 (include.zip)

ℹ️ **This release introduced a regression. Please update to [version 3.6.1](https://github.com/nlohmann/json/releases/tag/v3.6.1)!**

### Summary

This release adds some **convenience functions for JSON Pointers**, introduces a [`contains`](
http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_a0a45fc740637123fdf05fef970f8be47.html#a0a45fc740637123fdf05fef970f8be47) function to check if a key is present in an object, and improves the **performance of integer serialization**. Furthermore, a lot of small bug fixes and improvements have been made. All changes are backward-compatible.

### :sparkles: New Features

- Overworked the public interface for JSON Pointers. The creation of JSON Pointers is simplified with [`operator/`](
http://nlohmann.github.io/json/doxygen/classnlohmann_1_1json__pointer_a90a11fe6c7f37b1746a3ff9cb24b0d53.html#a90a11fe6c7f37b1746a3ff9cb24b0d53) and [`operator/=`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1json__pointer_a7395bd0af29ac23fd3f21543c935cdfa.html#a7395bd0af29ac23fd3f21543c935cdfa). JSON Pointers can be inspected with [`empty`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1json__pointer_a649252bda4a2e75a0915b11a25d8bcc3.html#a649252bda4a2e75a0915b11a25d8bcc3), [`back`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1json__pointer_a6bd5b554c10f15672135c216893eef31.html#a6bd5b554c10f15672135c216893eef31),  and [`parent_pointer`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1json__pointer_afdaacce1edb7145e0434e014f0e8685a.html#afdaacce1edb7145e0434e014f0e8685a), and manipulated with [`push_back`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1json__pointer_a697d12b5bd6205f8866691b166b7c7dc.html#a697d12b5bd6205f8866691b166b7c7dc) and [`pop_back`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1json__pointer_a4b1ee4d511ca195bed896a3da47e264c.html#a4b1ee4d511ca195bed896a3da47e264c). #1434
- Added a boolean method [`contains`](
http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_a0a45fc740637123fdf05fef970f8be47.html#a0a45fc740637123fdf05fef970f8be47) to check whether an element exists in a JSON object with a given key. Returns false when called on non-object types. #1471 #1474

### :bug: Bug Fixes

- Fixed a compilation issues with libc 2.12. #1483 #1514
- Fixed endian conversion on PPC64. #1489
- Fixed library to compile with GCC 9. #1472 #1492
- Fixed a compilation issue with GCC 7 on CentOS. #1496
- Fixed an integer overflow. #1447
- Fixed buffer flushing in serializer. #1445 #1446

### :zap: Improvements

- The performance of dumping integers has been greatly improved. #1411
- Added CMake parameter `JSON_Install` to control whether the library should be installed (default: on). #1330
- Fixed a lot of compiler and linter warnings. #1400 #1435 #1502
- Reduced required CMake version from 3.8 to 3.1. #1409 #1428 #1441 #1498
- Added `nodiscard` attribute to `meta()`, `array()`, `object()`, `from_cbor`, `from_msgpack`, `from_ubjson`, `from_bson`, and `parse`. #1433

### :hammer: Further Changes

- Added missing headers. #1500
- Fixed typos and broken links in README. #1417 #1423 #1425 #1451 #1455 #1491
- Fixed documentation of parse function. #1473
- Suppressed warning that cannot be fixed inside the library. #1401 #1468
- Imroved package manager suppert:
	- Updated Buckaroo instructions. #1495
	- Improved Meson support. #1463
	- Added Conda package manager documentation. #1430
	- Added NuGet package manager documentation. #1132
- Continuous Integration
	- Removed unstable or deprecated Travis builders (Xcode 6.4 - 8.2) and added Xcode 10.1 builder.
	- Added Clang 7 to Travis CI.
	- Fixed AppVeyor x64 builds. #1374 #1414
- Updated thirdparty libraries:
	- Catch 1.12.0 -> 1.12.2
	- Google Benchmark 1.3.0 -> 1.4.1
	- Doxygen 1.8.15 -> 1.8.16

### :fire: Deprecated functions

This release does not deprecate any functions. As an overview, the following functions have been deprecated in earlier versions and will be removed in the next major version (i.e., 4.0.0):

- Function [`iterator_wrapper`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_af1592a06bc63811886ade4f9d965045e.html#af1592a06bc63811886ade4f9d965045e) are deprecated. Please use the member function [`items()`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_afe3e137ace692efa08590d8df40f58dd.html#afe3e137ace692efa08590d8df40f58dd) instead.
- Functions [`friend std::istream& operator<<(basic_json&, std::istream&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_ab7285a92514fcdbe6de505ebaba92ea3.html#ab7285a92514fcdbe6de505ebaba92ea3) and [`friend std::ostream& operator>>(const basic_json&, std::ostream&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_a9e06deabe69262c3ffc5533d32856983.html#a9e06deabe69262c3ffc5533d32856983) are deprecated. Please use [`friend std::istream&  operator>>(std::istream&, basic_json&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_aaf363408931d76472ded14017e59c9e8.html#aaf363408931d76472ded14017e59c9e8) and [`friend operator<<(std::ostream&, const basic_json&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_a5e34c5435e557d0bf666bd7311211405.html#a5e34c5435e557d0bf666bd7311211405) instead.

## v3.5.0

!!! summary "Files"

    - [include.zip](https://github.com/nlohmann/json/releases/download/v3.5.0/include.zip) (133 KB)
    - [include.zip.asc](https://github.com/nlohmann/json/releases/download/v3.5.0/include.zip.asc) (1 KB)
    - [json.hpp](https://github.com/nlohmann/json/releases/download/v3.5.0/json.hpp) (693 KB)
    - [json.hpp.asc](https://github.com/nlohmann/json/releases/download/v3.5.0/json.hpp.asc) (1 KB)

Release date: 2018-12-22
SHA-256: 8a6dbf3bf01156f438d0ca7e78c2971bca50eec4ca6f0cf59adf3464c43bb9d5 (json.hpp), 3564da9c5b0cf2e032f97c69baedf10ddbc98030c337d0327a215ea72259ea21 (include.zip)

### Summary

This release introduces the support for **structured bindings** and reading from **`FILE*`**. Besides, a few bugs have been fixed. All changes are backward-compatible.

### :sparkles: New Features

- **Structured bindings** are now supported for JSON objects and arrays via the [`items()`](https://nlohmann.github.io/json/classnlohmann_1_1basic__json_afe3e137ace692efa08590d8df40f58dd.html#afe3e137ace692efa08590d8df40f58dd) member function, so finally this code is possible:
  ```cpp
  for (auto& [key, val] : j.items()) {
      std::cout << key << ':' << val << '\n';
  }
  ```  
  #1388 #1391

- Added support for **reading from `FILE*`** to support situations in which streams are nit available or would require too much RAM. #1370 #1392

### :bug: Bug Fixes

- The `eofbit` was not set for input streams when the end of a stream was reached while parsing. #1340 #1343
- Fixed a bug in the SAX parser for BSON arrays.

### :zap: Improvements

- Added support for Clang 5.0.1 (PS4 version). #1341 #1342

### :hammer: Further Changes

- Added a warning for implicit conversions to the documentation: It is not recommended to use implicit conversions when reading **from** a JSON value. Details about this recommendation can be found [here](https://www.github.com/nlohmann/json/issues/958).  #1363
- Fixed typos in the documentation. #1329 #1380 #1382
- Fixed a C4800 warning. #1364
- Fixed a `-Wshadow` warning #1346
- Wrapped `std::snprintf` calls to avoid error in MSVC. #1337
- Added code to allow installation via Meson. #1345

### :fire: Deprecated functions

This release does not deprecate any functions. As an overview, the following functions have been deprecated in earlier versions and will be removed in the next major version (i.e., 4.0.0):

- Function [`iterator_wrapper`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_af1592a06bc63811886ade4f9d965045e.html#af1592a06bc63811886ade4f9d965045e) are deprecated. Please use the member function [`items()`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_afe3e137ace692efa08590d8df40f58dd.html#afe3e137ace692efa08590d8df40f58dd) instead.
- Functions [`friend std::istream& operator<<(basic_json&, std::istream&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_ab7285a92514fcdbe6de505ebaba92ea3.html#ab7285a92514fcdbe6de505ebaba92ea3) and [`friend std::ostream& operator>>(const basic_json&, std::ostream&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_a9e06deabe69262c3ffc5533d32856983.html#a9e06deabe69262c3ffc5533d32856983) are deprecated. Please use [`friend std::istream&  operator>>(std::istream&, basic_json&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_aaf363408931d76472ded14017e59c9e8.html#aaf363408931d76472ded14017e59c9e8) and [`friend operator<<(std::ostream&, const basic_json&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_a5e34c5435e557d0bf666bd7311211405.html#a5e34c5435e557d0bf666bd7311211405) instead.

## v3.4.0

!!! summary "Files"

    - [include.zip](https://github.com/nlohmann/json/releases/download/v3.4.0/include.zip) (132 KB)
    - [include.zip.asc](https://github.com/nlohmann/json/releases/download/v3.4.0/include.zip.asc) (1 KB)
    - [json.hpp](https://github.com/nlohmann/json/releases/download/v3.4.0/json.hpp) (689 KB)
    - [json.hpp.asc](https://github.com/nlohmann/json/releases/download/v3.4.0/json.hpp.asc) (1 KB)

Release date: 2018-10-30
SHA-256: 63da6d1f22b2a7bb9e4ff7d6b255cf691a161ff49532dcc45d398a53e295835f (json.hpp), bfec46fc0cee01c509cf064d2254517e7fa80d1e7647fea37cf81d97c5682bdc (include.zip)

### Summary

This release introduces three new features:

- **BSON (Binary JSON)** is next to CBOR, MessagePack, and UBJSON the fourth binary (de)serialization format supported by the library.
- **Adjustable error handlers for invalid Unicode** allows to specify the behavior when invalid byte sequences are serialized.
- **Simplified enum/JSON mapping** with a macro in case the default mapping to integers is not desired.

Furthermore, some effort has been invested in improving the **parse error messages**. Besides, a few bugs have been fixed. All changes are backward-compatible.

### :sparkles: New Features

- The library can read and write a subset of **[BSON](http://bsonspec.org/) (Binary JSON)**. All data types known from JSON are supported, whereas other types more tied to MongoDB such as timestamps, object ids, or binary data are currently not implemented. See [the README](https://github.com/nlohmann/json#binary-formats-bson-cbor-messagepack-and-ubjson) for examples. #1244 #1320
- The behavior when the library encounters an invalid Unicode sequence during serialization can now be controlled by defining one of three **Unicode error handlers**: (1) throw an exception (default behavior), (2) replace invalid sequences by the Unicode replacement character (U+FFFD), or (3) ignore/filter invalid sequences. See the [documentation of the `dump` function](https://nlohmann.github.io/json/classnlohmann_1_1basic__json_a50ec80b02d0f3f51130d4abb5d1cfdc5.html#a50ec80b02d0f3f51130d4abb5d1cfdc5) for examples. #1198 #1314
- To easily specify a user-defined **enum/JSON mapping**, a macro `NLOHMANN_JSON_SERIALIZE_ENUM` has been introduced. See the [README section](https://github.com/nlohmann/json#specializing-enum-conversion) for more information. #1208 #1323

### :bug: Bug Fixes

- fixed truncation #1286 #1315
- fixed an issue with std::pair #1299 #1301
- fixed an issue with std::variant #1292 #1294
- fixed a bug in the JSON Pointer parser

### :zap: Improvements

- The **diagnosis messages for parse errors** have been improved: error messages now indicated line/column positions where possible (in addition to a byte count) and also the context in which the error occurred (e.g., "while parsing a JSON string"). Example: error `parse error at 2: syntax error - invalid string: control character must be escaped; last read: '<U+0009>'` is now reported as `parse error at line 1, column 2: syntax error while parsing value - invalid string: control character U+0009 (HT) must be escaped to \u0009 or \t; last read: '<U+0009>'`. #1280 #1288 #1303

### :hammer: Further Changes

- improved Meson documentation #1305
- fixed some more linter warnings #1280
- fixed Clang detection for third-party Google Benchmark library #1277

### :fire: Deprecated functions

This release does not deprecate any functions. As an overview, the following functions have been deprecated in earlier versions and will be removed in the next major version (i.e., 4.0.0):

- Function [`iterator_wrapper`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_af1592a06bc63811886ade4f9d965045e.html#af1592a06bc63811886ade4f9d965045e) are deprecated. Please use the member function [`items()`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_afe3e137ace692efa08590d8df40f58dd.html#afe3e137ace692efa08590d8df40f58dd) instead.
- Functions [`friend std::istream& operator<<(basic_json&, std::istream&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_ab7285a92514fcdbe6de505ebaba92ea3.html#ab7285a92514fcdbe6de505ebaba92ea3) and [`friend std::ostream& operator>>(const basic_json&, std::ostream&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_a9e06deabe69262c3ffc5533d32856983.html#a9e06deabe69262c3ffc5533d32856983) are deprecated. Please use [`friend std::istream&  operator>>(std::istream&, basic_json&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_aaf363408931d76472ded14017e59c9e8.html#aaf363408931d76472ded14017e59c9e8) and [`friend operator<<(std::ostream&, const basic_json&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_a5e34c5435e557d0bf666bd7311211405.html#a5e34c5435e557d0bf666bd7311211405) instead.

## v3.3.0

!!! summary "Files"

    - [include.zip](https://github.com/nlohmann/json/releases/download/v3.3.0/include.zip) (123 KB)
    - [include.zip.asc](https://github.com/nlohmann/json/releases/download/v3.3.0/include.zip.asc) (1 KB)
    - [json.hpp](https://github.com/nlohmann/json/releases/download/v3.3.0/json.hpp) (635 KB)
    - [json.hpp.asc](https://github.com/nlohmann/json/releases/download/v3.3.0/json.hpp.asc) (1 KB)

Release date: 2018-10-05
SHA-256: f1327bb60c58757a3dd2b0c9c45d49503d571337681d950ec621f8374bcc14d4 (json.hpp), 9588d63557333aaa485e92221ec38014a85a6134e7486fe3441e0541a5a89576 (include.zip)

### Summary

This release adds support for **GCC 4.8**. Furthermore, it adds a function [**`get_to`**](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_a8a3db7d78f74232d3a6fb8f1abf69709.html#a8a3db7d78f74232d3a6fb8f1abf69709) to write a JSON value to a passed reference. Another topic of this release was the **CMake support** which has been overworked and documented.

Besides, a lot of bugs have been fixed and slight improvements have been made. All changes are backward-compatible.

### :sparkles: New Features

- The library can now also built with **GCC 4.8**. Though this compiler does not fully support C++11, it can successfully compile and run the test suite. Note that bug [57824](https://gcc.gnu.org/bugzilla/show_bug.cgi?id=57824) in GCC 4.8 still forbids to use multiline raw strings in arguments to macros. #1257
- Added new function [**`get_to`**](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_a8a3db7d78f74232d3a6fb8f1abf69709.html#a8a3db7d78f74232d3a6fb8f1abf69709) to write a JSON value to a passed reference. The destination type is automatically derived which allows more succinct code compared to the `get` function. #1227 #1231

### :bug: Bug Fixes

- Fixed a bug in the CMake file that made `target_link_libraries` to not properly include `nlohmann_json`. #1243 #1245 #1260
- Fixed a warning in MSVC 2017 complaining about a constexpr if. #1204 #1268 #1272
- Fixed a bug that prevented compilation with ICPC. #755 #1222
- Improved the SFINAE correctness to fix a bug in the conversion operator. #1237 #1238
- Fixed a `-Wctor-dtor-privacy` warning. #1224
- Fixed a warning on a lambda in unevaluated context. #1225 #1230
- Fixed a bug introduced in version 3.2.0 where defining `JSON_CATCH_USER` led to duplicate macro definition of `JSON_INTERNAL_CATCH`. #1213 #1214
- Fixed a bug that prevented compilation with Clang 3.4.2 in RHEL 7. #1179 #1249

### :zap: Improvements

- Added [documentation on CMake integration](https://github.com/nlohmann/json#cmake) of the library. #1270
- Changed the CMake file to use `find_package(nlohmann_json)` without installing the library. #1202
- Improved error messages in case `operator[]` is used with the wrong combination (json.exception.type_error.305) of JSON container type and argument type. Example: "cannot use operator[] with a string argument". #1220 #1221
- Added a license and version information to the Meson build file. #1252
- Removed static assertions to indicated missing `to_json` or `from_json` functions as such assertions do not play well with SFINAE. These assertions also led to problems with GMock. #960 #1212 #1228
- The test suite now does not wait forever if run in a wrong directory and input files are not found. #1262
- The test suite does not show deprecation warnings for deprecated functions which frequently led to confusion. #1271

### :hammer: Further Changes

- GCC 4.8 and Xcode 10 were added to the [continuous integration suite](https://travis-ci.org/nlohmann/json) at Travis.
- Added [lgtm](https://lgtm.com/projects/g/nlohmann/json/context:cpp) checks to pull requests.
- Added tests for CMake integration. #1260

### :fire: Deprecated functions

This release does not deprecate any functions. As an overview, the following functions have been deprecated in earlier versions and will be removed in the next major version (i.e., 4.0.0):

- Function [`iterator_wrapper`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_af1592a06bc63811886ade4f9d965045e.html#af1592a06bc63811886ade4f9d965045e) are deprecated. Please use the member function [`items()`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_afe3e137ace692efa08590d8df40f58dd.html#afe3e137ace692efa08590d8df40f58dd) instead.
- Functions [`friend std::istream& operator<<(basic_json&, std::istream&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_ab7285a92514fcdbe6de505ebaba92ea3.html#ab7285a92514fcdbe6de505ebaba92ea3) and [`friend std::ostream& operator>>(const basic_json&, std::ostream&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_a9e06deabe69262c3ffc5533d32856983.html#a9e06deabe69262c3ffc5533d32856983) are deprecated. Please use [`friend std::istream&  operator>>(std::istream&, basic_json&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_aaf363408931d76472ded14017e59c9e8.html#aaf363408931d76472ded14017e59c9e8) and [`friend operator<<(std::ostream&, const basic_json&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_a5e34c5435e557d0bf666bd7311211405.html#a5e34c5435e557d0bf666bd7311211405) instead.


## v3.2.0

!!! summary "Files"

    - [include.zip](https://github.com/nlohmann/json/releases/download/v3.2.0/include.zip) (124 KB)
    - [include.zip.asc](https://github.com/nlohmann/json/releases/download/v3.2.0/include.zip.asc) (1 KB)
    - [json.hpp](https://github.com/nlohmann/json/releases/download/v3.2.0/json.hpp) (636 KB)
    - [json.hpp.asc](https://github.com/nlohmann/json/releases/download/v3.2.0/json.hpp.asc) (1 KB)

Release date: 2018-08-20
SHA-256: ce6b5610a051ec6795fa11c33854abebb086f0fd67c311f5921c3c07f9531b44 (json.hpp), 35ee642558b90e2f9bc758995c4788c4b4d4dec54eef95fb8f38cb4d49c8fc7c (include.zip)

### Summary

This release introduces a [**SAX interface**](https://nlohmann.github.io/json/structnlohmann_1_1json__sax.html) to the library. While this may be a very special feature used by only few people, it allowed to unify all functions that consumed input and created some kind of JSON value. Internally, now all existing functions like `parse`, `accept`, `from_cbor`, `from_msgpack`, and `from_ubjson` use the SAX interface with different event processors. This allowed to separate the input processing from the value generation. Furthermore, throwing an exception in case of a parse error is now optional and up to the event processor. Finally, the JSON parser is now non-recursive (meaning it does not use the call stack, but `std::vector<bool>` to track the hierarchy of structured values) which allows to process nested input more efficiently.

Furthermore, the library finally is able to parse from **wide string types**. This is the first step toward opening the library from UTF-8 to UTF-16 and UTF-32.

This release further fixes several bugs in the library. All changes are backward-compatible.

### :sparkles: New Features

- added a parser with a **SAX interface** (#971, #1153)
- support to parse from **wide string types** `std::wstring`, `std::u16string`, and `std::u32string`; the input will be converted to UTF-8 (#1031)
- added support for **`std::string_view`** when using C++17 (#1028)
- allow to **roundtrip `std::map` and `std::unordered_map`** from JSON if key type is not convertible to string; in these cases, values are serialized to arrays of pairs (#1079, #1089, #1133, #1138)

### :bug: Bug Fixes

- allow to create `nullptr_t` from JSON allowing to properly roundtrip `null` values (#1169)
- allow compare user-defined string types (#1130)
- better support for algorithms using iterators from `items()` (#1045, #1134)
- added parameter to avoid compilation error with MSVC 2015 debug builds (#1114)
- re-added accidentially skipped unit tests (#1176)
- fixed MSVC issue with `std::swap` (#1168)

### :zap: Improvements

- `key()` function for iterators returns a const reference rather than a string copy (#1098)
- binary formats CBOR, MessagePack, and UBJSON now supports `float` as type for floating-point numbers (#1021)

### :hammer: Further Changes

- changed issue templates
- improved continuous integration: added builders for Xcode 9.3 and 9.4, added builders for GCC 8 and Clang 6, added builder for MinGW, added builders for MSVC targeting x86
- required CMake version is now at least 3.8 (#1040)
- overworked CMake file wrt. packaging (#1048)
- added package managers: Spack (#1041) and CocoaPods (#1148)
- fixed Meson include directory (#1142)
- preprocessor macro `JSON_SKIP_UNSUPPORTED_COMPILER_CHECK` can skip the rejection of unsupported compilers - use at your own risk! (#1128)
- preprocessor macro `JSON_INTERNAL_CATCH`/`JSON_INTERNAL_CATCH_USER` allows to control the behavior of exception handling inside the library (#1187)
- added note on `char` to JSON conversion
- added note how to send security-related issue via encrypted email
- removed dependency to `std::stringstream` (#1117)
- added SPDX-License-Identifier
- added updated JSON Parsing Test Suite, described in [Parsing JSON is a Minefield 💣](http://seriot.ch/parsing_json.php)
- updated to Catch 1.12.0

### :fire: Deprecated functions

This release does not deprecate any functions. As an overview, the following functions have been deprecated in earlier versions and will be removed in the next major version (i.e., 4.0.0):

- Function [`iterator_wrapper`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_af1592a06bc63811886ade4f9d965045e.html#af1592a06bc63811886ade4f9d965045e) are deprecated. Please use the member function [`items()`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_afe3e137ace692efa08590d8df40f58dd.html#afe3e137ace692efa08590d8df40f58dd) instead.
- Functions [`friend std::istream& operator<<(basic_json&, std::istream&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_ab7285a92514fcdbe6de505ebaba92ea3.html#ab7285a92514fcdbe6de505ebaba92ea3) and [`friend std::ostream& operator>>(const basic_json&, std::ostream&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_a9e06deabe69262c3ffc5533d32856983.html#a9e06deabe69262c3ffc5533d32856983) are deprecated. Please use [`friend std::istream&  operator>>(std::istream&, basic_json&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_aaf363408931d76472ded14017e59c9e8.html#aaf363408931d76472ded14017e59c9e8) and [`friend operator<<(std::ostream&, const basic_json&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_a5e34c5435e557d0bf666bd7311211405.html#a5e34c5435e557d0bf666bd7311211405) instead.



## v3.1.2

!!! summary "Files"

    - [include.zip](https://github.com/nlohmann/json/releases/download/v3.1.2/include.zip) (115 KB)
    - [include.zip.asc](https://github.com/nlohmann/json/releases/download/v3.1.2/include.zip.asc) (1 KB)
    - [json.hpp](https://github.com/nlohmann/json/releases/download/v3.1.2/json.hpp) (582 KB)
    - [json.hpp.asc](https://github.com/nlohmann/json/releases/download/v3.1.2/json.hpp.asc) (1 KB)

Release date: 2018-03-14
SHA-256: fbdfec4b4cf63b3b565d09f87e6c3c183bdd45c5be1864d3fcb338f6f02c1733 (json.hpp), 495362ee1b9d03d9526ba9ccf1b4a9c37691abe3a642ddbced13e5778c16660c (include.zip)

### Summary

This release fixes several bugs in the library. All changes are backward-compatible.

### :bug: Bug Fixes

- Fixed a **memory leak** occurring in the parser callback (#1001).
- Different **specializations of `basic_json`** (e.g., using different template arguments for strings or objects) can now be used in assignments (#972, #977, #986).
- Fixed a logical error in an iterator range check (#992).

### :zap: Improvements

- The parser and the serialization now support **user-defined string types** (#1006, #1009).

### :hammer: Further Changes

- **[Clang Analyzer](http://clang-analyzer.llvm.org)** is now used as additional static analyzer; see `make clang_analyze`.
- Overworked [README](https://github.com/nlohmann/json/blob/develop/README.md) by adding links to the [documentation](https://nlohmann.github.io/json/) (#981).

### :fire: Deprecated functions

This release does not deprecate any functions. As an overview, the following functions have been deprecated in earlier versions and will be removed in the next major version (i.e., 4.0.0):

- Function [`iterator_wrapper`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_af1592a06bc63811886ade4f9d965045e.html#af1592a06bc63811886ade4f9d965045e) are deprecated. Please use the member function [`items()`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_afe3e137ace692efa08590d8df40f58dd.html#afe3e137ace692efa08590d8df40f58dd) instead.
- Functions [`friend std::istream& operator<<(basic_json&, std::istream&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_ab7285a92514fcdbe6de505ebaba92ea3.html#ab7285a92514fcdbe6de505ebaba92ea3) and [`friend std::ostream& operator>>(const basic_json&, std::ostream&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_a9e06deabe69262c3ffc5533d32856983.html#a9e06deabe69262c3ffc5533d32856983) are deprecated. Please use [`friend std::istream&  operator>>(std::istream&, basic_json&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_aaf363408931d76472ded14017e59c9e8.html#aaf363408931d76472ded14017e59c9e8) and [`friend operator<<(std::ostream&, const basic_json&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_a5e34c5435e557d0bf666bd7311211405.html#a5e34c5435e557d0bf666bd7311211405) instead.


## v3.1.1

!!! summary "Files"

    - [include.zip](https://github.com/nlohmann/json/releases/download/v3.1.1/include.zip) (114 KB)
    - [include.zip.asc](https://github.com/nlohmann/json/releases/download/v3.1.1/include.zip.asc) (1 KB)
    - [json.hpp](https://github.com/nlohmann/json/releases/download/v3.1.1/json.hpp) (577 KB)
    - [json.hpp.asc](https://github.com/nlohmann/json/releases/download/v3.1.1/json.hpp.asc) (1 KB)

Release date: 2018-02-13
SHA-256: e14ce5e33d6a2daf748026bd4947f3d9686ca4cfd53d10c3da46a0a9aceb7f2e (json.hpp), fde771d4b9e4f222965c00758a2bdd627d04fb7b59e09b7f3d1965abdc848505 (include.zip)

### Summary

This release fixes several bugs in the library. All changes are backward-compatible.

### :bug: Bug Fixes

- Fixed parsing of **CBOR strings with indefinite length** (#961). Earlier versions of this library misinterpreted the CBOR standard and rejected input with the `0x7F` start byte.
- Fixed user-defined **conversion to vector type** (#924, #969). A wrong SFINAE check rejected code though a user-defined conversion was provided.
- Fixed documentation of the parser behavior for **objects with duplicate keys** (#963). The exact behavior is not specified by [RFC 8259](https://tools.ietf.org/html/rfc8259) and the library now also provides no guarantee which object key is stored.
- Added check to detect memory **overflow when parsing UBJSON containers** (#962). The optimized UBJSON format allowed for specifying an array with billions of `null` elements with a few bytes and the library did not check whether this size exceeded `max_size()`.

### :hammer: Further Changes

- [Code coverage](https://coveralls.io/github/nlohmann/json) is now calculated for the individual header files, allowing to find uncovered lines more quickly than by browsing through the single header version (#953, #957).
- A Makefile target `run_benchmarks` was added to quickly build and run the benchmark suite.
- The documentation was harmonized with respect to the header inclusion (#955). Now all examples and the README use `#include <nlohmann/json.hpp>` to allow for selecting `single_include` or `include` or whatever installation folder as include directory.
- Added note on how to use the library with the [cget](http://cget.readthedocs.io/en/latest/) package manager (#954).

### :fire: Deprecated functions

This release does not deprecate any functions. As an overview, the following functions have been deprecated in earlier versions and will be removed in the next major version (i.e., 4.0.0):

- Function [`iterator_wrapper`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_af1592a06bc63811886ade4f9d965045e.html#af1592a06bc63811886ade4f9d965045e) are deprecated. Please use the member function [`items()`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_afe3e137ace692efa08590d8df40f58dd.html#afe3e137ace692efa08590d8df40f58dd) instead.
- Functions [`friend std::istream& operator<<(basic_json&, std::istream&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_ab7285a92514fcdbe6de505ebaba92ea3.html#ab7285a92514fcdbe6de505ebaba92ea3) and [`friend std::ostream& operator>>(const basic_json&, std::ostream&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_a9e06deabe69262c3ffc5533d32856983.html#a9e06deabe69262c3ffc5533d32856983) are deprecated. Please use [`friend std::istream&  operator>>(std::istream&, basic_json&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_aaf363408931d76472ded14017e59c9e8.html#aaf363408931d76472ded14017e59c9e8) and [`friend operator<<(std::ostream&, const basic_json&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_a5e34c5435e557d0bf666bd7311211405.html#a5e34c5435e557d0bf666bd7311211405) instead.

## v3.1.0

!!! summary "Files"

    - [include.zip](https://github.com/nlohmann/json/releases/download/v3.1.0/include.zip) (114 KB)
    - [include.zip.asc](https://github.com/nlohmann/json/releases/download/v3.1.0/include.zip.asc) (1 KB)
    - [json.hpp](https://github.com/nlohmann/json/releases/download/v3.1.0/json.hpp) (577 KB)
    - [json.hpp.asc](https://github.com/nlohmann/json/releases/download/v3.1.0/json.hpp.asc) (1 KB)

Release date: 2018-02-01
SHA-256: d40f614d10a6e4e4e80dca9463da905285f20e93116c36d97d4dc1aa63d10ba4 (json.hpp), 2b7234fca394d1e27b7e017117ed80b7518fafbb4f4c13a7c069624f6f924673 (include.zip)

### Summary

This release adds support for the [**UBJSON**](http://ubjson.org) format and [**JSON Merge Patch**](https://tools.ietf.org/html/rfc7386). It also contains some minor changes and bug fixes. All changes are backward-compatible.

### :sparkles: New features

- The library now supports [**UBJSON**](http://ubjson.org) (Universal Binary JSON Specification) as binary format to read and write JSON values space-efficiently. See the [documentation overview](https://github.com/nlohmann/json/blob/develop/doc/binary_formats.md) for a comparison of the different formats CBOR, MessagePack, and UBJSON.
- [**JSON Merge Patch**](https://tools.ietf.org/html/rfc7386) (RFC 7386) offers an intuitive means to describe patches between JSON values (#876, #877). See the documentation of [`merge_patch`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_a0ec0cd19cce42ae6071f3cc6870ea295.html#a0ec0cd19cce42ae6071f3cc6870ea295) for more information.

### :zap: Improvements

- The library now uses the **Grisu2 algorithm** for printing floating-point numbers (based on the reference implementation by Florian Loitsch) which produces a short representation which is guaranteed to round-trip (#360, #935, #936).
- The **UTF-8 handling** was further simplified by using the decoder of Björn Hoehrmann in more scenarios.

### :truck: Reorganization

- Though the library is released as a single header, its development got more and more complicated. With this release, the header is **split into several files** and the single-header file `json.hpp` can be generated from these development sources. In the repository, folder `include` contains the development sources and `single_include` contains the single `json.hpp` header (#700, #906, #907, #910, #911, #915, #920, #924, #925, #928, #944).
- The split further allowed for a **forward declaration header** `include/nlohmann/json_fwd.hpp` to speed up compilation times (#314).

### :hammer: Further changes

- [Google Benchmark](https://github.com/google/benchmark) is now used for micro benchmarks (see `benchmarks` folder, #921).
- The serialization (JSON and binary formats) now properly work with the libraries string template parameter, allowing for optimized string implementations to be used in constraint environments such as embedded software (#941, #950).
- The exceptional behavior can now be overridden by defining macros `JSON_THROW_USER`, `JSON_TRY_USER`, and `JSON_CATCH_USER`, defining the behavior of `throw`, `try` and `catch`, respectively. This allows to switch off C++'s exception mechanism yet still execute user-defined code in case an error condition occurs (#938).
- To facilitate the interplay with [flex](https://github.com/westes/flex) and [Bison](https://www.gnu.org/software/bison/), the library does not use the variable name `yytext` any more as it could clash with macro definitions (#933).
- The library now defines `NLOHMANN_JSON_VERSION_MAJOR`, `NLOHMANN_JSON_VERSION_MINOR`, and `NLOHMANN_JSON_VERSION_PATCH` to allow for conditional compilation based on the included library version (#943, #948).
- A compilation error with ICC has been fixed (#947).
- Typos and links in the documentation have been fixed (#900, #930).
- A compiler error related to incomplete types has been fixed (#919).
- The tests form the [UTF-8 decoder stress test](http://www.cl.cam.ac.uk/~mgk25/ucs/examples/UTF-8-test.txt) have been added to the test suite.

### :fire: Deprecated functions

- Function [`iterator_wrapper`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_af1592a06bc63811886ade4f9d965045e.html#af1592a06bc63811886ade4f9d965045e) has been deprecated (#874). Since its introduction, the name was up for discussion, as it was too technical. We now introduced the member function [`items()`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_afe3e137ace692efa08590d8df40f58dd.html#afe3e137ace692efa08590d8df40f58dd) with the same semantics. `iterator_wrapper` will be removed in the next major version (i.e., 4.0.0).

Furthermore, the following functions are deprecated since version 3.0.0 and will be removed in the next major version (i.e., 4.0.0):

- [`friend std::istream& operator<<(basic_json&, std::istream&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_ab7285a92514fcdbe6de505ebaba92ea3.html#ab7285a92514fcdbe6de505ebaba92ea3)
- [`friend std::ostream& operator>>(const basic_json&, std::ostream&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_a9e06deabe69262c3ffc5533d32856983.html#a9e06deabe69262c3ffc5533d32856983)

Please use [`friend std::istream&  operator>>(std::istream&, basic_json&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_aaf363408931d76472ded14017e59c9e8.html#aaf363408931d76472ded14017e59c9e8) and [`friend operator<<(std::ostream&, const basic_json&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_a5e34c5435e557d0bf666bd7311211405.html#a5e34c5435e557d0bf666bd7311211405) instead.

## v3.0.1

!!! summary "Files"

    - [json.hpp](https://github.com/nlohmann/json/releases/download/v3.0.1/json.hpp) (502 KB)
    - [json.hpp.asc](https://github.com/nlohmann/json/releases/download/v3.0.1/json.hpp.asc) (1 KB)

Release date: 2017-12-29
SHA-256: c9b3591f1bb94e723a0cd7be861733a3a555b234ef132be1e9027a0364118c4c

### Summary

This release fixes small issues in the implementation of **JSON Pointer** and **JSON Patch**. All changes are backward-compatible.

### Changes

- :bug: The **"copy" operation of JSON Patch** ([RFC 6902](https://tools.ietf.org/html/rfc6902)) requests that it is an error if the target path points into a non-existing array or object (see #894 for a detailed description). This release fixes the implementation to detect such invalid target paths and throw an exception.
- :bug: An **array index in a JSON Pointer** ([RFC 6901](https://tools.ietf.org/html/rfc6901)) must be an integer. This release fixes the implementation to throw an exception in case invalid array indices such as `10e2` are used.
- :white_check_mark: Added the [JSON Patch tests](https://github.com/json-patch/json-patch-tests) from Byron Ruth and Mike McCabe.
- :memo: Fixed the documentation of the [`at(ptr)` function with JSON Pointers](https://nlohmann.github.io/json/classnlohmann_1_1basic__json_a8ab61397c10f18b305520da7073b2b45.html#a8ab61397c10f18b305520da7073b2b45) to list all possible exceptions (see #888).
- :memo: Updated the [container overview documentation](https://nlohmann.github.io/json/) (see #883).
- :wrench: The CMake files now respect the [`BUILD_TESTING`](https://cmake.org/cmake/help/latest/module/CTest.html?highlight=build_testing) option (see #846, #885)
- :rotating_light: Fixed some compiler warnings (see #858, #882).

### Deprecated functions

:fire: To unify the interfaces and to improve similarity with the STL, the following functions are deprecated since version 3.0.0 and will be removed in the next major version (i.e., 4.0.0):

- [`friend std::istream& operator<<(basic_json&, std::istream&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_ab7285a92514fcdbe6de505ebaba92ea3.html#ab7285a92514fcdbe6de505ebaba92ea3)
- [`friend std::ostream& operator>>(const basic_json&, std::ostream&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_a9e06deabe69262c3ffc5533d32856983.html#a9e06deabe69262c3ffc5533d32856983)

Please use [`friend std::istream&  operator>>(std::istream&, basic_json&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_aaf363408931d76472ded14017e59c9e8.html#aaf363408931d76472ded14017e59c9e8) and [`friend operator<<(std::ostream&, const basic_json&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_a5e34c5435e557d0bf666bd7311211405.html#a5e34c5435e557d0bf666bd7311211405) instead.

## v3.0.0

!!! summary "Files"

    - [json.hpp](https://github.com/nlohmann/json/releases/download/v3.0.0/json.hpp) (501 KB)
    - [json.hpp.asc](https://github.com/nlohmann/json/releases/download/v3.0.0/json.hpp.asc) (1 KB)

Release date: 2017-12-17
SHA-256: 076d4a0cb890a3c3d389c68421a11c3d77c64bd788e85d50f1b77ed252f2a462

### Summary

<img src="https://user-images.githubusercontent.com/159488/34072418-8f5ba396-e287-11e7-9de7-8bc7482ac23c.png" align="right">

After almost a year, here is finally a new release of JSON for Modern C++, and it is a major one! As we adhere to [semantic versioning](https://semver.org), this means the release includes some breaking changes, so please read the next section carefully before you update. But don't worry, we also added a few new features and put a lot of effort into fixing a lot of bugs and straighten out a few inconsistencies.

### :boom: Breaking changes

This section describes changes that change the public API of the library and may require changes in code using a previous version of the library. In section "Moving from 2.x.x to 3.0.0" at the end of the release notes, we describe in detail how existing code needs to be changed.

- The library now uses [**user-defined exceptions**](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_a9a0aced019cb1d65bb49703406c84970.html#a9a0aced019cb1d65bb49703406c84970) instead of re-using those defined in `<stdexcept>` (#244). This not only allows to add more information to the exceptions (every exception now has an identifier, and parse errors contain the position of the error), but also to easily catch all library exceptions with a single `catch(json::exception)`.
- When strings with a different encoding as UTF-8 were stored in JSON values, their serialization could not be parsed by the library itself, as only UTF-8 is supported. To enforce this library limitation and improve consistency, **non-UTF-8 encoded strings now yield a `json::type_error` exception during serialization** (#838). The check for valid UTF-8 is realized with code from [Björn Hoehrmann](http://bjoern.hoehrmann.de/).
- **NaN and infinity values can now be stored inside the JSON value** without throwing an exception. They are, however, still serialized as `null` (#388).
- The library's iterator tag was changed from RandomAccessIterator to **[BidirectionalIterator](http://en.cppreference.com/w/cpp/concept/BidirectionalIterator)** (#593). Supporting RandomAccessIterator was incorrect as it assumed an ordering of values in a JSON objects which are unordered by definition.
- The library does not include the standard headers `<iostream>`, `<ctype>`, and `<stdexcept>` any more. You may need to add these headers to code relying on them.
- Removed constructor `explicit basic_json(std::istream& i, const parser_callback_t cb = nullptr)` which was deprecated in version 2.0.0 (#480).

### :fire: Deprecated functions

To unify the interfaces and to improve similarity with the STL, the following functions are now deprecated and will be removed in the next major version (i.e., 4.0.0):

- [`friend std::istream& operator<<(basic_json&, std::istream&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_ab7285a92514fcdbe6de505ebaba92ea3.html#ab7285a92514fcdbe6de505ebaba92ea3)
- [`friend std::ostream& operator>>(const basic_json&, std::ostream&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_a9e06deabe69262c3ffc5533d32856983.html#a9e06deabe69262c3ffc5533d32856983)

Please use [`friend std::istream&  operator>>(std::istream&, basic_json&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_aaf363408931d76472ded14017e59c9e8.html#aaf363408931d76472ded14017e59c9e8) and [`friend operator<<(std::ostream&, const basic_json&)`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_a5e34c5435e557d0bf666bd7311211405.html#a5e34c5435e557d0bf666bd7311211405) instead.

### :sparkles: New features

With all this breaking and deprecation out of the way, let's talk about features!

- We improved the **diagnostic information for syntax errors** (#301). Now, an exception [`json::parse_error`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_af1efc2468e6022be6e35fc2944cabe4d.html#af1efc2468e6022be6e35fc2944cabe4d) is thrown which contains a detailed message on the error, but also a member `byte` to indicate the byte offset in the input where the error occurred.
- We added a **non-throwing syntax check** (#458): The new `accept` function returns a Boolean indicating whether the input is proper JSON. We also added a Boolean parameter `allow_exceptions` to the existing [`parse`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_aa9676414f2e36383c4b181fe856aa3c0.html#aa9676414f2e36383c4b181fe856aa3c0) functions to return a `discarded` value in case a syntax error occurs instead of throwing an exception.
- An [`update`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_a1cfa9ae5e7c2434cab4cfe69bffffe11.html#a1cfa9ae5e7c2434cab4cfe69bffffe11) function was added to **merge two JSON objects** (#428). In case you are wondering: the name was inspired by [Python](https://docs.python.org/2/library/stdtypes.html#dict.update).
- The [`insert`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_a1b0a4e60d56f1fe80501ed941e122892.html#a1b0a4e60d56f1fe80501ed941e122892) function now also supports an iterator range to add elements to an object.
- The binary exchange formats **CBOR and MessagePack can now be parsed from input streams and written to output streams** (#477).
- Input streams are now only read until the end of a JSON value instead of the end of the input (#367).
- The serialization function [`dump`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_a5adea76fedba9898d404fef8598aa663.html#a5adea76fedba9898d404fef8598aa663) now has two optional parameters `ensure_ascii` to **escape all non-ASCII characters** with `\uxxxx` and an `indent_char` parameter to choose whether to **indent with spaces or tabs** (#654). 
- Added **built-in type support** for C arrays (#502), `std::pair` and `std::tuple` (#563, #614), `enum` and `enum class` (#545), `std::vector<bool>` (#494). Fixed support for `std::valarray` (#702), `std::array` (#553), and `std::map<std::string, std::string>` (#600, #607).

### :hammer: Further changes

Furthermore, there have been a lot of changes under the hood:

- Replaced the [re2c](http://re2c.org) generated scanner by a self-coded version which allows for a better modularization of the parser and better diagnostics. To test the new scanner, we added millions (8,860,608 to be exact) of unit tests to check all valid and invalid byte sequences of the Unicode standard.
- Google's OSS-Fuzz is still constantly fuzz-testing the library and found several issues that were fixed in this release (#497, #504, #514, #516, #518, #519, #575).
- We now also ignore UTF-8 byte order marks when parsing from an iterator range (#602).
- Values can be now moved from initializer lists (#663).
- Updated to [Catch](https://github.com/catchorg/Catch2) 1.9.7. Unfortunately, Catch2 currently has some performance issues.
- The non-exceptional paths of the library are now annotated with `__builtin_expect` to optimize branch prediction as long as no error occurs.
- MSVC now produces a stack trace in MSVC if a `from_json` or `to_json` function was not found for a user-defined type. We also added a debug visualizer [`nlohmann_json.natvis`](https://github.com/nlohmann/json/blob/develop/nlohmann_json.natvis) for better debugging in MSVC (#844).
- Overworked the documentation and added even more examples.
- The build workflow now relies on CMake and CTest. Special flags can be chosen with CMake, including coverage (`JSON_Coverage`), compilation without exceptions (`JSON_NoExceptions`), LLVM sanitizers (`JSON_Sanitizer`), or execution with Valgrind (`JSON_Valgrind`).
- Added support for package managers Meson (#576), Conan (#566), Hunter (#671, #829), and vcpkg (#753).
- Added CI builders: Xcode 8.3, 9.0, 9.1, and 9.2; GCC 7.2; Clang 3.8, 3.9, 4.0, and 5.0; Visual Studio 2017. The library is further built with C++17 settings on the latest Clang, GCC, and MSVC version to quickly detect new issues.

### Moving from 2.x.x to 3.0.0

#### User-defined Exceptions

There are five different exceptions inheriting from [`json::exception`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_a9a0aced019cb1d65bb49703406c84970.html#a9a0aced019cb1d65bb49703406c84970):

- [`json::parse_error`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_af1efc2468e6022be6e35fc2944cabe4d.html#af1efc2468e6022be6e35fc2944cabe4d) for syntax errors (including the binary formats),
- [`json::invalid_iterator`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_ac13d32f7cbd02d616e71d8dc30dadcbf.html#ac13d32f7cbd02d616e71d8dc30dadcbf) for errors related to iterators,
- [`json::type_error`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_a4010e8e268fefd86da773c10318f2902.html#a4010e8e268fefd86da773c10318f2902) for errors where functions were called with the wrong JSON type,
- [`json::out_of_range`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_a28f7c2f087274a0012eb7a2333ee1580.html#a28f7c2f087274a0012eb7a2333ee1580) for range errors, and
- [`json::other_error`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_a3333a5a8714912adda33a35b369f7b3d.html#a3333a5a8714912adda33a35b369f7b3d) for miscellaneous errors.

To support these exception, the `try`/`catch` blocks of your code need to be adjusted:

| new exception | previous exception |
|:--|:--|
| parse_error.101 | invalid_argument |
| parse_error.102 | invalid_argument |
| parse_error.103 | invalid_argument |
| parse_error.104 | invalid_argument |
| parse_error.105 | invalid_argument |
| parse_error.106 | domain_error |
| parse_error.107 | domain_error |
| parse_error.108 | domain_error |
| parse_error.109 | invalid_argument |
| parse_error.110 | out_of_range |
| parse_error.111 | invalid_argument |
| parse_error.112 | invalid_argument |
| invalid_iterator.201 | domain_error |
| invalid_iterator.202 | domain_error |
| invalid_iterator.203 | domain_error |
| invalid_iterator.204 | out_of_range |
| invalid_iterator.205 | out_of_range |
| invalid_iterator.206 | domain_error |
| invalid_iterator.207 | domain_error |
| invalid_iterator.208 | domain_error |
| invalid_iterator.209 | domain_error |
| invalid_iterator.210 | domain_error |
| invalid_iterator.211 | domain_error |
| invalid_iterator.212 | domain_error |
| invalid_iterator.213 | domain_error |
| invalid_iterator.214 | out_of_range |
| type_error.301 | domain_error |
| type_error.302 | domain_error |
| type_error.303 | domain_error |
| type_error.304 | domain_error |
| type_error.305 | domain_error |
| type_error.306 | domain_error |
| type_error.307 | domain_error |
| type_error.308 | domain_error |
| type_error.309 | domain_error |
| type_error.310 | domain_error |
| type_error.311 | domain_error |
| type_error.313 | domain_error |
| type_error.314 | domain_error |
| type_error.315 | domain_error |
| out_of_range.401 | out_of_range |
| out_of_range.402 | out_of_range |
| out_of_range.403 | out_of_range |
| out_of_range.404 | out_of_range |
| out_of_range.405 | domain_error |
| other_error.501 | domain_error |

#### Handling of NaN and INF

- If an overflow occurs during parsing a number from a JSON text, an exception [`json::out_of_range`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_a28f7c2f087274a0012eb7a2333ee1580.html#a28f7c2f087274a0012eb7a2333ee1580) is thrown so that the overflow is detected early and roundtripping is guaranteed.

- NaN and INF floating-point values can be stored in a JSON value and are not replaced by null. That is, the basic_json class behaves like `double` in this regard (no exception occurs). However, NaN and INF are serialized to `null`.

#### Removal of deprecated functions

Function `explicit basic_json(std::istream& i, const parser_callback_t cb = nullptr)` should be replaced by the `parse` function: Let `ss` be a stream and `cb` be a parse callback function.

Old code:

```cpp
json j(ss, cb);
```

New code:

```cpp
json j = json::parse(ss, cb);
```

If no callback function is used, also the following code works:

```cpp
json j;
j << ss;
```

or

```cpp
json j;
ss >> j;
```

## v2.1.1

!!! summary "Files"

    - [json.hpp](https://github.com/nlohmann/json/releases/download/v2.1.1/json.hpp) (437 KB)
    - [json.hpp.asc](https://github.com/nlohmann/json/releases/download/v2.1.1/json.hpp.asc) (1 KB)

Release date: 2017-02-25
SHA-256: faa2321beb1aa7416d035e7417fcfa59692ac3d8c202728f9bcc302e2d558f57

### Summary

This release **fixes a locale-related bug in the parser**. To do so, the whole number handling (lexer, parser, and also the serialization) have been overworked. Furthermore, a lot of small changes added up that were added to this release. All changes are backward-compatible.

### Changes
- :bug: Locales that have a different character than `.` as decimal separator (e.g., the Norwegian locale `nb_NO.UTF-8`) led to truncated number parsing or parse errors. The library now has been fixed to work with **any locale**. Note that `.` is still the only valid decimal separator for JSON input.
- :bug: Numbers like `1.0` were correctly parsed as floating-point number, but serialized as integer (`1`). Now, **floating-point numbers correctly round trip**.
- :bug: Parsing incorrect JSON numbers with leading 0 (`0123`) could yield a [buffer overflow](https://github.com/nlohmann/json/issues/452). This is fixed now by detecting such errors directly by the lexer.
- :bug: Constructing a JSON value from a pointer was incorrectly interpreted as a Boolean; such code will now yield a compiler error.
- :bug: Comparing a JSON number with `0` led to a comparison with `null`. This is fixed now.
- :bug: All throw calls are now wrapped in macros.
- :lock: Starting during the preparation of this release (since 8 February 2017), commits and released files are **cryptographically signed** with [this GPG key](https://keybase.io/nlohmann/pgp_keys.asc?fingerprint=797167ae41c0a6d9232e48457f3cea63ae251b69). Previous releases have also been signed.
- :sparkles: The parser for MessagePack and CBOR now supports an optional start index parameter to define a byte offset for the parser.
- :rotating_light: Some more warnings have been fixed. With Clang, the code compiles **without warnings** with `-Weverything` (well, it needs `-Wno-documentation-unknown-command` and `-Wno-deprecated-declarations`, but you get the point).
- :hammer: The code can be compiled easier with many Android NDKs by avoiding macros like `UINT8_MAX` which previously required defining a preprocessor macro for compilation.
- :zap: The unit tests now compile two times faster.
- :heavy_plus_sign: [Cotire](https://github.com/sakra/cotire) is used to speed up the build.
- :pencil2: Fixed a lot of typos in the documentation.
- :memo: Added a section to the README file that lists all used [third-party code/tools](https://github.com/nlohmann/json#used-third-party-tools).
- :memo: Added a note on constructing a string value vs. parsing.
- :white_check_mark: The test suite now contains 11202597 unit tests.
- :memo: Improved the [Doxygen documentation](https://nlohmann.github.io/json/) by shortening the template parameters of class `basic_json`.
- :construction_worker: Removed Doozer.
- :construction_worker: Added Codacity.
- :arrow_up: Upgraded Catch to version 1.7.2.


## v2.1.0

!!! summary "Files"

    - [json.hpp](https://github.com/nlohmann/json/releases/download/v2.1.0/json.hpp) (426 KB)
    - [json.hpp.asc](https://github.com/nlohmann/json/releases/download/v2.1.0/json.hpp.asc) (1 KB)

- Release date: 2017-01-28
- SHA-256: a571dee92515b685784fd527e38405cf3f5e13e96edbfe3f03d6df2e363a767b

### Summary

This release introduces a means to convert from/to user-defined types. The release is backwards compatible.

![conversion](https://cloud.githubusercontent.com/assets/159488/22399173/aebe8f7a-e597-11e6-930f-7494ee615827.png)

### Changes
- :sparkles: The library now offers an elegant way to **convert from and to arbitrary value types**. All you need to do is to implement two functions: `to_json` and `from_json`. Then, a conversion is as simple as putting a `=` between variables. See the [README](https://github.com/nlohmann/json#arbitrary-types-conversions) for more information and examples.
- :sparkles: **Exceptions can now be switched off.** This can be done by defining the preprocessor symbol `JSON_NOEXCEPTION` or by passing `-fno-exceptions` to your compiler. In case the code would usually thrown an exception, `abort()` is now called.
- :sparkles: **Information on the library** can be queried with the new (static) function `meta()` which returns a JSON object with information on the version, compiler, and platform. See the [documentation]() for an example.
- :bug: A bug in the CBOR parser was fixed which led to a buffer overflow.
- :sparkles: The function [`type_name()`]() is now public. It allows to query the type of a JSON value as string.
- :white_check_mark: Added the [Big List of Naughty Strings](https://github.com/minimaxir/big-list-of-naughty-strings) as test case.
- :arrow_up: Updated to [Catch v1.6.0](https://github.com/philsquared/Catch/releases/tag/v1.6.0).
- :memo: Some typos in the documentation have been fixed.


## v2.0.10

!!! summary "Files"

    - [json.hpp](https://github.com/nlohmann/json/releases/download/v2.0.10/json.hpp) (409 KB)
    - [json.hpp.asc](https://github.com/nlohmann/json/releases/download/v2.0.10/json.hpp.asc) (1 KB)

- Release date: 2017-01-02
- SHA-256: ec27d4e74e9ce0f78066389a70724afd07f10761009322dc020656704ad5296d

### Summary

This release fixes several security-relevant bugs in the MessagePack and CBOR parsers. The fixes are backwards compatible.

### Changes
- :bug: Fixed a lot of **bugs in the CBOR and MesssagePack parsers**. These bugs occurred if invalid input was parsed and then could lead in buffer overflows. These bugs were found with Google's [OSS-Fuzz](https://github.com/google/oss-fuzz), see #405, #407, #408, #409, #411, and #412 for more information.
- :construction_worker: We now also use the **[Doozer](https://doozer.io) continuous integration platform**.
- :construction_worker: The complete test suite is now also run with **Clang's address sanitizer and undefined-behavior sanitizer**.
- :white_check_mark: Overworked **fuzz testing**; CBOR and MessagePack implementations are now fuzz-tested. Furthermore, all fuzz tests now include a round trip which ensures created output can again be properly parsed and yields the same JSON value.
- :memo: Clarified documentation of `find()` function to always return `end()` when called on non-object value types.
- :hammer: Moved thirdparty test code to `test/thirdparty` directory.

## v2.0.9

!!! summary "Files"

    - [json.hpp](https://github.com/nlohmann/json/releases/download/v2.0.9/json.hpp) (406 KB)
    - [json.hpp.asc](https://github.com/nlohmann/json/releases/download/v2.0.9/json.hpp.asc) (1 KB)

- Release date: 2016-12-16
- SHA-256: fbf3396f13e187d6c214c297bddc742d918ea9b55e10bfb3d9f458b9bfdc22e5

### Summary

This release implements with **[CBOR](http://cbor.io)** and **[MessagePack](http://msgpack.org)** two **binary serialization/deserialization formats**. It further contains some small fixes and improvements. The fixes are backwards compatible.

![cbor](https://cloud.githubusercontent.com/assets/159488/22399181/d4d60d32-e597-11e6-8dcb-825abcf9ac2a.png)

### Changes
- :sparkles: The library can now read and write the binary formats **[CBOR](http://cbor.io)** (Concise Binary Object Representation) and **[MessagePack](http://msgpack.org)**. Both formats are aimed to produce a very compact representation of JSON which can be parsed very efficiently. See the  [README file](https://github.com/nlohmann/json#binary-formats-cbor-and-messagepack) for more information and examples.
- :fire: simplified the iteration implementation allowing to remove dozens of lines of code
- :bug: fixed an [integer overflow error](https://github.com/nlohmann/json/issues/389) detected by [Google's OSS-Fuzz](https://github.com/google/oss-fuzz)
- :bug: suppressed documentation warnings inside the library to facilitate compilation with `-Wdocumentation`
- :bug: fixed an overflow detection error in the number parser
- :memo: updated [contribution guidelines](https://github.com/nlohmann/json/blob/develop/.github/CONTRIBUTING.md) to a list of frequentely asked features that will most likely be never added to the library
- :memo:  added a **table of contents** to the [README file](https://github.com/nlohmann/json/blob/develop/README.md) to add some structure
- :memo: mentioned the many [examples](https://github.com/nlohmann/json/tree/develop/doc/examples) and the [documentation](https://nlohmann.github.io/json/) in the [README file]()
- :hammer: split [unit tests](https://github.com/nlohmann/json/tree/develop/test/src) into individual independent binaries to speed up compilation and testing
- :white_check_mark: the test suite now contains **11201886** tests

## v2.0.8

!!! summary "Files"

    - [json.hpp](https://github.com/nlohmann/json/releases/download/v2.0.8/json.hpp) (360 KB)
    - [json.hpp.asc](https://github.com/nlohmann/json/releases/download/v2.0.8/json.hpp.asc) (1 KB)

- Release date: 2016-12-02
- SHA-256: b70db0ad34f8e0e61dc3f0cbab88099336c9674c193d8a3439d93d6aca2d7120

### Summary

This release combines a lot of small fixes and improvements. The fixes are backwards compatible.

### Changes
- :bug: fixed a bug that froze the parser if a passed file was not found (now, `std::invalid_argument` is thrown)
- :bug: fixed a bug that lead to an error of a file at EOF was parsed again (now, `std::invalid_argument` is thrown)
- :sparkles: the well known functions [`emplace`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_a602f275f0359ab181221384989810604.html#a602f275f0359ab181221384989810604) and [`emplace_back`](http://nlohmann.github.io/json/doxygen/classnlohmann_1_1basic__json_af8a435033327d9237da414afc1cce513.html#af8a435033327d9237da414afc1cce513) have been added to JSON values and work as expected
- :zap: improved the performance of the serialization (`dump` function)
- :zap: improved the performance of the deserialization (parser)
- :construction_worker: some continuous integration images at [Travis](https://travis-ci.org/nlohmann/json) were added and retired; see [here](https://github.com/nlohmann/json#supported-compilers) for the current continuous integration setup
- :construction_worker: the [Coverity scan](https://scan.coverity.com/projects/nlohmann-json) works again
- :chart_with_upwards_trend: the benchmarking code has been improved to produce more stable results
- :memo: the [README](https://github.com/nlohmann/json/blob/develop/README.md) file has been extended and includes more frequently asked examples
- :white_check_mark: the test suite now contains 8905518 tests
- :arrow_up: updated [Catch](https://github.com/philsquared/Catch) to version 1.5.8

## v2.0.7

!!! summary "Files"

    - [json.hpp](https://github.com/nlohmann/json/releases/download/v2.0.7/json.hpp) (355 KB)
    - [json.hpp.asc](https://github.com/nlohmann/json/releases/download/v2.0.7/json.hpp.asc) (1 KB)

- Release date: 2016-11-02
- SHA-256: 5545c323670f8165bae90b9dc6078825e86ec310d96cc4e5b47233ea43715bbf

### Summary

This release fixes a few bugs in the JSON parser found in the [Parsing JSON is a Minefield 💣](http://seriot.ch/parsing_json.html) article. The fixes are backwards compatible.

### Changes
- The article [Parsing JSON is a Minefield 💣](http://seriot.ch/parsing_json.html) discusses a lot of pitfalls of the JSON specification. When investigating the published test cases, a few bugs in the library were found and fixed:
  - Files with less than 5 bytes can now be parsed without error.
  - The library now properly rejects any file encoding other than UTF-8. Furthermore, incorrect surrogate pairs are properly detected and rejected.
  - The library now accepts all but one "yes" test (y_string_utf16.json): UTF-16 is not supported.
  - The library rejects all but one "no" test (n_number_then_00.json): Null bytes are treated as end of file instead of an error. This allows to parse input from null-terminated strings.
- The string length passed to a user-defined string literal is now exploited to choose a more efficient constructor.
- A few grammar mistakes in the README file have been fixed.

## v2.0.6

!!! summary "Files"

    - [json.hpp](https://github.com/nlohmann/json/releases/download/v2.0.6/json.hpp) (349 KB)
    - [json.hpp.asc](https://github.com/nlohmann/json/releases/download/v2.0.6/json.hpp.asc) (1 KB)

- Release date: 2016-10-15
- SHA256: 459cc93d5e2f503e50c6d5876eb86bfea7daf405f5a567c5a2c9abc2383756ae

### Summary

This release fixes the semantics of `operator[]` for JSON Pointers (see below). This fix is backwards compatible.

### Changes
- **`operator[]` for JSON Pointers** now behaves like the other versions of `operator[]` and transforms `null` values into objects or arrays if required. This allows to created nested structues like `j["/foo/bar/2"] = 17` (yielding `{"foo": "bar": [null, null, 17]}`) without problems.
- overworked a helper SFINAE function
- fixed some documentation issues
- fixed the CMake files to allow to run the test suite outside the main project directory
- restored test coverage to 100%.

## v2.0.5

!!! summary "Files"

    - [json.hpp](https://github.com/nlohmann/json/releases/download/v2.0.5/json.hpp) (347 KB)
    - [json.hpp.asc](https://github.com/nlohmann/json/releases/download/v2.0.5/json.hpp.asc) (1 KB)

- Release date: 2016-09-14
- SHA-256: 8b7565263a44e2b7d3b89808bc73d2d639037ff0c1f379e3d56dbd77e00b98d9

### Summary

This release fixes a regression bug in the stream parser (function `parse()` and the `<<`/`>>` operators). This fix is backwards compatible.

### Changes
- **Bug fix**: The end of a file stream was not detected properly which led to parse errors. This bug should have been fixed with 2.0.4, but there was still a flaw in the code.

## v2.0.4

!!! summary "Files"

    - [json.hpp](https://github.com/nlohmann/json/releases/download/v2.0.4/json.hpp) (347 KB)
    - [json.hpp.asc](https://github.com/nlohmann/json/releases/download/v2.0.4/json.hpp.asc) (1 KB)

- Release date: 2016-09-11
- SHA-256: 632ceec4c25c4e2153f71470d3a2b992c8355f6d8b4d627d05dd16095cd3aeda

### Summary

This release fixes a bug in the stream parser (function `parse()` and the `<<`/`>>` operators). This fix is backwards compatible.

### Changes
- **Bug fix**: The end of a file stream was not detected properly which led to parse errors.
- Fixed a compiler warning about an unused variable.

## v2.0.3

!!! summary "Files"

    - [json.hpp](https://github.com/nlohmann/json/releases/download/v2.0.3/json.hpp) (347 KB)
    - [json.hpp.asc](https://github.com/nlohmann/json/releases/download/v2.0.3/json.hpp.asc) (1 KB)

- Release date: 2016-08-31
- SHA-256: 535b73efe5546fde9e763c14aeadfc7b58183c0b3cd43c29741025aba6cf6bd3

### Summary

This release combines a lot of small fixes and improvements. The release is backwards compatible.

### Changes
- The **parser/deserialization functions have been generalized** to process any contiguous sequence of 1-byte elements (e.g., `char`, `unsigned char`, `uint8_t`). This includes all kind of string representations (string literals, char arrays, `std::string`, `const char*`), contiguous containers (C-style arrays, `std::vector`, `std::array`, `std::valarray`, `std::initializer_list`). User-defined containers providing random-access iterator access via `std::begin` and `std::end` can be used as well. See the documentation ([1](https://nlohmann.github.io/json/classnlohmann_1_1basic__json_ace63ac4eb1dd7251a259d32e397461a3.html#ace63ac4eb1dd7251a259d32e397461a3), [2](https://nlohmann.github.io/json/classnlohmann_1_1basic__json_a90f05d55d9d0702c075cd281fd0d85ae.html#a90f05d55d9d0702c075cd281fd0d85ae), [3](https://nlohmann.github.io/json/classnlohmann_1_1basic__json_aeffd70f622f8f2a51fd3d95af64b63a7.html#aeffd70f622f8f2a51fd3d95af64b63a7), [4](https://nlohmann.github.io/json/classnlohmann_1_1basic__json_aa8dca2e91a6301c36890f844e64f0023.html#aa8dca2e91a6301c36890f844e64f0023)) for more information. Note that contiguous storage cannot be checked at compile time; if any of the parse functions are called with a noncompliant container, the behavior is undefined and will most likely yield segmentation violation. The preconditions are enforced by an assertion unless the library is compiled with preprocessor symbol `NDEBUG`.
- As a general remark on **assertions**: The library uses assertions to preclude undefined behavior. A [prominent example](https://github.com/nlohmann/json/issues/289) for this is the `operator[]` for const JSON objects. The behavior of this const version of the operator is undefined if the given key does not exist in the JSON object, because unlike the non-const version, it cannot add a `null` value at the given key. Assertions can be switched of by defining the preprocessor symbol `NDEBUG`. See the [documentation of `assert`](http://en.cppreference.com/w/cpp/error/assert) for more information.
- In the course of cleaning up the parser/deserialization functions, the constructor [`basic_json(std::istream&, const parser_callback_t)`](https://nlohmann.github.io/json/classnlohmann_1_1basic__json_a32350263eb105764844c5a85e156a255.html#a32350263eb105764844c5a85e156a255) has been **deprecated** and will be deleted with the next major release 3.0.0 to unify the interface of the library. Deserialization will be done by stream operators or by calling one of the `parse` functions. That is, calls like `json j(i);` for an input stream `i` need to be replaced by `json j = json::parse(i);`. Compilers will produce a deprecation warning if client code uses this function.
- Minor improvements:
  - Improved the performance of the serialization by avoiding the re-creation of a locale object.
  - Fixed two MSVC warnings. Compiling the test suite with `/Wall` now only warns about non-inlined functions (C4710) and the deprecation of the constructor from input-stream (C4996).
- Some project internals:
  - <img align="right" src="https://bestpractices.coreinfrastructure.org/assets/questions_page_badge-17b338c0e8528d695d8676e23f39f17ca2b89bb88176370803ee69aeebcb5be4.png"> The project has qualified for the [Core Infrastructure Initiative Best Practices Badge](https://bestpractices.coreinfrastructure.org/projects/289). While most requirements where already satisfied, some led to a more explicit documentation of quality-ensuring procedures. For instance, static analysis is now executed with every commit on the build server. Furthermore, the [contribution guidelines document](https://github.com/nlohmann/json/blob/develop/.github/CONTRIBUTING.md) how to communicate security issues privately.
  - The test suite has been overworked and split into several files to allow for faster compilation and analysis. The execute the test suite, simply execute `make check`.
  - The continuous integration with [Travis](https://travis-ci.org/nlohmann/json) was extended with Clang versions 3.6.0 to 3.8.1 and now includes 18 different compiler/OS combinations.
  - An 11-day run of [American fuzzy lop](http://lcamtuf.coredump.cx/afl/) checked 962 million inputs on the parser and found no issue.

## v2.0.2

!!! summary "Files"

    - [json.hpp](https://github.com/nlohmann/json/releases/download/v2.0.2/json.hpp) (338 KB)
    - [json.hpp.asc](https://github.com/nlohmann/json/releases/download/v2.0.2/json.hpp.asc) (1 KB)

- Release date: 2016-07-31
- SHA-256: 8e97b7965b4594b00998d6704465412360e1a0ed927badb51ded8b82291a8f3d

### Summary

This release combines a lot of small fixes and improvements. The release is backwards compatible.

### Changes
- The **parser** has been overworked, and a lot of small issues have been fixed:
  - Improved parser performance by avoiding recursion and using move semantics for the return value.
  - Unescaped control charaters `\x10`-`\x1f` are not accepted any more.
  - Fixed a bug in the parser when reading from an input stream.
  - Improved test case coverage for UTF-8 parsing: now, all valid Unicode code points are tested both escaped and unescaped.
  - The precision of output streams is now preserved by the parser.
- Started to check the **code correctness** by proving termination of important loops. Furthermore, individual assertions have been replaced by a more systematic function which checks the class invariants. Note that assertions should be switched off in production by defining the preprocessor macro `NDEBUG`, see the [documentation of `assert`](http://en.cppreference.com/w/cpp/error/assert).
- A lot of **code cleanup**: removed unused headers, fixed some compiler warnings, and fixed a build error for Windows-based Clang builds.
- Added some compile-time checks:
  - Unsupported compilers are rejected during compilation with an `#error` command.
  - Static assertion prohibits code with incompatible pointer types used in `get_ptr()`.
- Improved the [documentation](https://nlohmann.github.io/json/), and adjusted the documentation script to choose the correct version of `sed`.
- Replaced a lot of "raw loops" by STL functions like `std::all_of`, `std::for_each`, or `std::accumulate`. This facilitates reasoning about termination of loops and sometimes allowed to simplify functions to a single return statement.
- Implemented a `value()` function for JSON pointers (similar to `at` function).
- The Homebrew formula (see [Integration](https://github.com/nlohmann/json#integration)) is now tested for all Xcode builds (6.1 - 8.x) with Travis.
- Avoided output to `std::cout` in the test cases.

## v2.0.1

!!! summary "Files"

    - [json.hpp](https://github.com/nlohmann/json/releases/download/v2.0.1/json.hpp) (321 KB)
    - [json.hpp.asc](https://github.com/nlohmann/json/releases/download/v2.0.1/json.hpp.asc) (1 KB)

- Release date: 2016-06-28
- SHA-256: ef550fcd7df572555bf068e9ec4e9d3b9e4cdd441cecb0dcea9ea7fd313f72dd

### Summary

This release fixes a performance regression in the JSON serialization (function `dump()`). This fix is backwards compatible.

### Changes
- The locale of the output stream (or the internal string stream if a JSON value is serialized to a string) is now adjusted once for the whole serialization instead of for each floating-point number.
- The locale of an output stream is now correctly reset to the previous value by the JSON library.


## v2.0.0

!!! summary "Files"

    - [json.hpp](https://github.com/nlohmann/json/releases/download/v2.0.0/json.hpp) (321 KB)
    - [json.hpp.asc](https://github.com/nlohmann/json/releases/download/v2.0.0/json.hpp.asc) (1 KB)

- Release date: 2016-06-24
- SHA-256: ac9e1fb25c2ac9ca5fc501fcd2fe3281fe04f07018a1b48820e7b1b11491bb6c

### Summary

This release adds several features such as JSON Pointers, JSON Patch, or support for 64 bit unsigned integers. Furthermore, several (subtle) bugs have been fixed.

As `noexcept` and `constexpr` specifier have been added to several functions, the public API has effectively been changed in a (potential) non-backwards compatible manner. As we adhere to [Semantic Versioning](http://semver.org), this calls for a new major version, so say hello to 2️⃣.0️⃣.0️⃣.

### Changes
- 🔟 A JSON value now uses `uint64_t` (default value for template parameter `NumberUnsignedType`) as data type for **unsigned integer** values. This type is used automatically when an unsigned number is parsed. Furthermore, constructors, conversion operators and an `is_number_unsigned()` test have been added.
-  👉 **JSON Pointer** ([RFC 6901](https://tools.ietf.org/html/rfc6901)) support: A JSON Pointer is a string (similar to an XPath expression) to address a value inside a structured JSON value. JSON Pointers can be used in `at()` and `operator[]` functions. Furthermore, JSON values can be “flattened” to key/value pairs using `flatten()` where each key is a JSON Pointer. The original value can be restored by “unflattening” the flattened value using `unflatten()`.
- 🏥 **JSON Patch** ([RFC 6902](https://tools.ietf.org/html/rfc6902)) support. A JSON Patch is a JSON value that describes the required edit operations (add, change, remove, …) to transform a JSON value into another one. A JSON Patch can be created with function `diff(const basic_json&)` and applied with `patch(const basic_json&)`. Note the created patches use a rather primitive algorithm so far and leave room for improvement.
- 🇪🇺 The code is now **locale-independent**: Floating-point numbers are always serialized with a period (`.`) as decimal separator and ignores different settings from the locale.
- 🍺 **Homebrew** support: Install the library with `brew tap nlohmann/json && brew install nlohmann_json`.
- Added constructor to create a JSON value by parsing a `std::istream` (e.g., `std::stringstream` or `std::ifstream`).
- Added **`noexcept`** specifier to `basic_json(boolean_t)`, `basic_json(const number_integer_t)`, `basic_json(const int)`, `basic_json(const number_float_t)`, iterator functions (`begin()`, `end()`, etc.)
- When parsing numbers, the sign of `0.0` (vs. `-0.0`) is preserved.
- Improved MSVC 2015, Android, and MinGW support. See [README](https://github.com/nlohmann/json#supported-compilers) for more information.
- Improved test coverage (added 2,225,386 tests).
- Removed some misuses of `std::move`.
- Fixed several compiler warnings.
- Improved error messages from JSON parser.
- Updated to [`re2c`](http://re2c.org) to version 0.16 to use a minimal DFAs for the lexer.
- Updated test suite to use [Catch](https://github.com/philsquared/Catch) version 1.5.6.
- Made type getters (`is_number`, etc.) and const value access `constexpr`.
- Functions `push_back` and `operator+=` now work with key/value pairs passed as initializer list, e.g. `j_object += {"key", 1}`.
- Overworked `CMakeLists.txt` to make it easier to integrate the library into other projects.

### Notes
- Parser error messages are still very vague and contain no information on the error location.
- The implemented `diff` function is rather primitive and does not create minimal diffs.
- The name of function `iteration_wrapper` may change in the future and the function will be deprecated in the next release.
- Roundtripping (i.e., parsing a JSON value from a string, serializing it, and comparing the strings) of floating-point numbers is not 100% accurate. Note that [RFC 8259](https://tools.ietf.org/html/rfc8259) defines no format to internally represent numbers and states not requirement for roundtripping. Nevertheless, benchmarks like [Native JSON Benchmark](https://github.com/miloyip/nativejson-benchmark) treat roundtripping deviations as conformance errors.


## v1.1.0

!!! summary "Files"

    - [json.hpp](https://github.com/nlohmann/json/releases/download/v1.1.0/json.hpp) (257 KB)
    - [json.hpp.asc](https://github.com/nlohmann/json/releases/download/v1.1.0/json.hpp.asc) (1 KB)

- Release date: 2016-01-24
- SHA-256: c0cf0e3017798ca6bb18e757ebc570d21a3bdac877845e2b9e9573d183ed2f05

### Summary

This release fixes several small bugs and adds functionality in a backwards-compatible manner. Compared to the [last version (1.0.0)](https://github.com/nlohmann/json/releases/tag/v1.0.0), the following changes have been made:

### Changes
- _Fixed_: **Floating-point numbers** are now serialized and deserialized properly such that rountripping works in more cases. [#185, #186, #190, #191, #194]
- _Added_: The code now contains **assertions** to detect undefined behavior during development. As the standard function `assert` is used, the assertions can be switched off by defining the preprocessor symbol `NDEBUG` during compilation. [#168]
- _Added_: It is now possible to get a **reference** to the stored values via the newly added function `get_ref()`. [#128, #184]
- _Fixed_: Access to object values via keys (**`operator[]`**) now works with all kind of string representations. [#171, #189]
- _Fixed_: The code now compiles again with **Microsoft Visual Studio 2015**. [#144, #167, #188]
- _Fixed_: All required headers are now included.
- _Fixed_: Typos and other small issues. [#162, #166,  #175, #177, #179, #180]

### Notes

There are still known open issues (#178, #187) which will be fixed in version 2.0.0. However, these fixes will require a small API change and will not be entirely backwards-compatible.


## v1.0.0

!!! summary "Files"

    - [json.hpp](https://github.com/nlohmann/json/releases/download/v1.0.0/json.hpp) (243 KB)
    - [json.hpp.asc](https://github.com/nlohmann/json/releases/download/v1.0.0/json.hpp.asc) (1 KB)

- Release date: 2015-12-28
- SHA-256: 767dc2fab1819d7b9e19b6e456d61e38d21ef7182606ecf01516e3f5230446de

### Summary

This is the first official release. Compared to the [prerelease version 1.0.0-rc1](https://github.com/nlohmann/json/releases/tag/v1.0.0-rc1), only a few minor improvements have been made:

### Changes
- _Changed_: A **UTF-8 byte order mark** is silently ignored.
- _Changed_: `sprintf` is no longer used.
- _Changed_: `iterator_wrapper` also works for const objects; note: the name may change!
- _Changed_: **Error messages** during deserialization have been improved.
- _Added_: The `parse` function now also works with type `std::istream&&`.
- _Added_: Function `value(key, default_value)` returns either a copy of an object's element at the specified key or a given default value if no element with the key exists.
- _Added_: Public functions are tagged with the version they were introduced. This shall allow for better **versioning** in the future.
- _Added_: All public functions and types are **documented** (see http://nlohmann.github.io/json/doxygen/) including executable examples.
- _Added_: Allocation of all types (in particular arrays, strings, and objects) is now exception-safe.
- _Added_: They descriptions of thrown exceptions have been overworked and are part of the tests suite and documentation.
