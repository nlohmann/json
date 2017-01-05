[![JSON for Modern C++](https://raw.githubusercontent.com/nlohmann/json/master/doc/json.gif)](https://github.com/nlohmann/json/releases)

[![Build Status](https://travis-ci.org/nlohmann/json.svg?branch=master)](https://travis-ci.org/nlohmann/json)
[![Build Status](https://ci.appveyor.com/api/projects/status/1acb366xfyg3qybk/branch/develop?svg=true)](https://ci.appveyor.com/project/nlohmann/json)
[![Build status](https://doozer.io/badge/nlohmann/json/buildstatus/develop)](https://doozer.io/user/nlohmann/json)
[![Coverage Status](https://img.shields.io/coveralls/nlohmann/json.svg)](https://coveralls.io/r/nlohmann/json)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/5550/badge.svg)](https://scan.coverity.com/projects/nlohmann-json)
[![Try online](https://img.shields.io/badge/try-online-blue.svg)](http://melpon.org/wandbox/permlink/IoZNMHqubixQx2dN)
[![Documentation](https://img.shields.io/badge/docs-doxygen-blue.svg)](http://nlohmann.github.io/json)
[![GitHub license](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/nlohmann/json/master/LICENSE.MIT)
[![Github Releases](https://img.shields.io/github/release/nlohmann/json.svg)](https://github.com/nlohmann/json/releases)
[![Github Issues](https://img.shields.io/github/issues/nlohmann/json.svg)](http://github.com/nlohmann/json/issues)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/289/badge)](https://bestpractices.coreinfrastructure.org/projects/289)

- [Design goals](#design-goals)
- [Integration](#integration)
- [Examples](#examples)
  - [JSON as first-class data type](#json-as-first-class-data-type)
  - [Serialization / Deserialization](#serialization--deserialization)
  - [STL-like access](#stl-like-access)
  - [Conversion from STL containers](#conversion-from-stl-containers)
  - [JSON Pointer and JSON Patch](#json-pointer-and-json-patch)
  - [Implicit conversions](#implicit-conversions)
  - [Binary formats (CBOR and MessagePack)](#binary-formats-cbor-and-messagepack)
- [Supported compilers](#supported-compilers)
- [License](#license)
- [Thanks](#thanks)
- [Notes](#notes)
- [Execute unit tests](#execute-unit-tests)

## Design goals

There are myriads of [JSON](http://json.org) libraries out there, and each may even have its reason to exist. Our class had these design goals:

- **Intuitive syntax**. In languages such as Python, JSON feels like a first class data type. We used all the operator magic of modern C++ to achieve the same feeling in your code. Check out the [examples below](#examples) and you'll know what I mean.

- **Trivial integration**. Our whole code consists of a single header file [`json.hpp`](https://github.com/nlohmann/json/blob/develop/src/json.hpp). That's it. No library, no subproject, no dependencies, no complex build system. The class is written in vanilla C++11. All in all, everything should require no adjustment of your compiler flags or project settings.

- **Serious testing**. Our class is heavily [unit-tested](https://github.com/nlohmann/json/blob/master/test/src/unit.cpp) and covers [100%](https://coveralls.io/r/nlohmann/json) of the code, including all exceptional behavior. Furthermore, we checked with [Valgrind](http://valgrind.org) that there are no memory leaks. To maintain high quality, the project is following the [Core Infrastructure Initiative (CII) best practices](https://bestpractices.coreinfrastructure.org/projects/289).

Other aspects were not so important to us:

- **Memory efficiency**. Each JSON object has an overhead of one pointer (the maximal size of a union) and one enumeration element (1 byte). The default generalization uses the following C++ data types: `std::string` for strings, `int64_t`, `uint64_t` or `double` for numbers, `std::map` for objects, `std::vector` for arrays, and `bool` for Booleans. However, you can template the generalized class `basic_json` to your needs.

- **Speed**. There are certainly [faster JSON libraries](https://github.com/miloyip/nativejson-benchmark#parsing-time) out there. However, if your goal is to speed up your development by adding JSON support with a single header, then this library is the way to go. If you know how to use a `std::vector` or `std::map`, you are already set.

See the [contribution guidelines](https://github.com/nlohmann/json/blob/master/.github/CONTRIBUTING.md#please-dont) for more information.


## Integration

The single required source, file `json.hpp` is in the `src` directory or [released here](https://github.com/nlohmann/json/releases). All you need to do is add

```cpp
#include "json.hpp"

// for convenience
using json = nlohmann::json;
```

to the files you want to use JSON objects. That's it. Do not forget to set the necessary switches to enable C++11 (e.g., `-std=c++11` for GCC and Clang).

:beer: If you are using OS X and [Homebrew](http://brew.sh), just type `brew tap nlohmann/json` and `brew install nlohmann_json` and you're set. If you want the bleeding edge rather than the latest release, use `brew install nlohmann_json --HEAD`.


## Examples

Beside the examples below, you may want to check the [documentation](https://nlohmann.github.io/json/) where each function contains a separate code example (e.g., check out [`emplace()`](https://nlohmann.github.io/json/classnlohmann_1_1basic__json_a602f275f0359ab181221384989810604.html#a602f275f0359ab181221384989810604)). All [example files](https://github.com/nlohmann/json/tree/develop/doc/examples) can be compiled and executed on their own (e.g., file [emplace.cpp](https://github.com/nlohmann/json/blob/develop/doc/examples/emplace.cpp)).

### JSON as first-class data type

Here are some examples to give you an idea how to use the class.

Assume you want to create the JSON object

```json
{
  "pi": 3.141,
  "happy": true,
  "name": "Niels",
  "nothing": null,
  "answer": {
    "everything": 42
  },
  "list": [1, 0, 2],
  "object": {
    "currency": "USD",
    "value": 42.99
  }
}
```

With the JSON class, you could write:

```cpp
// create an empty structure (null)
json j;

// add a number that is stored as double (note the implicit conversion of j to an object)
j["pi"] = 3.141;

// add a Boolean that is stored as bool
j["happy"] = true;

// add a string that is stored as std::string
j["name"] = "Niels";

// add another null object by passing nullptr
j["nothing"] = nullptr;

// add an object inside the object
j["answer"]["everything"] = 42;

// add an array that is stored as std::vector (using an initializer list)
j["list"] = { 1, 0, 2 };

// add another object (using an initializer list of pairs)
j["object"] = { {"currency", "USD"}, {"value", 42.99} };

// instead, you could also write (which looks very similar to the JSON above)
json j2 = {
  {"pi", 3.141},
  {"happy", true},
  {"name", "Niels"},
  {"nothing", nullptr},
  {"answer", {
    {"everything", 42}
  }},
  {"list", {1, 0, 2}},
  {"object", {
    {"currency", "USD"},
    {"value", 42.99}
  }}
};
```

Note that in all these cases, you never need to "tell" the compiler which JSON value you want to use. If you want to be explicit or express some edge cases, the functions `json::array` and `json::object` will help:

```cpp
// a way to express the empty array []
json empty_array_explicit = json::array();

// ways to express the empty object {}
json empty_object_implicit = json({});
json empty_object_explicit = json::object();

// a way to express an _array_ of key/value pairs [["currency", "USD"], ["value", 42.99]]
json array_not_object = { json::array({"currency", "USD"}), json::array({"value", 42.99}) };
```


### Serialization / Deserialization

#### To/from strings

You can create an object (deserialization) by appending `_json` to a string literal:

```cpp
// create object from string literal
json j = "{ \"happy\": true, \"pi\": 3.141 }"_json;

// or even nicer with a raw string literal
auto j2 = R"(
  {
    "happy": true,
    "pi": 3.141
  }
)"_json;

// or explicitly
auto j3 = json::parse("{ \"happy\": true, \"pi\": 3.141 }");
```

You can also get a string representation (serialize):

```cpp
// explicit conversion to string
std::string s = j.dump();    // {\"happy\":true,\"pi\":3.141}

// serialization with pretty printing
// pass in the amount of spaces to indent
std::cout << j.dump(4) << std::endl;
// {
//     "happy": true,
//     "pi": 3.141
// }
```

#### To/from streams (e.g. files, string streams)

You can also use streams to serialize and deserialize:

```cpp
// deserialize from standard input
json j;
std::cin >> j;

// serialize to standard output
std::cout << j;

// the setw manipulator was overloaded to set the indentation for pretty printing
std::cout << std::setw(4) << j << std::endl;
```

These operators work for any subclasses of `std::istream` or `std::ostream`. Here is the same example with files:

```cpp
// read a JSON file
std::ifstream i("file.json");
json j;
i >> j;

// write prettified JSON to another file
std::ofstream o("pretty.json");
o << std::setw(4) << j << std::endl;
```

Please note that setting the exception bit for `failbit` is inappropriate for this use case. It will result in program termination due to the `noexcept` specifier in use.

#### Read from iterator range

You can also read JSON from an iterator range; that is, from any container accessible by iterators whose content is stored as contiguous byte sequence, for instance a `std::vector<uint8_t>`:

```cpp
std::vector<uint8_t> v = {'t', 'r', 'u', 'e'};
json j = json::parse(v.begin(), v.end());
```

You may leave the iterators for the range [begin, end):

```cpp
std::vector<uint8_t> v = {'t', 'r', 'u', 'e'};
json j = json::parse(v);
```


### STL-like access

We designed the JSON class to behave just like an STL container. In fact, it satisfies the [**ReversibleContainer**](http://en.cppreference.com/w/cpp/concept/ReversibleContainer) requirement.

```cpp
// create an array using push_back
json j;
j.push_back("foo");
j.push_back(1);
j.push_back(true);

// also use emplace_back
j.emplace_back(1.78);

// iterate the array
for (json::iterator it = j.begin(); it != j.end(); ++it) {
  std::cout << *it << '\n';
}

// range-based for
for (auto& element : j) {
  std::cout << element << '\n';
}

// getter/setter
const std::string tmp = j[0];
j[1] = 42;
bool foo = j.at(2);

// other stuff
j.size();     // 3 entries
j.empty();    // false
j.type();     // json::value_t::array
j.clear();    // the array is empty again

// convenience type checkers
j.is_null();
j.is_boolean();
j.is_number();
j.is_object();
j.is_array();
j.is_string();

// comparison
j == "[\"foo\", 1, true]"_json;  // true

// create an object
json o;
o["foo"] = 23;
o["bar"] = false;
o["baz"] = 3.141;

// also use emplace
o.emplace("weather", "sunny");

// special iterator member functions for objects
for (json::iterator it = o.begin(); it != o.end(); ++it) {
  std::cout << it.key() << " : " << it.value() << "\n";
}

// find an entry
if (o.find("foo") != o.end()) {
  // there is an entry with key "foo"
}

// or simpler using count()
int foo_present = o.count("foo"); // 1
int fob_present = o.count("fob"); // 0

// delete an entry
o.erase("foo");
```


### Conversion from STL containers

Any sequence container (`std::array`, `std::vector`, `std::deque`, `std::forward_list`, `std::list`) whose values can be used to construct JSON types (e.g., integers, floating point numbers, Booleans, string types, or again STL containers described in this section) can be used to create a JSON array. The same holds for similar associative containers (`std::set`, `std::multiset`, `std::unordered_set`, `std::unordered_multiset`), but in these cases the order of the elements of the array depends how the elements are ordered in the respective STL container.

```cpp
std::vector<int> c_vector {1, 2, 3, 4};
json j_vec(c_vector);
// [1, 2, 3, 4]

std::deque<double> c_deque {1.2, 2.3, 3.4, 5.6};
json j_deque(c_deque);
// [1.2, 2.3, 3.4, 5.6]

std::list<bool> c_list {true, true, false, true};
json j_list(c_list);
// [true, true, false, true]

std::forward_list<int64_t> c_flist {12345678909876, 23456789098765, 34567890987654, 45678909876543};
json j_flist(c_flist);
// [12345678909876, 23456789098765, 34567890987654, 45678909876543]

std::array<unsigned long, 4> c_array {{1, 2, 3, 4}};
json j_array(c_array);
// [1, 2, 3, 4]

std::set<std::string> c_set {"one", "two", "three", "four", "one"};
json j_set(c_set); // only one entry for "one" is used
// ["four", "one", "three", "two"]

std::unordered_set<std::string> c_uset {"one", "two", "three", "four", "one"};
json j_uset(c_uset); // only one entry for "one" is used
// maybe ["two", "three", "four", "one"]

std::multiset<std::string> c_mset {"one", "two", "one", "four"};
json j_mset(c_mset); // both entries for "one" are used
// maybe ["one", "two", "one", "four"]

std::unordered_multiset<std::string> c_umset {"one", "two", "one", "four"};
json j_umset(c_umset); // both entries for "one" are used
// maybe ["one", "two", "one", "four"]
```

Likewise, any associative key-value containers (`std::map`, `std::multimap`, `std::unordered_map`, `std::unordered_multimap`) whose keys can construct an `std::string` and whose values can be used to construct JSON types (see examples above) can be used to to create a JSON object. Note that in case of multimaps only one key is used in the JSON object and the value depends on the internal order of the STL container.

```cpp
std::map<std::string, int> c_map { {"one", 1}, {"two", 2}, {"three", 3} };
json j_map(c_map);
// {"one": 1, "three": 3, "two": 2 }

std::unordered_map<const char*, double> c_umap { {"one", 1.2}, {"two", 2.3}, {"three", 3.4} };
json j_umap(c_umap);
// {"one": 1.2, "two": 2.3, "three": 3.4}

std::multimap<std::string, bool> c_mmap { {"one", true}, {"two", true}, {"three", false}, {"three", true} };
json j_mmap(c_mmap); // only one entry for key "three" is used
// maybe {"one": true, "two": true, "three": true}

std::unordered_multimap<std::string, bool> c_ummap { {"one", true}, {"two", true}, {"three", false}, {"three", true} };
json j_ummap(c_ummap); // only one entry for key "three" is used
// maybe {"one": true, "two": true, "three": true}
```

### JSON Pointer and JSON Patch

The library supports **JSON Pointer** ([RFC 6901](https://tools.ietf.org/html/rfc6901)) as alternative means to address structured values. On top of this, **JSON Patch** ([RFC 6902](https://tools.ietf.org/html/rfc6902)) allows to describe differences between two JSON values - effectively allowing patch and diff operations known from Unix.

```cpp
// a JSON value
json j_original = R"({
  "baz": ["one", "two", "three"],
  "foo": "bar"
})"_json;

// access members with a JSON pointer (RFC 6901)
j_original["/baz/1"_json_pointer];
// "two"

// a JSON patch (RFC 6902)
json j_patch = R"([
  { "op": "replace", "path": "/baz", "value": "boo" },
  { "op": "add", "path": "/hello", "value": ["world"] },
  { "op": "remove", "path": "/foo"}
])"_json;

// apply the patch
json j_result = j_original.patch(j_patch);
// {
//    "baz": "boo",
//    "hello": ["world"]
// }

// calculate a JSON patch from two JSON values
json::diff(j_result, j_original);
// [
//   { "op":" replace", "path": "/baz", "value": ["one", "two", "three"] },
//   { "op": "remove","path": "/hello" },
//   { "op": "add", "path": "/foo", "value": "bar" }
// ]
```


### Implicit conversions

The type of the JSON object is determined automatically by the expression to store. Likewise, the stored value is implicitly converted.

```cpp
// strings
std::string s1 = "Hello, world!";
json js = s1;
std::string s2 = js;

// Booleans
bool b1 = true;
json jb = b1;
bool b2 = jb;

// numbers
int i = 42;
json jn = i;
double f = jn;

// etc.
```

You can also explicitly ask for the value:

```cpp
std::string vs = js.get<std::string>();
bool vb = jb.get<bool>();
int vi = jn.get<int>();

// etc.
```

### Binary formats (CBOR and MessagePack)

Though JSON is a ubiquitous data format, it is not a very compact format suitable for data exchange, for instance over a network. Hence, the library supports [CBOR](http://cbor.io) (Concise Binary Object Representation) and [MessagePack](http://msgpack.org) to efficiently encode JSON values to byte vectors and to decode such vectors.

```cpp
// create a JSON value
json j = R"({"compact": true, "schema": 0})"_json;

// serialize to CBOR
std::vector<uint8_t> v_cbor = json::to_cbor(j);

// 0xa2, 0x67, 0x63, 0x6f, 0x6d, 0x70, 0x61, 0x63, 0x74, 0xf5, 0x66, 0x73, 0x63, 0x68, 0x65, 0x6d, 0x61, 0x00

// roundtrip
json j_from_cbor = json::from_cbor(v_cbor);

// serialize to MessagePack
std::vector<uint8_t> v_msgpack = json::to_msgpack(j);

// 0x82, 0xa7, 0x63, 0x6f, 0x6d, 0x70, 0x61, 0x63, 0x74, 0xc3, 0xa6, 0x73, 0x63, 0x68, 0x65, 0x6d, 0x61, 0x00

// roundtrip
json j_from_msgpack = json::from_msgpack(v_msgpack);
```


## Supported compilers

Though it's 2016 already, the support for C++11 is still a bit sparse. Currently, the following compilers are known to work:

- GCC 4.9 - 6.0 (and possibly later)
- Clang 3.4 - 3.9 (and possibly later)
- Microsoft Visual C++ 2015 / Build Tools 14.0.25123.0 (and possibly later)

I would be happy to learn about other compilers/versions.

Please note:

- GCC 4.8 does not work because of two bugs ([55817](https://gcc.gnu.org/bugzilla/show_bug.cgi?id=55817) and [57824](https://gcc.gnu.org/bugzilla/show_bug.cgi?id=57824)) in the C++11 support. Note there is a [pull request](https://github.com/nlohmann/json/pull/212) to fix some of the issues.
- Android defaults to using very old compilers and C++ libraries. To fix this, add the following to your `Application.mk`. This will switch to the LLVM C++ library, the Clang compiler, and enable C++11 and other features disabled by default.
 
    ```
    APP_STL := c++_shared
    NDK_TOOLCHAIN_VERSION := clang3.6
    APP_CPPFLAGS += -frtti -fexceptions
    ```
 
    The code compiles successfully with [Android NDK](https://developer.android.com/ndk/index.html?hl=ml), Revision 9 - 11 (and possibly later) and [CrystaX's Android NDK](https://www.crystax.net/en/android/ndk) version 10.

- For GCC running on MinGW or Android SDK, the error `'to_string' is not a member of 'std'` (or similarly, for `strtod`) may occur. Note this is not an issue with the code,  but rather with the compiler itself. On Android, see above to build with a newer environment.  For MinGW, please refer to [this site](http://tehsausage.com/mingw-to-string) and [this discussion](https://github.com/nlohmann/json/issues/136) for information on how to fix this bug. For Android NDK using `APP_STL := gnustl_static`, please refer to [this discussion](https://github.com/nlohmann/json/issues/219).

The following compilers are currently used in continuous integration at [Travis](https://travis-ci.org/nlohmann/json) and [AppVeyor](https://ci.appveyor.com/project/nlohmann/json):

| Compiler        | Operating System             | Version String |
|-----------------|------------------------------|----------------|
| GCC 4.9.3       | Ubuntu 14.04.4 LTS           | g++-4.9 (Ubuntu 4.9.3-8ubuntu2~14.04) 4.9.3 |
| GCC 5.3.0       | Ubuntu 14.04.4 LTS           | g++-5 (Ubuntu 5.3.0-3ubuntu1~14.04) 5.3.0 20151204 |
| GCC 6.1.1       | Ubuntu 14.04.4 LTS           | g++-6 (Ubuntu 6.1.1-3ubuntu11~14.04.1) 6.1.1 20160511 |
| Clang 3.6.0     | Ubuntu 14.04.4 LTS           | clang version 3.6.0 (tags/RELEASE_360/final) |
| Clang 3.6.1     | Ubuntu 14.04.4 LTS           | clang version 3.6.1 (tags/RELEASE_361/final) |
| Clang 3.6.2     | Ubuntu 14.04.4 LTS           | clang version 3.6.2 (tags/RELEASE_362/final) |
| Clang 3.7.0     | Ubuntu 14.04.4 LTS           | clang version 3.7.0 (tags/RELEASE_370/final) |
| Clang 3.7.1     | Ubuntu 14.04.4 LTS           | clang version 3.7.1 (tags/RELEASE_371/final) |
| Clang 3.8.0     | Ubuntu 14.04.4 LTS           | clang version 3.8.0 (tags/RELEASE_380/final) |
| Clang 3.8.1     | Ubuntu 14.04.4 LTS           | clang version 3.8.1 (tags/RELEASE_381/final) |
| Clang Xcode 6.4 | Darwin Kernel Version 14.3.0 (OSX 10.10.3) | Apple LLVM version 6.1.0 (clang-602.0.53) (based on LLVM 3.6.0svn) |
| Clang Xcode 7.3 | Darwin Kernel Version 15.0.0 (OSX 10.10.5) | Apple LLVM version 7.3.0 (clang-703.0.29) |
| Clang Xcode 8.0 | Darwin Kernel Version 15.6.0 | Apple LLVM version 8.0.0 (clang-800.0.38) |
| Clang Xcode 8.1 | Darwin Kernel Version 16.1.0 (macOS 10.12.1) | Apple LLVM version 8.0.0 (clang-800.0.42.1) |
| Clang Xcode 8.2 | Darwin Kernel Version 16.1.0 (macOS 10.12.1) | Apple LLVM version 8.0.0 (clang-800.0.42.1) |
| Visual Studio 14 2015 | Windows Server 2012 R2 (x64) | Microsoft (R) Build Engine version 14.0.25123.0 | 


## License

<img align="right" src="http://opensource.org/trademarks/opensource/OSI-Approved-License-100x137.png">

The class is licensed under the [MIT License](http://opensource.org/licenses/MIT):

Copyright &copy; 2013-2016 [Niels Lohmann](http://nlohmann.me)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


## Thanks

I deeply appreciate the help of the following people.

- [Teemperor](https://github.com/Teemperor) implemented CMake support and lcov integration, realized escape and Unicode handling in the string parser, and fixed the JSON serialization.
- [elliotgoodrich](https://github.com/elliotgoodrich) fixed an issue with double deletion in the iterator classes.
- [kirkshoop](https://github.com/kirkshoop) made the iterators of the class composable to other libraries.
- [wancw](https://github.com/wanwc) fixed a bug that hindered the class to compile with Clang.
- Tomas Åblad found a bug in the iterator implementation.
- [Joshua C. Randall](https://github.com/jrandall) fixed a bug in the floating-point serialization.
- [Aaron Burghardt](https://github.com/aburgh) implemented code to parse streams incrementally. Furthermore, he greatly improved the parser class by allowing the definition of a filter function to discard undesired elements while parsing.
- [Daniel Kopeček](https://github.com/dkopecek) fixed a bug in the compilation with GCC 5.0.
- [Florian Weber](https://github.com/Florianjw) fixed a bug in and improved the performance of the comparison operators.
- [Eric Cornelius](https://github.com/EricMCornelius) pointed out a bug in the handling with NaN and infinity values. He also improved the performance of the string escaping.
- [易思龙](https://github.com/likebeta) implemented a conversion from anonymous enums.
- [kepkin](https://github.com/kepkin) patiently pushed forward the support for Microsoft Visual studio.
- [gregmarr](https://github.com/gregmarr) simplified the implementation of reverse iterators and helped with numerous hints and improvements.
- [Caio Luppi](https://github.com/caiovlp) fixed a bug in the Unicode handling.
- [dariomt](https://github.com/dariomt) fixed some typos in the examples.
- [Daniel Frey](https://github.com/d-frey) cleaned up some pointers and implemented exception-safe memory allocation.
- [Colin Hirsch](https://github.com/ColinH) took care of a small namespace issue.
- [Huu Nguyen](https://github.com/whoshuu) correct a variable name in the documentation.
- [Silverweed](https://github.com/silverweed) overloaded `parse()` to accept an rvalue reference.
- [dariomt](https://github.com/dariomt) fixed a subtlety in MSVC type support and implemented the `get_ref()` function to get a reference to stored values.
- [ZahlGraf](https://github.com/ZahlGraf) added a workaround that allows compilation using Android NDK.
- [whackashoe](https://github.com/whackashoe) replaced a function that was marked as unsafe by Visual Studio.
- [406345](https://github.com/406345) fixed two small warnings.
- [Glen Fernandes](https://github.com/glenfe) noted a potential portability problem in the `has_mapped_type` function.
- [Corbin Hughes](https://github.com/nibroc) fixed some typos in the contribution guidelines.
- [twelsby](https://github.com/twelsby) fixed the array subscript operator, an issue that failed the MSVC build, and floating-point parsing/dumping. He further added support for unsigned integer numbers and implemented better roundtrip support for parsed numbers.
- [Volker Diels-Grabsch](https://github.com/vog) fixed a link in the README file.
- [msm-](https://github.com/msm-) added support for american fuzzy lop. 
- [Annihil](https://github.com/Annihil) fixed an example in the README file.
- [Themercee](https://github.com/Themercee) noted a wrong URL in the README file.
- [Lv Zheng](https://github.com/lv-zheng) fixed a namespace issue with `int64_t` and `uint64_t`.
- [abc100m](https://github.com/abc100m) analyzed the issues with GCC 4.8 and proposed a [partial solution](https://github.com/nlohmann/json/pull/212).
- [zewt](https://github.com/zewt) added useful notes to the README file about Android.
- [Róbert Márki](https://github.com/robertmrk) added a fix to use move iterators and improved the integration via CMake.
- [Chris Kitching](https://github.com/ChrisKitching) cleaned up the CMake files.
- [Tom Needham](https://github.com/06needhamt) fixed a subtle bug with MSVC 2015 which was also proposed by [Michael K.](https://github.com/Epidal).
- [Mário Feroldi](https://github.com/thelostt) fixed a small typo.
- [duncanwerner](https://github.com/duncanwerner) found a really embarrassing performance regression in the 2.0.0 release.
- [Damien](https://github.com/dtoma) fixed one of the last conversion warnings.
- [Thomas Braun](https://github.com/t-b) fixed a warning in a test case.
- [Théo DELRIEU](https://github.com/theodelrieu) patiently and constructively oversaw the long way toward [iterator-range parsing](https://github.com/nlohmann/json/issues/290).
- [Stefan](https://github.com/5tefan) fixed a minor issue in the documentation.
- [Vasil Dimov](https://github.com/vasild) fixed the documentation regarding conversions from `std::multiset`.
- [ChristophJud](https://github.com/ChristophJud) overworked the CMake files to ease project inclusion.
- [Vladimir Petrigo](https://github.com/vpetrigo) made a SFINAE hack more readable.
- [Denis Andrejew](https://github.com/seeekr) fixed a grammar issue in the README file.
- [Pierre-Antoine Lacaze](https://github.com/palacaze) found a subtle bug in the `dump()` function.
- [TurpentineDistillery](https://github.com/TurpentineDistillery) pointed to [`std::locale::classic()`](http://en.cppreference.com/w/cpp/locale/locale/classic) to avoid too much locale joggling, found some nice performance improvements in the parser and improved the benchmarking code.
- [cgzones](https://github.com/cgzones) had an idea how to fix the Coverity scan.
- [Jared Grubb](https://github.com/jaredgrubb) silenced a nasty documentation warning.
- [Yixin Zhang](https://github.com/qwename) fixed an integer overflow check.
- [Bosswestfalen](https://github.com/Bosswestfalen) merged two iterator classes into a smaller one.
- [Daniel599](https://github.com/Daniel599) helped to get Travis execute the tests with Clang's sanitizers.

Thanks a lot for helping out!


## Notes

- The code contains numerous debug **assertions** which can be switched off by defining the preprocessor macro `NDEBUG`, see the [documentation of `assert`](http://en.cppreference.com/w/cpp/error/assert). In particular, note [`operator[]`](https://nlohmann.github.io/json/classnlohmann_1_1basic__json_a2e26bd0b0168abb61f67ad5bcd5b9fa1.html#a2e26bd0b0168abb61f67ad5bcd5b9fa1) implements **unchecked access** for const objects: If the given key is not present, the behavior is undefined (think of a dereferenced null pointer) and yields an [assertion failure](https://github.com/nlohmann/json/issues/289) if assertions are switched on. If you are not sure whether an element in an object exists, use checked access with the [`at()` function](https://nlohmann.github.io/json/classnlohmann_1_1basic__json_a674de1ee73e6bf4843fc5dc1351fb726.html#a674de1ee73e6bf4843fc5dc1351fb726).
- As the exact type of a number is not defined in the [JSON specification](http://rfc7159.net/rfc7159), this library tries to choose the best fitting C++ number type automatically. As a result, the type `double` may be used to store numbers which may yield [**floating-point exceptions**](https://github.com/nlohmann/json/issues/181) in certain rare situations if floating-point exceptions have been unmasked in the calling code. These exceptions are not caused by the library and need to be fixed in the calling code, such as by re-masking the exceptions prior to calling library functions.
- The library supports **Unicode input** as follows:
  - Only **UTF-8** encoded input is supported which is the default encoding for JSON according to [RFC 7159](http://rfc7159.net/rfc7159#rfc.section.8.1).
  - Other encodings such as Latin-1, UTF-16, or UTF-32 are not supported and will yield parse errors.
  - [Unicode noncharacters](http://www.unicode.org/faq/private_use.html#nonchar1) will not be replaced by the library.
  - Invalid surrogates (e.g., incomplete pairs such as `\uDEAD`) will yield parse errors.
  - The strings stored in the library are UTF-8 encoded. When using the default string type (`std::string`), note that its length/size functions return the number of stored bytes rather than the number of characters or glyphs.


## Execute unit tests

To compile and run the tests, you need to execute

```sh
$ make check

===============================================================================
All tests passed (11202040 assertions in 44 test cases)
```

Alternatively, you can use [CMake](https://cmake.org) and run

```sh
$ mkdir build
$ cd build
$ cmake ..
$ make
$ ctest
```

For more information, have a look at the file [.travis.yml](https://github.com/nlohmann/json/blob/master/.travis.yml).
