[![JSON for Modern C++](https://raw.githubusercontent.com/nlohmann/json/master/doc/json.gif)](https://github.com/nlohmann/json/releases)

[![Build Status](https://travis-ci.org/nlohmann/json.svg?branch=master)](https://travis-ci.org/nlohmann/json)
[![Build Status](https://ci.appveyor.com/api/projects/status/1acb366xfyg3qybk/branch/develop?svg=true)](https://ci.appveyor.com/project/nlohmann/json)
[![Coverage Status](https://img.shields.io/coveralls/nlohmann/json.svg)](https://coveralls.io/r/nlohmann/json)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/5550/badge.svg)](https://scan.coverity.com/projects/nlohmann-json)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/f3732b3327e34358a0e9d1fe9f661f08)](https://www.codacy.com/app/nlohmann/json?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=nlohmann/json&amp;utm_campaign=Badge_Grade)
[![Try online](https://img.shields.io/badge/try-online-blue.svg)](https://wandbox.org/permlink/TarF5pPn9NtHQjhf)
[![Documentation](https://img.shields.io/badge/docs-doxygen-blue.svg)](http://nlohmann.github.io/json)
[![GitHub license](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/nlohmann/json/master/LICENSE.MIT)
[![GitHub Releases](https://img.shields.io/github/release/nlohmann/json.svg)](https://github.com/nlohmann/json/releases)
[![GitHub Issues](https://img.shields.io/github/issues/nlohmann/json.svg)](http://github.com/nlohmann/json/issues)
[![Average time to resolve an issue](http://isitmaintained.com/badge/resolution/nlohmann/json.svg)](http://isitmaintained.com/project/nlohmann/json "Average time to resolve an issue")
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/289/badge)](https://bestpractices.coreinfrastructure.org/projects/289)

- [Design goals](#design-goals)
- [Integration](#integration)
- [Examples](#examples)
  - [JSON as first-class data type](#json-as-first-class-data-type)
  - [Serialization / Deserialization](#serialization--deserialization)
  - [STL-like access](#stl-like-access)
  - [Conversion from STL containers](#conversion-from-stl-containers)
  - [JSON Pointer and JSON Patch](#json-pointer-and-json-patch)
  - [JSON Merge Patch](#json-merge-patch)
  - [Implicit conversions](#implicit-conversions)
  - [Conversions to/from arbitrary types](#arbitrary-types-conversions)
  - [Binary formats (CBOR, MessagePack, and UBJSON)](#binary-formats-cbor-messagepack-and-ubjson)
- [Supported compilers](#supported-compilers)
- [License](#license)
- [Contact](#contact)
- [Thanks](#thanks)
- [Used third-party tools](#used-third-party-tools)
- [Projects using JSON for Modern C++](#projects-using-json-for-modern-c)
- [Notes](#notes)
- [Execute unit tests](#execute-unit-tests)

## Design goals

There are myriads of [JSON](http://json.org) libraries out there, and each may even have its reason to exist. Our class had these design goals:

- **Intuitive syntax**. In languages such as Python, JSON feels like a first class data type. We used all the operator magic of modern C++ to achieve the same feeling in your code. Check out the [examples below](#examples) and you'll know what I mean.

- **Trivial integration**. Our whole code consists of a single header file [`json.hpp`](https://github.com/nlohmann/json/blob/develop/single_include/nlohmann/json.hpp). That's it. No library, no subproject, no dependencies, no complex build system. The class is written in vanilla C++11. All in all, everything should require no adjustment of your compiler flags or project settings.

- **Serious testing**. Our class is heavily [unit-tested](https://github.com/nlohmann/json/tree/develop/test/src) and covers [100%](https://coveralls.io/r/nlohmann/json) of the code, including all exceptional behavior. Furthermore, we checked with [Valgrind](http://valgrind.org) and the [Clang Sanitizers](https://clang.llvm.org/docs/index.html) that there are no memory leaks. [Google OSS-Fuzz](https://github.com/google/oss-fuzz/tree/master/projects/json) additionally runs fuzz tests agains all parsers 24/7, effectively executing billions of tests so far. To maintain high quality, the project is following the [Core Infrastructure Initiative (CII) best practices](https://bestpractices.coreinfrastructure.org/projects/289).

Other aspects were not so important to us:

- **Memory efficiency**. Each JSON object has an overhead of one pointer (the maximal size of a union) and one enumeration element (1 byte). The default generalization uses the following C++ data types: `std::string` for strings, `int64_t`, `uint64_t` or `double` for numbers, `std::map` for objects, `std::vector` for arrays, and `bool` for Booleans. However, you can template the generalized class `basic_json` to your needs.

- **Speed**. There are certainly [faster JSON libraries](https://github.com/miloyip/nativejson-benchmark#parsing-time) out there. However, if your goal is to speed up your development by adding JSON support with a single header, then this library is the way to go. If you know how to use a `std::vector` or `std::map`, you are already set.

See the [contribution guidelines](https://github.com/nlohmann/json/blob/master/.github/CONTRIBUTING.md#please-dont) for more information.


## Integration

[`json.hpp`](https://github.com/nlohmann/json/blob/develop/single_include/nlohmann/json.hpp) is the single required file in `single_include/nlohmann` or [released here](https://github.com/nlohmann/json/releases). You need to add

```cpp
#include <nlohmann/json.hpp>

// for convenience
using json = nlohmann::json;
```

to the files you want to process JSON and set the necessary switches to enable C++11 (e.g., `-std=c++11` for GCC and Clang).

You can further use file [`include/nlohmann/json_fwd.hpp`](https://github.com/nlohmann/json/blob/develop/include/nlohmann/json_fwd.hpp) for forward-declarations. The installation of json_fwd.hpp (as part of cmake's install step), can be achieved by setting `-DJSON_MultipleHeaders=ON`.

### Package Managers

:beer: If you are using OS X and [Homebrew](http://brew.sh), just type `brew tap nlohmann/json` and `brew install nlohmann_json` and you're set. If you want the bleeding edge rather than the latest release, use `brew install nlohmann_json --HEAD`.

If you are using the [Meson Build System](http://mesonbuild.com), then you can wrap this repository as a subproject.

If you are using [Conan](https://www.conan.io/) to manage your dependencies, merely add `jsonformoderncpp/x.y.z@vthiery/stable` to your `conanfile.py`'s requires, where `x.y.z` is the release version you want to use. Please file issues [here](https://github.com/vthiery/conan-jsonformoderncpp/issues) if you experience problems with the packages.

If you are using [Spack](https://www.spack.io/) to manage your dependencies, you can use the `nlohmann_json` package. Please see the [spack project](https://github.com/spack/spack) for any issues regarding the packaging.

If you are using [hunter](https://github.com/ruslo/hunter/) on your project for external dependencies, then you can use the [nlohmann_json package](https://docs.hunter.sh/en/latest/packages/pkg/nlohmann_json.html). Please see the hunter project for any issues regarding the packaging.

If you are using [Buckaroo](https://buckaroo.pm), you can install this library's module with `buckaroo install nlohmann/json`. Please file issues [here](https://github.com/LoopPerfect/buckaroo-recipes/issues/new?title=nlohmann/nlohmann/json).

If you are using [vcpkg](https://github.com/Microsoft/vcpkg/) on your project for external dependencies, then you can use the [nlohmann-json package](https://github.com/Microsoft/vcpkg/tree/master/ports/nlohmann-json). Please see the vcpkg project for any issues regarding the packaging.

If you are using [cget](http://cget.readthedocs.io/en/latest/), you can install the latest development version with `cget install nlohmann/json`. A specific version can be installed with `cget install nlohmann/json@v3.1.0`. Also, the multiple header version can be installed by adding the `-DJSON_MultipleHeaders=ON` flag (i.e., `cget install nlohmann/json -DJSON_MultipleHeaders=ON`).

If you are using [CocoaPods](https://cocoapods.org), you can use the library by adding pod `"nlohmann_json", '~>3.1.2'` to your podfile (see [an example](https://bitbucket.org/benman/nlohmann_json-cocoapod/src/master/)). Please file issues [here](https://bitbucket.org/benman/nlohmann_json-cocoapod/issues?status=new&status=open).

## Examples

Beside the examples below, you may want to check the [documentation](https://nlohmann.github.io/json/) where each function contains a separate code example (e.g., check out [`emplace()`](https://nlohmann.github.io/json/classnlohmann_1_1basic__json_a5338e282d1d02bed389d852dd670d98d.html#a5338e282d1d02bed389d852dd670d98d)). All [example files](https://github.com/nlohmann/json/tree/develop/doc/examples) can be compiled and executed on their own (e.g., file [emplace.cpp](https://github.com/nlohmann/json/blob/develop/doc/examples/emplace.cpp)).

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

With this library, you could write:

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

Note that in all these cases, you never need to "tell" the compiler which JSON value type you want to use. If you want to be explicit or express some edge cases, the functions [`json::array`](https://nlohmann.github.io/json/classnlohmann_1_1basic__json_aa80485befaffcadaa39965494e0b4d2e.html#aa80485befaffcadaa39965494e0b4d2e) and [`json::object`](https://nlohmann.github.io/json/classnlohmann_1_1basic__json_aa13f7c0615867542ce80337cbcf13ada.html#aa13f7c0615867542ce80337cbcf13ada) will help:

```cpp
// a way to express the empty array []
json empty_array_explicit = json::array();

// ways to express the empty object {}
json empty_object_implicit = json({});
json empty_object_explicit = json::object();

// a way to express an _array_ of key/value pairs [["currency", "USD"], ["value", 42.99]]
json array_not_object = json::array({ {"currency", "USD"}, {"value", 42.99} });
```

### Serialization / Deserialization

#### To/from strings

You can create a JSON value (deserialization) by appending `_json` to a string literal:

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
```

Note that without appending the `_json` suffix, the passed string literal is not parsed, but just used as JSON string value. That is, `json j = "{ \"happy\": true, \"pi\": 3.141 }"` would just store the string `"{ "happy": true, "pi": 3.141 }"` rather than parsing the actual object.

The above example can also be expressed explicitly using [`json::parse()`](https://nlohmann.github.io/json/classnlohmann_1_1basic__json_aa9676414f2e36383c4b181fe856aa3c0.html#aa9676414f2e36383c4b181fe856aa3c0):

```cpp
// parse explicitly
auto j3 = json::parse("{ \"happy\": true, \"pi\": 3.141 }");
```

You can also get a string representation of a JSON value (serialize):

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

Note the difference between serialization and assignment:

```cpp
// store a string in a JSON value
json j_string = "this is a string";

// retrieve the string value (implicit JSON to std::string conversion)
std::string cpp_string = j_string;
// retrieve the string value (explicit JSON to std::string conversion)
auto cpp_string2 = j_string.get<std::string>();

// retrieve the serialized value (explicit JSON serialization)
std::string serialized_string = j_string.dump();

// output of original string
std::cout << cpp_string << " == " << cpp_string2 << " == " << j_string.get<std::string>() << '\n';
// output of serialized value
std::cout << j_string << " == " << serialized_string << std::endl;
```

[`.dump()`](https://nlohmann.github.io/json/classnlohmann_1_1basic__json_a5adea76fedba9898d404fef8598aa663.html#a5adea76fedba9898d404fef8598aa663) always returns the serialized value, and [`.get<std::string>()`](https://nlohmann.github.io/json/classnlohmann_1_1basic__json_a16f9445f7629f634221a42b967cdcd43.html#a16f9445f7629f634221a42b967cdcd43) returns the originally stored string value.

Note the library only supports UTF-8. When you store strings with different encodings in the library, calling [`dump()`](https://nlohmann.github.io/json/classnlohmann_1_1basic__json_a5adea76fedba9898d404fef8598aa663.html#a5adea76fedba9898d404fef8598aa663) may throw an exception.

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

You can also parse JSON from an iterator range; that is, from any container accessible by iterators whose content is stored as contiguous byte sequence, for instance a `std::vector<std::uint8_t>`:

```cpp
std::vector<std::uint8_t> v = {'t', 'r', 'u', 'e'};
json j = json::parse(v.begin(), v.end());
```

You may leave the iterators for the range [begin, end):

```cpp
std::vector<std::uint8_t> v = {'t', 'r', 'u', 'e'};
json j = json::parse(v);
```

#### SAX interface

The library uses a SAX-like interface with the following functions:

```cpp
// called when null is parsed
bool null();

// called when a boolean is parsed; value is passed
bool boolean(bool val);

// called when a signed or unsigned integer number is parsed; value is passed
bool number_integer(number_integer_t val);
bool number_unsigned(number_unsigned_t val);

// called when a floating-point number is parsed; value and original string is passed
bool number_float(number_float_t val, const string_t& s);

// called when a string is parsed; value is passed and can be safely moved away
bool string(string_t& val);

// called when an object or array begins or ends, resp. The number of elements is passed (or -1 if not known)
bool start_object(std::size_t elements);
bool end_object();
bool start_array(std::size_t elements);
bool end_array();
// called when an object key is parsed; value is passed and can be safely moved away
bool key(string_t& val);

// called when a parse error occurs; byte position, the last token, and an exception is passed
bool parse_error(std::size_t position, const std::string& last_token, const detail::exception& ex);
```

The return value of each function determines whether parsing should proceed.

To implement your own SAX handler, proceed as follows:

1. Implement the SAX interface in a class. You can use class `nlohmann::json_sax<json>` as base class, but you can also use any class where the functions described above are implemented and public.
2. Create an object of your SAX interface class, e.g. `my_sax`.
3. Call `bool json::sax_parse(input, &my_sax)`; where the first parameter can be any input like a string or an input stream and the second parameter is a pointer to your SAX interface.

Note the `sax_parse` function only returns a `bool` indicating the result of the last executed SAX event. It does not return a  `json` value - it is up to you to decide what to do with the SAX events. Furthermore, no exceptions are thrown in case of a parse error - it is up to you what to do with the exception object passed to your `parse_error` implementation. Internally, the SAX interface is used for the DOM parser (class `json_sax_dom_parser`) as well as the acceptor (`json_sax_acceptor`), see file [`json_sax.hpp`](https://github.com/nlohmann/json/blob/develop/include/nlohmann/detail/input/json_sax.hpp).


### STL-like access

We designed the JSON class to behave just like an STL container. In fact, it satisfies the [**ReversibleContainer**](https://en.cppreference.com/w/cpp/named_req/ReversibleContainer) requirement.

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

// comparison
j == "[\"foo\", 1, true]"_json;  // true

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

Any sequence container (`std::array`, `std::vector`, `std::deque`, `std::forward_list`, `std::list`) whose values can be used to construct JSON values (e.g., integers, floating point numbers, Booleans, string types, or again STL containers described in this section) can be used to create a JSON array. The same holds for similar associative containers (`std::set`, `std::multiset`, `std::unordered_set`, `std::unordered_multiset`), but in these cases the order of the elements of the array depends on how the elements are ordered in the respective STL container.

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

Likewise, any associative key-value containers (`std::map`, `std::multimap`, `std::unordered_map`, `std::unordered_multimap`) whose keys can construct an `std::string` and whose values can be used to construct JSON values (see examples above) can be used to create a JSON object. Note that in case of multimaps only one key is used in the JSON object and the value depends on the internal order of the STL container.

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

### JSON Merge Patch

The library supports **JSON Merge Patch** ([RFC 7386](https://tools.ietf.org/html/rfc7386)) as a patch format. Instead of using JSON Pointer (see above) to specify values to be manipulated, it describes the changes using a syntax that closely mimics the document being modified.

```cpp
// a JSON value
json j_document = R"({
  "a": "b",
  "c": {
    "d": "e",
    "f": "g"
  }
})"_json;

// a patch
json j_patch = R"({
  "a":"z",
  "c": {
    "f": null
  }
})"_json;

// apply the patch
j_original.merge_patch(j_patch);
// {
//  "a": "z",
//  "c": {
//    "d": "e"
//  }
// }
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

Note that `char` types are not automatically converted to JSON strings, but to integer numbers. A conversion to a string must be specified explicitly:

```cpp
char ch = 'A';                       // ASCII value 65
json j_default = ch;                 // stores integer number 65
json j_string = std::string(1, ch);  // stores string "A"
```

### Arbitrary types conversions

Every type can be serialized in JSON, not just STL containers and scalar types. Usually, you would do something along those lines:

```cpp
namespace ns {
    // a simple struct to model a person
    struct person {
        std::string name;
        std::string address;
        int age;
    };
}

ns::person p = {"Ned Flanders", "744 Evergreen Terrace", 60};

// convert to JSON: copy each value into the JSON object
json j;
j["name"] = p.name;
j["address"] = p.address;
j["age"] = p.age;

// ...

// convert from JSON: copy each value from the JSON object
ns::person p {
    j["name"].get<std::string>(),
    j["address"].get<std::string>(),
    j["age"].get<int>()
};
```

It works, but that's quite a lot of boilerplate... Fortunately, there's a better way:

```cpp
// create a person
ns::person p {"Ned Flanders", "744 Evergreen Terrace", 60};

// conversion: person -> json
json j = p;

std::cout << j << std::endl;
// {"address":"744 Evergreen Terrace","age":60,"name":"Ned Flanders"}

// conversion: json -> person
ns::person p2 = j;

// that's it
assert(p == p2);
```

#### Basic usage

To make this work with one of your types, you only need to provide two functions:

```cpp
using nlohmann::json;

namespace ns {
    void to_json(json& j, const person& p) {
        j = json{{"name", p.name}, {"address", p.address}, {"age", p.age}};
    }

    void from_json(const json& j, person& p) {
        p.name = j.at("name").get<std::string>();
        p.address = j.at("address").get<std::string>();
        p.age = j.at("age").get<int>();
    }
} // namespace ns
```

That's all! When calling the `json` constructor with your type, your custom `to_json` method will be automatically called.
Likewise, when calling `get<your_type>()`, the `from_json` method will be called.

Some important things:

* Those methods **MUST** be in your type's namespace (which can be the global namespace), or the library will not be able to locate them (in this example, they are in namespace `ns`, where `person` is defined).
* Those methods **MUST** be available (e.g., properly headers must be included) everywhere you use the implicit conversions. Look at [issue 1108](https://github.com/nlohmann/json/issues/1108) for errors that may occur otherwise.
* When using `get<your_type>()`, `your_type` **MUST** be [DefaultConstructible](https://en.cppreference.com/w/cpp/named_req/DefaultConstructible). (There is a way to bypass this requirement described later.)
* In function `from_json`, use function [`at()`](https://nlohmann.github.io/json/classnlohmann_1_1basic__json_a93403e803947b86f4da2d1fb3345cf2c.html#a93403e803947b86f4da2d1fb3345cf2c) to access the object values rather than `operator[]`. In case a key does not exist, `at` throws an exception that you can handle, whereas `operator[]` exhibits undefined behavior.
* In case your type contains several `operator=` definitions, code like `your_variable = your_json;` [may not compile](https://github.com/nlohmann/json/issues/667). You need to write `your_variable = your_json.get<decltype your_variable>();` instead.
* You do not need to add serializers or deserializers for STL types like `std::vector`: the library already implements these.
* Be careful with the definition order of the `from_json`/`to_json` functions: If a type `B` has a member of type `A`, you **MUST** define `to_json(A)` before `to_json(B)`. Look at [issue 561](https://github.com/nlohmann/json/issues/561) for more details.


#### How do I convert third-party types?

This requires a bit more advanced technique. But first, let's see how this conversion mechanism works:

The library uses **JSON Serializers** to convert types to json.
The default serializer for `nlohmann::json` is `nlohmann::adl_serializer` (ADL means [Argument-Dependent Lookup](https://en.cppreference.com/w/cpp/language/adl)).

It is implemented like this (simplified):

```cpp
template <typename T>
struct adl_serializer {
    static void to_json(json& j, const T& value) {
        // calls the "to_json" method in T's namespace
    }

    static void from_json(const json& j, T& value) {
        // same thing, but with the "from_json" method
    }
};
```

This serializer works fine when you have control over the type's namespace. However, what about `boost::optional` or `std::filesystem::path` (C++17)? Hijacking the `boost` namespace is pretty bad, and it's illegal to add something other than template specializations to `std`...

To solve this, you need to add a specialization of `adl_serializer` to the `nlohmann` namespace, here's an example:

```cpp
// partial specialization (full specialization works too)
namespace nlohmann {
    template <typename T>
    struct adl_serializer<boost::optional<T>> {
        static void to_json(json& j, const boost::optional<T>& opt) {
            if (opt == boost::none) {
                j = nullptr;
            } else {
              j = *opt; // this will call adl_serializer<T>::to_json which will
                        // find the free function to_json in T's namespace!
            }
        }

        static void from_json(const json& j, boost::optional<T>& opt) {
            if (j.is_null()) {
                opt = boost::none;
            } else {
                opt = j.get<T>(); // same as above, but with
                                  // adl_serializer<T>::from_json
            }
        }
    };
}
```

#### How can I use `get()` for non-default constructible/non-copyable types?

There is a way, if your type is [MoveConstructible](https://en.cppreference.com/w/cpp/named_req/MoveConstructible). You will need to specialize the `adl_serializer` as well, but with a special `from_json` overload:

```cpp
struct move_only_type {
    move_only_type() = delete;
    move_only_type(int ii): i(ii) {}
    move_only_type(const move_only_type&) = delete;
    move_only_type(move_only_type&&) = default;

    int i;
};

namespace nlohmann {
    template <>
    struct adl_serializer<move_only_type> {
        // note: the return type is no longer 'void', and the method only takes
        // one argument
        static move_only_type from_json(const json& j) {
            return {j.get<int>()};
        }

        // Here's the catch! You must provide a to_json method! Otherwise you
        // will not be able to convert move_only_type to json, since you fully
        // specialized adl_serializer on that type
        static void to_json(json& j, move_only_type t) {
            j = t.i;
        }
    };
}
```

#### Can I write my own serializer? (Advanced use)

Yes. You might want to take a look at [`unit-udt.cpp`](https://github.com/nlohmann/json/blob/develop/test/src/unit-udt.cpp) in the test suite, to see a few examples.

If you write your own serializer, you'll need to do a few things:

- use a different `basic_json` alias than `nlohmann::json` (the last template parameter of `basic_json` is the `JSONSerializer`)
- use your `basic_json` alias (or a template parameter) in all your `to_json`/`from_json` methods
- use `nlohmann::to_json` and `nlohmann::from_json` when you need ADL

Here is an example, without simplifications, that only accepts types with a size <= 32, and uses ADL.

```cpp
// You should use void as a second template argument
// if you don't need compile-time checks on T
template<typename T, typename SFINAE = typename std::enable_if<sizeof(T) <= 32>::type>
struct less_than_32_serializer {
    template <typename BasicJsonType>
    static void to_json(BasicJsonType& j, T value) {
        // we want to use ADL, and call the correct to_json overload
        using nlohmann::to_json; // this method is called by adl_serializer,
                                 // this is where the magic happens
        to_json(j, value);
    }

    template <typename BasicJsonType>
    static void from_json(const BasicJsonType& j, T& value) {
        // same thing here
        using nlohmann::from_json;
        from_json(j, value);
    }
};
```

Be **very** careful when reimplementing your serializer, you can stack overflow if you don't pay attention:

```cpp
template <typename T, void>
struct bad_serializer
{
    template <typename BasicJsonType>
    static void to_json(BasicJsonType& j, const T& value) {
      // this calls BasicJsonType::json_serializer<T>::to_json(j, value);
      // if BasicJsonType::json_serializer == bad_serializer ... oops!
      j = value;
    }

    template <typename BasicJsonType>
    static void to_json(const BasicJsonType& j, T& value) {
      // this calls BasicJsonType::json_serializer<T>::from_json(j, value);
      // if BasicJsonType::json_serializer == bad_serializer ... oops!
      value = j.template get<T>(); // oops!
    }
};
```

### Binary formats (CBOR, MessagePack, and UBJSON)

Though JSON is a ubiquitous data format, it is not a very compact format suitable for data exchange, for instance over a network. Hence, the library supports [CBOR](http://cbor.io) (Concise Binary Object Representation), [MessagePack](http://msgpack.org), and [UBJSON](http://ubjson.org) (Universal Binary JSON Specification) to efficiently encode JSON values to byte vectors and to decode such vectors.

```cpp
// create a JSON value
json j = R"({"compact": true, "schema": 0})"_json;

// serialize to CBOR
std::vector<std::uint8_t> v_cbor = json::to_cbor(j);

// 0xA2, 0x67, 0x63, 0x6F, 0x6D, 0x70, 0x61, 0x63, 0x74, 0xF5, 0x66, 0x73, 0x63, 0x68, 0x65, 0x6D, 0x61, 0x00

// roundtrip
json j_from_cbor = json::from_cbor(v_cbor);

// serialize to MessagePack
std::vector<std::uint8_t> v_msgpack = json::to_msgpack(j);

// 0x82, 0xA7, 0x63, 0x6F, 0x6D, 0x70, 0x61, 0x63, 0x74, 0xC3, 0xA6, 0x73, 0x63, 0x68, 0x65, 0x6D, 0x61, 0x00

// roundtrip
json j_from_msgpack = json::from_msgpack(v_msgpack);

// serialize to UBJSON
std::vector<std::uint8_t> v_ubjson = json::to_ubjson(j);

// 0x7B, 0x69, 0x07, 0x63, 0x6F, 0x6D, 0x70, 0x61, 0x63, 0x74, 0x54, 0x69, 0x06, 0x73, 0x63, 0x68, 0x65, 0x6D, 0x61, 0x69, 0x00, 0x7D

// roundtrip
json j_from_ubjson = json::from_ubjson(v_ubjson);
```


## Supported compilers

Though it's 2018 already, the support for C++11 is still a bit sparse. Currently, the following compilers are known to work:

- GCC 4.9 - 8.2 (and possibly later)
- Clang 3.4 - 6.1 (and possibly later)
- Intel C++ Compiler 17.0.2 (and possibly later)
- Microsoft Visual C++ 2015 / Build Tools 14.0.25123.0 (and possibly later)
- Microsoft Visual C++ 2017 / Build Tools 15.5.180.51428 (and possibly later)

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

- Unsupported versions of GCC and Clang are rejected by `#error` directives. This can be switched off by defining `JSON_SKIP_UNSUPPORTED_COMPILER_CHECK`. Note that you can expect no support in this case.

The following compilers are currently used in continuous integration at [Travis](https://travis-ci.org/nlohmann/json) and [AppVeyor](https://ci.appveyor.com/project/nlohmann/json):

| Compiler        | Operating System             | Version String |
|-----------------|------------------------------|----------------|
| GCC 4.9.4       | Ubuntu 14.04.1 LTS           | g++-4.9 (Ubuntu 4.9.4-2ubuntu1~14.04.1) 4.9.4 |
| GCC 5.5.0       | Ubuntu 14.04.1 LTS           | g++-5 (Ubuntu 5.5.0-12ubuntu1~14.04) 5.5.0 20171010 |
| GCC 6.4.0       | Ubuntu 14.04.1 LTS           | g++-6 (Ubuntu 6.4.0-17ubuntu1~14.04) 6.4.0 20180424 |
| GCC 7.3.0       | Ubuntu 14.04.1 LTS           | g++-7 (Ubuntu 7.3.0-21ubuntu1~14.04) 7.3.0 |
| GCC 7.3.0       | Windows Server 2012 R2 (x64) | g++ (x86_64-posix-seh-rev0, Built by MinGW-W64 project) 7.3.0 |
| GCC 8.1.0       | Ubuntu 14.04.1 LTS           | g++-8 (Ubuntu 8.1.0-5ubuntu1~14.04) 8.1.0 |
| Clang 3.5.0     | Ubuntu 14.04.1 LTS           | clang version 3.5.0-4ubuntu2~trusty2 (tags/RELEASE_350/final) (based on LLVM 3.5.0) |
| Clang 3.6.2     | Ubuntu 14.04.1 LTS           | clang version 3.6.2-svn240577-1~exp1 (branches/release_36) (based on LLVM 3.6.2) |
| Clang 3.7.1     | Ubuntu 14.04.1 LTS           | clang version 3.7.1-svn253571-1~exp1 (branches/release_37) (based on LLVM 3.7.1) |
| Clang 3.8.0     | Ubuntu 14.04.1 LTS           | clang version 3.8.0-2ubuntu3~trusty5 (tags/RELEASE_380/final) |
| Clang 3.9.1     | Ubuntu 14.04.1 LTS           | clang version 3.9.1-4ubuntu3~14.04.3 (tags/RELEASE_391/rc2) |
| Clang 4.0.1     | Ubuntu 14.04.1 LTS           | clang version 4.0.1-svn305264-1~exp1 (branches/release_40) |
| Clang 5.0.2     | Ubuntu 14.04.1 LTS           | clang version 5.0.2-svn328729-1~exp1~20180509123505.100 (branches/release_50) |
| Clang 6.0.1     | Ubuntu 14.04.1 LTS           | clang version 6.0.1-svn334776-1~exp1~20180726133705.85 (branches/release_60) |
| Clang Xcode 6.4 | OSX 10.10.5 | Apple LLVM version 6.1.0 (clang-602.0.53) (based on LLVM 3.6.0svn) |
| Clang Xcode 7.3 | OSX 10.11.6 | Apple LLVM version 7.3.0 (clang-703.0.31) |
| Clang Xcode 8.0 | OSX 10.11.6 | Apple LLVM version 8.0.0 (clang-800.0.38) |
| Clang Xcode 8.1 | OSX 10.12.6 | Apple LLVM version 8.0.0 (clang-800.0.42.1) |
| Clang Xcode 8.2 | OSX 10.12.6 | Apple LLVM version 8.0.0 (clang-800.0.42.1) |
| Clang Xcode 8.3 | OSX 10.11.6 | Apple LLVM version 8.1.0 (clang-802.0.38) |
| Clang Xcode 9.0 | OSX 10.12.6 | Apple LLVM version 9.0.0 (clang-900.0.37) |
| Clang Xcode 9.1 | OSX 10.12.6 | Apple LLVM version 9.0.0 (clang-900.0.38) |
| Clang Xcode 9.2 | OSX 10.13.3 | Apple LLVM version 9.1.0 (clang-902.0.39.1) |
| Clang Xcode 9.3 | OSX 10.13.3 | Apple LLVM version 9.1.0 (clang-902.0.39.2) |
| Visual Studio 14 2015 | Windows Server 2012 R2 (x64) | Microsoft (R) Build Engine version 14.0.25420.1, MSVC 19.0.24215.1 |
| Visual Studio 2017 | Windows Server 2016 | Microsoft (R) Build Engine version 15.7.180.61344, MSVC 19.14.26433.0 |

## License

<img align="right" src="http://opensource.org/trademarks/opensource/OSI-Approved-License-100x137.png">

The class is licensed under the [MIT License](http://opensource.org/licenses/MIT):

Copyright &copy; 2013-2018 [Niels Lohmann](http://nlohmann.me)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

* * *

The class contains the UTF-8 Decoder from Bjoern Hoehrmann which is licensed under the [MIT License](http://opensource.org/licenses/MIT) (see above). Copyright &copy; 2008-2009 [Björn Hoehrmann](http://bjoern.hoehrmann.de/) <bjoern@hoehrmann.de>

The class contains a slightly modified version of the Grisu2 algorithm from Florian Loitsch which is licensed under the [MIT License](http://opensource.org/licenses/MIT) (see above). Copyright &copy; 2009 [Florian Loitsch](http://florian.loitsch.com/)

## Contact

If you have questions regarding the library, I would like to invite you to [open an issue at GitHub](https://github.com/nlohmann/json/issues/new). Please describe your request, problem, or question as detailed as possible, and also mention the version of the library you are using as well as the version of your compiler and operating system. Opening an issue at GitHub allows other users and contributors to this library to collaborate. For instance, I have little experience with MSVC, and most issues in this regard have been solved by a growing community. If you have a look at the [closed issues](https://github.com/nlohmann/json/issues?q=is%3Aissue+is%3Aclosed), you will see that we react quite timely in most cases.

Only if your request would contain confidential information, please [send me an email](mailto:mail@nlohmann.me). For encrypted messages, please use [this key](https://keybase.io/nlohmann/pgp_keys.asc).

## Security

[Commits by Niels Lohmann](https://github.com/nlohmann/json/commits) and [releases](https://github.com/nlohmann/json/releases) are signed with this [PGP Key](https://keybase.io/nlohmann/pgp_keys.asc?fingerprint=797167ae41c0a6d9232e48457f3cea63ae251b69).

## Thanks

I deeply appreciate the help of the following people.

![Contributors](https://raw.githubusercontent.com/nlohmann/json/develop/doc/avatars.png)

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
- [gregmarr](https://github.com/gregmarr) simplified the implementation of reverse iterators and helped with numerous hints and improvements. In particular, he pushed forward the implementation of user-defined types.
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
- [msm-](https://github.com/msm-) added support for American Fuzzy Lop.
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
- [Théo DELRIEU](https://github.com/theodelrieu) patiently and constructively oversaw the long way toward [iterator-range parsing](https://github.com/nlohmann/json/issues/290). He also implemented the magic behind the serialization/deserialization of user-defined types and split the single header file into smaller chunks.
- [Stefan](https://github.com/5tefan) fixed a minor issue in the documentation.
- [Vasil Dimov](https://github.com/vasild) fixed the documentation regarding conversions from `std::multiset`.
- [ChristophJud](https://github.com/ChristophJud) overworked the CMake files to ease project inclusion.
- [Vladimir Petrigo](https://github.com/vpetrigo) made a SFINAE hack more readable and added Visual Studio 17 to the build matrix.
- [Denis Andrejew](https://github.com/seeekr) fixed a grammar issue in the README file.
- [Pierre-Antoine Lacaze](https://github.com/palacaze) found a subtle bug in the `dump()` function.
- [TurpentineDistillery](https://github.com/TurpentineDistillery) pointed to [`std::locale::classic()`](https://en.cppreference.com/w/cpp/locale/locale/classic) to avoid too much locale joggling, found some nice performance improvements in the parser, improved the benchmarking code, and realized locale-independent number parsing and printing.
- [cgzones](https://github.com/cgzones) had an idea how to fix the Coverity scan.
- [Jared Grubb](https://github.com/jaredgrubb) silenced a nasty documentation warning.
- [Yixin Zhang](https://github.com/qwename) fixed an integer overflow check.
- [Bosswestfalen](https://github.com/Bosswestfalen) merged two iterator classes into a smaller one.
- [Daniel599](https://github.com/Daniel599) helped to get Travis execute the tests with Clang's sanitizers.
- [Jonathan Lee](https://github.com/vjon) fixed an example in the README file.
- [gnzlbg](https://github.com/gnzlbg) supported the implementation of user-defined types.
- [Alexej Harm](https://github.com/qis) helped to get the user-defined types working with Visual Studio.
- [Jared Grubb](https://github.com/jaredgrubb) supported the implementation of user-defined types.
- [EnricoBilla](https://github.com/EnricoBilla) noted a typo in an example.
- [Martin Hořeňovský](https://github.com/horenmar) found a way for a 2x speedup for the compilation time of the test suite.
- [ukhegg](https://github.com/ukhegg) found proposed an improvement for the examples section.
- [rswanson-ihi](https://github.com/rswanson-ihi) noted a typo in the README.
- [Mihai Stan](https://github.com/stanmihai4) fixed a bug in the comparison with `nullptr`s.
- [Tushar Maheshwari](https://github.com/tusharpm) added [cotire](https://github.com/sakra/cotire) support to speed up the compilation.
- [TedLyngmo](https://github.com/TedLyngmo) noted a typo in the README, removed unnecessary bit arithmetic, and fixed some `-Weffc++` warnings.
- [Krzysztof Woś](https://github.com/krzysztofwos) made exceptions more visible.
- [ftillier](https://github.com/ftillier) fixed a compiler warning.
- [tinloaf](https://github.com/tinloaf) made sure all pushed warnings are properly popped.
- [Fytch](https://github.com/Fytch) found a bug in the documentation.
- [Jay Sistar](https://github.com/Type1J) implemented a Meson build description.
- [Henry Lee](https://github.com/HenryRLee) fixed a warning in ICC and improved the iterator implementation.
- [Vincent Thiery](https://github.com/vthiery) maintains a package for the Conan package manager.
- [Steffen](https://github.com/koemeet) fixed a potential issue with MSVC and `std::min`.
- [Mike Tzou](https://github.com/Chocobo1) fixed some typos.
- [amrcode](https://github.com/amrcode) noted a misleading documentation about comparison of floats.
- [Oleg Endo](https://github.com/olegendo) reduced the memory consumption by replacing `<iostream>` with `<iosfwd>`.
- [dan-42](https://github.com/dan-42) cleaned up the CMake files to simplify including/reusing of the library.
- [Nikita Ofitserov](https://github.com/himikof) allowed for moving values from initializer lists.
- [Greg Hurrell](https://github.com/wincent) fixed a typo.
- [Dmitry Kukovinets](https://github.com/DmitryKuk) fixed a typo.
- [kbthomp1](https://github.com/kbthomp1) fixed an issue related to the Intel OSX compiler.
- [Markus Werle](https://github.com/daixtrose) fixed a typo.
- [WebProdPP](https://github.com/WebProdPP) fixed a subtle error in a precondition check.
- [Alex](https://github.com/leha-bot) noted an error in a code sample.
- [Tom de Geus](https://github.com/tdegeus) reported some warnings with ICC and helped fixing them.
- [Perry Kundert](https://github.com/pjkundert) simplified reading from input streams.
- [Sonu Lohani](https://github.com/sonulohani) fixed a small compilation error.
- [Jamie Seward](https://github.com/jseward) fixed all MSVC warnings.
- [Nate Vargas](https://github.com/eld00d) added a Doxygen tag file.
- [pvleuven](https://github.com/pvleuven) helped fixing a warning in ICC.
- [Pavel](https://github.com/crea7or) helped fixing some warnings in MSVC.
- [Jamie Seward](https://github.com/jseward) avoided unnecessary string copies in `find()` and `count()`.
- [Mitja](https://github.com/Itja) fixed some typos.
- [Jorrit Wronski](https://github.com/jowr) updated the Hunter package links.
- [Matthias Möller](https://github.com/TinyTinni) added a `.natvis` for the MSVC debug view.
- [bogemic](https://github.com/bogemic) fixed some C++17 deprecation warnings.
- [Eren Okka](https://github.com/erengy) fixed some MSVC warnings.
- [abolz](https://github.com/abolz) integrated the Grisu2 algorithm for proper floating-point formatting, allowing more roundtrip checks to succeed.
- [Vadim Evard](https://github.com/Pipeliner) fixed a Markdown issue in the README.
- [zerodefect](https://github.com/zerodefect) fixed a compiler warning.
- [Kert](https://github.com/kaidokert) allowed to template the string type in the serialization and added the possibility to override the exceptional behavior.
- [mark-99](https://github.com/mark-99) helped fixing an ICC error.
- [Patrik Huber](https://github.com/patrikhuber) fixed links in the README file.
- [johnfb](https://github.com/johnfb) found a bug in the implementation of CBOR's indefinite length strings.
- [Paul Fultz II](https://github.com/pfultz2) added a note on the cget package manager.
- [Wilson Lin](https://github.com/wla80) made the integration section of the README more concise.
- [RalfBielig](https://github.com/ralfbielig) detected and fixed a memory leak in the parser callback.
- [agrianius](https://github.com/agrianius) allowed to dump JSON to an alternative string type.
- [Kevin Tonon](https://github.com/ktonon) overworked the C++11 compiler checks in CMake.
- [Axel Huebl](https://github.com/ax3l) simplified a CMake check and added support for the [Spack package manager](https://spack.io).
- [Carlos O'Ryan](https://github.com/coryan) fixed a typo.
- [James Upjohn](https://github.com/jammehcow) fixed a version number in the compilers section.
- [Chuck Atkins](https://github.com/chuckatkins) adjusted the CMake files to the CMake packaging guidelines
- [Jan Schöppach](https://github.com/dns13) fixed a typo.
- [martin-mfg](https://github.com/martin-mfg) fixed a typo.
- [Matthias Möller](https://github.com/TinyTinni) removed the dependency from `std::stringstream`.
- [agrianius](https://github.com/agrianius) added code to use alternative string implementations.
- [Daniel599](https://github.com/Daniel599) allowed to use more algorithms with the `items()` function.
- [Julius Rakow](https://github.com/jrakow) fixed the Meson include directory and fixed the links to [cppreference.com](cppreference.com).
- [Sonu Lohani](https://github.com/sonulohani) fixed the compilation with MSVC 2015 in debug mode.
- [grembo](https://github.com/grembo) fixed the test suite and re-enabled several test cases.
- [Hyeon Kim](https://github.com/simnalamburt) introduced the macro `JSON_INTERNAL_CATCH` to control the exception handling inside the library.
- [thyu](https://github.com/thyu) fixed a compiler warning.

Thanks a lot for helping out! Please [let me know](mailto:mail@nlohmann.me) if I forgot someone.


## Used third-party tools

The library itself consists of a single header file licensed under the MIT license. However, it is built, tested, documented, and whatnot using a lot of third-party tools and services. Thanks a lot!

- [**amalgamate.py - Amalgamate C source and header files**](https://github.com/edlund/amalgamate) to create a single header file
- [**American fuzzy lop**](http://lcamtuf.coredump.cx/afl/) for fuzz testing
- [**AppVeyor**](https://www.appveyor.com) for [continuous integration](https://ci.appveyor.com/project/nlohmann/json) on Windows
- [**Artistic Style**](http://astyle.sourceforge.net) for automatic source code identation
- [**Catch**](https://github.com/philsquared/Catch) for the unit tests
- [**Clang**](http://clang.llvm.org) for compilation with code sanitizers
- [**Cmake**](https://cmake.org) for build automation
- [**Codacity**](https://www.codacy.com) for further [code analysis](https://www.codacy.com/app/nlohmann/json)
- [**Coveralls**](https://coveralls.io) to measure [code coverage](https://coveralls.io/github/nlohmann/json)
- [**Coverity Scan**](https://scan.coverity.com) for [static analysis](https://scan.coverity.com/projects/nlohmann-json)
- [**cppcheck**](http://cppcheck.sourceforge.net) for static analysis
- [**Doxygen**](http://www.stack.nl/~dimitri/doxygen/) to generate [documentation](https://nlohmann.github.io/json/)
- [**git-update-ghpages**](https://github.com/rstacruz/git-update-ghpages) to upload the documentation to gh-pages
- [**GitHub Changelog Generator**](https://github.com/skywinder/github-changelog-generator) to generate the [ChangeLog](https://github.com/nlohmann/json/blob/develop/ChangeLog.md)
- [**Google Benchmark**](https://github.com/google/benchmark) to implement the benchmarks
- [**libFuzzer**](http://llvm.org/docs/LibFuzzer.html) to implement fuzz testing for OSS-Fuzz
- [**OSS-Fuzz**](https://github.com/google/oss-fuzz) for continuous fuzz testing of the library ([project repository](https://github.com/google/oss-fuzz/tree/master/projects/json))
- [**Probot**](https://probot.github.io) for automating maintainer tasks such as closing stale issues, requesting missing information, or detecting toxic comments.
- [**send_to_wandbox**](https://github.com/nlohmann/json/blob/develop/doc/scripts/send_to_wandbox.py) to send code examples to [Wandbox](http://melpon.org/wandbox)
- [**Travis**](https://travis-ci.org) for [continuous integration](https://travis-ci.org/nlohmann/json) on Linux and macOS
- [**Valgrind**](http://valgrind.org) to check for correct memory management
- [**Wandbox**](http://melpon.org/wandbox) for [online examples](https://wandbox.org/permlink/TarF5pPn9NtHQjhf)


## Projects using JSON for Modern C++

The library is currently used in Apple macOS Sierra and iOS 10. I am not sure what they are using the library for, but I am happy that it runs on so many devices.


## Notes

- The code contains numerous debug **assertions** which can be switched off by defining the preprocessor macro `NDEBUG`, see the [documentation of `assert`](https://en.cppreference.com/w/cpp/error/assert). In particular, note [`operator[]`](https://nlohmann.github.io/json/classnlohmann_1_1basic__json_a2e26bd0b0168abb61f67ad5bcd5b9fa1.html#a2e26bd0b0168abb61f67ad5bcd5b9fa1) implements **unchecked access** for const objects: If the given key is not present, the behavior is undefined (think of a dereferenced null pointer) and yields an [assertion failure](https://github.com/nlohmann/json/issues/289) if assertions are switched on. If you are not sure whether an element in an object exists, use checked access with the [`at()` function](https://nlohmann.github.io/json/classnlohmann_1_1basic__json_a674de1ee73e6bf4843fc5dc1351fb726.html#a674de1ee73e6bf4843fc5dc1351fb726).
- As the exact type of a number is not defined in the [JSON specification](http://rfc7159.net/rfc7159), this library tries to choose the best fitting C++ number type automatically. As a result, the type `double` may be used to store numbers which may yield [**floating-point exceptions**](https://github.com/nlohmann/json/issues/181) in certain rare situations if floating-point exceptions have been unmasked in the calling code. These exceptions are not caused by the library and need to be fixed in the calling code, such as by re-masking the exceptions prior to calling library functions.
- The library supports **Unicode input** as follows:
  - Only **UTF-8** encoded input is supported which is the default encoding for JSON according to [RFC 7159](http://rfc7159.net/rfc7159#rfc.section.8.1).
  - Other encodings such as Latin-1, UTF-16, or UTF-32 are not supported and will yield parse or serialization errors.
  - [Unicode noncharacters](http://www.unicode.org/faq/private_use.html#nonchar1) will not be replaced by the library.
  - Invalid surrogates (e.g., incomplete pairs such as `\uDEAD`) will yield parse errors.
  - The strings stored in the library are UTF-8 encoded. When using the default string type (`std::string`), note that its length/size functions return the number of stored bytes rather than the number of characters or glyphs.
- The code can be compiled without C++ **runtime type identification** features; that is, you can use the `-fno-rtti` compiler flag.
- **Exceptions** are used widely within the library. They can, however, be switched off with either using the compiler flag `-fno-exceptions` or by defining the symbol `JSON_NOEXCEPTION`. In this case, exceptions are replaced by an `abort()` call.
- By default, the library does not preserve the **insertion order of object elements**. This is standards-compliant, as the [JSON standard](https://tools.ietf.org/html/rfc7159.html) defines objects as "an unordered collection of zero or more name/value pairs". If you do want to preserve the insertion order, you can specialize the object type with containers like [`tsl::ordered_map`](https://github.com/Tessil/ordered-map) ([integration](https://github.com/nlohmann/json/issues/546#issuecomment-304447518)) or [`nlohmann::fifo_map`](https://github.com/nlohmann/fifo_map) ([integration](https://github.com/nlohmann/json/issues/485#issuecomment-333652309)).


## Execute unit tests

To compile and run the tests, you need to execute

```sh
$ mkdir build
$ cd build
$ cmake ..
$ cmake --build .
$ ctest --output-on-failure
```

For more information, have a look at the file [.travis.yml](https://github.com/nlohmann/json/blob/master/.travis.yml).
