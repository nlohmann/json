[![JSON for Modern C++](docs/json.gif)](https://github.com/nlohmann/json/releases)

[![Build Status](https://ci.appveyor.com/api/projects/status/1acb366xfyg3qybk/branch/develop?svg=true)](https://ci.appveyor.com/project/nlohmann/json)
[![Ubuntu](https://github.com/nlohmann/json/workflows/Ubuntu/badge.svg)](https://github.com/nlohmann/json/actions?query=workflow%3AUbuntu)
[![macOS](https://github.com/nlohmann/json/workflows/macOS/badge.svg)](https://github.com/nlohmann/json/actions?query=workflow%3AmacOS)
[![Windows](https://github.com/nlohmann/json/workflows/Windows/badge.svg)](https://github.com/nlohmann/json/actions?query=workflow%3AWindows)
[![Coverage Status](https://coveralls.io/repos/github/nlohmann/json/badge.svg?branch=develop)](https://coveralls.io/github/nlohmann/json?branch=develop)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/5550/badge.svg)](https://scan.coverity.com/projects/nlohmann-json)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/e0d1a9d5d6fd46fcb655c4cb930bb3e8)](https://www.codacy.com/gh/nlohmann/json/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=nlohmann/json&amp;utm_campaign=Badge_Grade)
[![Language grade: C/C++](https://img.shields.io/lgtm/grade/cpp/g/nlohmann/json.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/nlohmann/json/context:cpp)
[![Fuzzing Status](https://oss-fuzz-build-logs.storage.googleapis.com/badges/json.svg)](https://bugs.chromium.org/p/oss-fuzz/issues/list?sort=-opened&can=1&q=proj:json)
[![Try online](https://img.shields.io/badge/try-online-blue.svg)](https://wandbox.org/permlink/1mp10JbaANo6FUc7)
[![Documentation](https://img.shields.io/badge/docs-mkdocs-blue.svg)](https://json.nlohmann.me)
[![GitHub license](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/nlohmann/json/master/LICENSE.MIT)
[![GitHub Releases](https://img.shields.io/github/release/nlohmann/json.svg)](https://github.com/nlohmann/json/releases)
[![Packaging status](https://repology.org/badge/tiny-repos/nlohmann-json.svg)](https://repology.org/project/nlohmann-json/versions)
[![GitHub Downloads](https://img.shields.io/github/downloads/nlohmann/json/total)](https://github.com/nlohmann/json/releases)
[![GitHub Issues](https://img.shields.io/github/issues/nlohmann/json.svg)](https://github.com/nlohmann/json/issues)
[![Average time to resolve an issue](https://isitmaintained.com/badge/resolution/nlohmann/json.svg)](https://isitmaintained.com/project/nlohmann/json "Average time to resolve an issue")
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/289/badge)](https://bestpractices.coreinfrastructure.org/projects/289)
[![GitHub Sponsors](https://img.shields.io/badge/GitHub-Sponsors-ff69b4)](https://github.com/sponsors/nlohmann)
[![REUSE status](https://api.reuse.software/badge/github.com/nlohmann/json)](https://api.reuse.software/info/github.com/nlohmann/json)
[![Discord](https://img.shields.io/discord/1003743314341793913)](https://discord.gg/6mrGXKvX7y)

- [Design goals](#design-goals)
- [Sponsors](#sponsors)
- [Support](#support) ([documentation](https://json.nlohmann.me), [FAQ](https://json.nlohmann.me/home/faq/), [discussions](https://github.com/nlohmann/json/discussions), [API](https://json.nlohmann.me/api/basic_json/), [bug issues](https://github.com/nlohmann/json/issues))
- [Examples](#examples)
  - [Read JSON from a file](#read-json-from-a-file)
  - [Creating `json` objects from JSON literals](#creating-json-objects-from-json-literals)
  - [JSON as first-class data type](#json-as-first-class-data-type)
  - [Serialization / Deserialization](#serialization--deserialization)
  - [STL-like access](#stl-like-access)
  - [Conversion from STL containers](#conversion-from-stl-containers)
  - [JSON Pointer and JSON Patch](#json-pointer-and-json-patch)
  - [JSON Merge Patch](#json-merge-patch)
  - [Implicit conversions](#implicit-conversions)
  - [Conversions to/from arbitrary types](#arbitrary-types-conversions)
  - [Specializing enum conversion](#specializing-enum-conversion)
  - [Binary formats (BSON, CBOR, MessagePack, UBJSON, and BJData)](#binary-formats-bson-cbor-messagepack-ubjson-and-bjdata)
- [Supported compilers](#supported-compilers)
- [Integration](#integration)
  - [CMake](#cmake)
  - [Package Managers](#package-managers)
  - [Pkg-config](#pkg-config)
- [License](#license)
- [Contact](#contact)
- [Thanks](#thanks)
- [Used third-party tools](#used-third-party-tools)
- [Projects using JSON for Modern C++](#projects-using-json-for-modern-c)
- [Notes](#notes)
- [Execute unit tests](#execute-unit-tests)

## Design goals

There are myriads of [JSON](https://json.org) libraries out there, and each may even have its reason to exist. Our class had these design goals:

- **Intuitive syntax**. In languages such as Python, JSON feels like a first class data type. We used all the operator magic of modern C++ to achieve the same feeling in your code. Check out the [examples below](#examples) and you'll know what I mean.

- **Trivial integration**. Our whole code consists of a single header file [`json.hpp`](https://github.com/nlohmann/json/blob/develop/single_include/nlohmann/json.hpp). That's it. No library, no subproject, no dependencies, no complex build system. The class is written in vanilla C++11. All in all, everything should require no adjustment of your compiler flags or project settings.

- **Serious testing**. Our code is heavily [unit-tested](https://github.com/nlohmann/json/tree/develop/tests/src) and covers [100%](https://coveralls.io/r/nlohmann/json) of the code, including all exceptional behavior. Furthermore, we checked with [Valgrind](https://valgrind.org) and the [Clang Sanitizers](https://clang.llvm.org/docs/index.html) that there are no memory leaks. [Google OSS-Fuzz](https://github.com/google/oss-fuzz/tree/master/projects/json) additionally runs fuzz tests against all parsers 24/7, effectively executing billions of tests so far. To maintain high quality, the project is following the [Core Infrastructure Initiative (CII) best practices](https://bestpractices.coreinfrastructure.org/projects/289).

Other aspects were not so important to us:

- **Memory efficiency**. Each JSON object has an overhead of one pointer (the maximal size of a union) and one enumeration element (1 byte). The default generalization uses the following C++ data types: `std::string` for strings, `int64_t`, `uint64_t` or `double` for numbers, `std::map` for objects, `std::vector` for arrays, and `bool` for Booleans. However, you can template the generalized class `basic_json` to your needs.

- **Speed**. There are certainly [faster JSON libraries](https://github.com/miloyip/nativejson-benchmark#parsing-time) out there. However, if your goal is to speed up your development by adding JSON support with a single header, then this library is the way to go. If you know how to use a `std::vector` or `std::map`, you are already set.

See the [contribution guidelines](https://github.com/nlohmann/json/blob/master/.github/CONTRIBUTING.md#please-dont) for more information.


## Sponsors

You can sponsor this library at [GitHub Sponsors](https://github.com/sponsors/nlohmann).

### :office: Corporate Sponsor

[![](https://upload.wikimedia.org/wikipedia/commons/thumb/9/9e/Codacy-logo-black.svg/320px-Codacy-logo-black.svg.png)](https://github.com/codacy/About)

### :label: Named Sponsors

- [Michael Hartmann](https://github.com/reFX-Mike)
- [Stefan Hagen](https://github.com/sthagen)
- [Steve Sperandeo](https://github.com/homer6)
- [Robert Jefe Lindstädt](https://github.com/eljefedelrodeodeljefe)
- [Steve Wagner](https://github.com/ciroque)

Thanks everyone!

## Support

:question: If you have a **question**, please check if it is already answered in the [**FAQ**](https://json.nlohmann.me/home/faq/) or the [**Q&A**](https://github.com/nlohmann/json/discussions/categories/q-a) section. If not, please [**ask a new question**](https://github.com/nlohmann/json/discussions/new) there.

:books: If you want to **learn more** about how to use the library, check out the rest of the [**README**](#examples), have a look at [**code examples**](https://github.com/nlohmann/json/tree/develop/docs/examples), or browse through the [**help pages**](https://json.nlohmann.me).

:construction: If you want to understand the **API** better, check out the [**API Reference**](https://json.nlohmann.me/api/basic_json/).

:bug: If you found a **bug**, please check the [**FAQ**](https://json.nlohmann.me/home/faq/) if it is a known issue or the result of a design decision. Please also have a look at the [**issue list**](https://github.com/nlohmann/json/issues) before you [**create a new issue**](https://github.com/nlohmann/json/issues/new/choose). Please provide as much information as possible to help us understand and reproduce your issue.

There is also a [**docset**](https://github.com/Kapeli/Dash-User-Contributions/tree/master/docsets/JSON_for_Modern_C%2B%2B) for the documentation browsers [Dash](https://kapeli.com/dash), [Velocity](https://velocity.silverlakesoftware.com), and [Zeal](https://zealdocs.org) that contains the full [documentation](https://json.nlohmann.me) as offline resource.

## Examples

Here are some examples to give you an idea how to use the class.

Beside the examples below, you may want to:

→ Check the [documentation](https://json.nlohmann.me/)\
→ Browse the [standalone example files](https://github.com/nlohmann/json/tree/develop/docs/examples)

Every API function (documented in the [API Documentation](https://json.nlohmann.me/api/basic_json/)) has a corresponding standalone example file. For example, the [`emplace()`](https://json.nlohmann.me/api/basic_json/emplace/) function has a matching [emplace.cpp](https://github.com/nlohmann/json/blob/develop/docs/examples/emplace.cpp) example file.

### Read JSON from a file

The `json` class provides an API for manipulating a JSON value. To create a `json` object by reading a JSON file:

```cpp
#include <fstream>
#include <nlohmann/json.hpp>
using json = nlohmann::json;

// ...

std::ifstream f("example.json");
json data = json::parse(f);
```

### Creating `json` objects from JSON literals

Assume you want to create hard-code this literal JSON value in a file, as a `json` object:

```json
{
  "pi": 3.141,
  "happy": true
}
```

There are various options:

```cpp
// Using (raw) string literals and json::parse
json ex1 = json::parse(R"(
  {
    "pi": 3.141,
    "happy": true
  }
)");

// Using user-defined (raw) string literals
using namespace nlohmann::literals;
json ex2 = R"(
  {
    "pi": 3.141,
    "happy": true
  }
)"_json;

// Using initializer lists
json ex3 = {
  {"happy", true},
  {"pi", 3.141},
};
```

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

Note that in all these cases, you never need to "tell" the compiler which JSON value type you want to use. If you want to be explicit or express some edge cases, the functions [`json::array()`](https://json.nlohmann.me/api/basic_json/array/) and [`json::object()`](https://json.nlohmann.me/api/basic_json/object/) will help:

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

Note that without appending the `_json` suffix, the passed string literal is not parsed, but just used as JSON string
value. That is, `json j = "{ \"happy\": true, \"pi\": 3.141 }"` would just store the string
`"{ "happy": true, "pi": 3.141 }"` rather than parsing the actual object.

The string literal should be brought into scope with `using namespace nlohmann::literals;`
(see [`json::parse()`](https://json.nlohmann.me/api/operator_literal_json/)).

The above example can also be expressed explicitly using [`json::parse()`](https://json.nlohmann.me/api/basic_json/parse/):

```cpp
// parse explicitly
auto j3 = json::parse(R"({"happy": true, "pi": 3.141})");
```

You can also get a string representation of a JSON value (serialize):

```cpp
// explicit conversion to string
std::string s = j.dump();    // {"happy":true,"pi":3.141}

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

// retrieve the string value
auto cpp_string = j_string.get<std::string>();
// retrieve the string value (alternative when a variable already exists)
std::string cpp_string2;
j_string.get_to(cpp_string2);

// retrieve the serialized value (explicit JSON serialization)
std::string serialized_string = j_string.dump();

// output of original string
std::cout << cpp_string << " == " << cpp_string2 << " == " << j_string.get<std::string>() << '\n';
// output of serialized value
std::cout << j_string << " == " << serialized_string << std::endl;
```

[`.dump()`](https://json.nlohmann.me/api/basic_json/dump/) returns the originally stored string value.

Note the library only supports UTF-8. When you store strings with different encodings in the library, calling [`dump()`](https://json.nlohmann.me/api/basic_json/dump/) may throw an exception unless `json::error_handler_t::replace` or `json::error_handler_t::ignore` are used as error handlers.

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

You can also parse JSON from an iterator range; that is, from any container accessible by iterators whose `value_type` is an integral type of 1, 2 or 4 bytes, which will be interpreted as UTF-8, UTF-16 and UTF-32 respectively. For instance, a `std::vector<std::uint8_t>`, or a `std::list<std::uint16_t>`:

```cpp
std::vector<std::uint8_t> v = {'t', 'r', 'u', 'e'};
json j = json::parse(v.begin(), v.end());
```

You may leave the iterators for the range [begin, end):

```cpp
std::vector<std::uint8_t> v = {'t', 'r', 'u', 'e'};
json j = json::parse(v);
```

#### Custom data source

Since the parse function accepts arbitrary iterator ranges, you can provide your own data sources by implementing the `LegacyInputIterator` concept.

```cpp
struct MyContainer {
  void advance();
  const char& get_current();
};

struct MyIterator {
    using difference_type = std::ptrdiff_t;
    using value_type = char;
    using pointer = const char*;
    using reference = const char&;
    using iterator_category = std::input_iterator_tag;

    MyIterator& operator++() {
        MyContainer.advance();
        return *this;
    }

    bool operator!=(const MyIterator& rhs) const {
        return rhs.target != target;
    }

    reference operator*() const {
        return target.get_current();
    }

    MyContainer* target = nullptr;
};

MyIterator begin(MyContainer& tgt) {
    return MyIterator{&tgt};
}

MyIterator end(const MyContainer&) {
    return {};
}

void foo() {
    MyContainer c;
    json j = json::parse(c);
}
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
// called when a binary value is parsed; value is passed and can be safely moved away
bool binary(binary_t& val);

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
const auto tmp = j[0].get<std::string>();
j[1] = 42;
bool foo = j.at(2);

// comparison
j == R"(["foo", 1, true, 1.78])"_json;  // true

// other stuff
j.size();     // 4 entries
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

// the same code as range for
for (auto& el : o.items()) {
  std::cout << el.key() << " : " << el.value() << "\n";
}

// even easier with structured bindings (C++17)
for (auto& [key, value] : o.items()) {
  std::cout << key << " : " << value << "\n";
}

// find an entry
if (o.contains("foo")) {
  // there is an entry with key "foo"
}

// or via find and an iterator
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

The library supports **JSON Pointer** ([RFC 6901](https://tools.ietf.org/html/rfc6901)) as alternative means to address structured values. On top of this, **JSON Patch** ([RFC 6902](https://tools.ietf.org/html/rfc6902)) allows describing differences between two JSON values - effectively allowing patch and diff operations known from Unix.

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
j_document.merge_patch(j_patch);
// {
//  "a": "z",
//  "c": {
//    "d": "e"
//  }
// }
```

### Implicit conversions

Supported types can be implicitly converted to JSON values.

It is recommended to **NOT USE** implicit conversions **FROM** a JSON value.
You can find more details about this recommendation [here](https://www.github.com/nlohmann/json/issues/958).
You can switch off implicit conversions by defining `JSON_USE_IMPLICIT_CONVERSIONS` to `0` before including the `json.hpp` header. When using CMake, you can also achieve this by setting the option `JSON_ImplicitConversions` to `OFF`.

```cpp
// strings
std::string s1 = "Hello, world!";
json js = s1;
auto s2 = js.get<std::string>();
// NOT RECOMMENDED
std::string s3 = js;
std::string s4;
s4 = js;

// Booleans
bool b1 = true;
json jb = b1;
auto b2 = jb.get<bool>();
// NOT RECOMMENDED
bool b3 = jb;
bool b4;
b4 = jb;

// numbers
int i = 42;
json jn = i;
auto f = jn.get<double>();
// NOT RECOMMENDED
double f2 = jb;
double f3;
f3 = jb;

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
auto p2 = j.get<ns::person>();

// that's it
assert(p == p2);
```

#### Basic usage

To make this work with one of your types, you only need to provide two functions:

```cpp
using json = nlohmann::json;

namespace ns {
    void to_json(json& j, const person& p) {
        j = json{{"name", p.name}, {"address", p.address}, {"age", p.age}};
    }

    void from_json(const json& j, person& p) {
        j.at("name").get_to(p.name);
        j.at("address").get_to(p.address);
        j.at("age").get_to(p.age);
    }
} // namespace ns
```

That's all! When calling the `json` constructor with your type, your custom `to_json` method will be automatically called.
Likewise, when calling `get<your_type>()` or `get_to(your_type&)`, the `from_json` method will be called.

Some important things:

* Those methods **MUST** be in your type's namespace (which can be the global namespace), or the library will not be able to locate them (in this example, they are in namespace `ns`, where `person` is defined).
* Those methods **MUST** be available (e.g., proper headers must be included) everywhere you use these conversions. Look at [issue 1108](https://github.com/nlohmann/json/issues/1108) for errors that may occur otherwise.
* When using `get<your_type>()`, `your_type` **MUST** be [DefaultConstructible](https://en.cppreference.com/w/cpp/named_req/DefaultConstructible). (There is a way to bypass this requirement described later.)
* In function `from_json`, use function [`at()`](https://json.nlohmann.me/api/basic_json/at/) to access the object values rather than `operator[]`. In case a key does not exist, `at` throws an exception that you can handle, whereas `operator[]` exhibits undefined behavior.
* You do not need to add serializers or deserializers for STL types like `std::vector`: the library already implements these.

#### Simplify your life with macros

If you just want to serialize/deserialize some structs, the `to_json`/`from_json` functions can be a lot of boilerplate.

There are two macros to make your life easier as long as you (1) want to use a JSON object as serialization and (2) want to use the member variable names as object keys in that object:

- `NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(name, member1, member2, ...)` is to be defined inside the namespace of the class/struct to create code for.
- `NLOHMANN_DEFINE_TYPE_INTRUSIVE(name, member1, member2, ...)` is to be defined inside the class/struct to create code for. This macro can also access private members.

In both macros, the first parameter is the name of the class/struct, and all remaining parameters name the members.

##### Examples

The `to_json`/`from_json` functions for the `person` struct above can be created with:

```cpp
namespace ns {
    NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(person, name, address, age)
}
```

Here is an example with private members, where `NLOHMANN_DEFINE_TYPE_INTRUSIVE` is needed:

```cpp
namespace ns {
    class address {
      private:
        std::string street;
        int housenumber;
        int postcode;

      public:
        NLOHMANN_DEFINE_TYPE_INTRUSIVE(address, street, housenumber, postcode)
    };
}
```

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

        // Here's the catch! You must provide a to_json method! Otherwise, you
        // will not be able to convert move_only_type to json, since you fully
        // specialized adl_serializer on that type
        static void to_json(json& j, move_only_type t) {
            j = t.i;
        }
    };
}
```

#### Can I write my own serializer? (Advanced use)

Yes. You might want to take a look at [`unit-udt.cpp`](https://github.com/nlohmann/json/blob/develop/tests/src/unit-udt.cpp) in the test suite, to see a few examples.

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

### Specializing enum conversion

By default, enum values are serialized to JSON as integers. In some cases this could result in undesired behavior. If an enum is modified or re-ordered after data has been serialized to JSON, the later de-serialized JSON data may be undefined or a different enum value than was originally intended.

It is possible to more precisely specify how a given enum is mapped to and from JSON as shown below:

```cpp
// example enum type declaration
enum TaskState {
    TS_STOPPED,
    TS_RUNNING,
    TS_COMPLETED,
    TS_INVALID=-1,
};

// map TaskState values to JSON as strings
NLOHMANN_JSON_SERIALIZE_ENUM( TaskState, {
    {TS_INVALID, nullptr},
    {TS_STOPPED, "stopped"},
    {TS_RUNNING, "running"},
    {TS_COMPLETED, "completed"},
})
```

The `NLOHMANN_JSON_SERIALIZE_ENUM()` macro declares a set of `to_json()` / `from_json()` functions for type `TaskState` while avoiding repetition and boilerplate serialization code.

**Usage:**

```cpp
// enum to JSON as string
json j = TS_STOPPED;
assert(j == "stopped");

// json string to enum
json j3 = "running";
assert(j3.get<TaskState>() == TS_RUNNING);

// undefined json value to enum (where the first map entry above is the default)
json jPi = 3.14;
assert(jPi.get<TaskState>() == TS_INVALID );
```

Just as in [Arbitrary Type Conversions](#arbitrary-types-conversions) above,
- `NLOHMANN_JSON_SERIALIZE_ENUM()` MUST be declared in your enum type's namespace (which can be the global namespace), or the library will not be able to locate it, and it will default to integer serialization.
- It MUST be available (e.g., proper headers must be included) everywhere you use the conversions.

Other Important points:
- When using `get<ENUM_TYPE>()`, undefined JSON values will default to the first pair specified in your map. Select this default pair carefully.
- If an enum or JSON value is specified more than once in your map, the first matching occurrence from the top of the map will be returned when converting to or from JSON.

### Binary formats (BSON, CBOR, MessagePack, UBJSON, and BJData)

Though JSON is a ubiquitous data format, it is not a very compact format suitable for data exchange, for instance over a network. Hence, the library supports [BSON](https://bsonspec.org) (Binary JSON), [CBOR](https://cbor.io) (Concise Binary Object Representation), [MessagePack](https://msgpack.org), [UBJSON](https://ubjson.org) (Universal Binary JSON Specification) and [BJData](https://neurojson.org/bjdata) (Binary JData) to efficiently encode JSON values to byte vectors and to decode such vectors.

```cpp
// create a JSON value
json j = R"({"compact": true, "schema": 0})"_json;

// serialize to BSON
std::vector<std::uint8_t> v_bson = json::to_bson(j);

// 0x1B, 0x00, 0x00, 0x00, 0x08, 0x63, 0x6F, 0x6D, 0x70, 0x61, 0x63, 0x74, 0x00, 0x01, 0x10, 0x73, 0x63, 0x68, 0x65, 0x6D, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00

// roundtrip
json j_from_bson = json::from_bson(v_bson);

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

The library also supports binary types from BSON, CBOR (byte strings), and MessagePack (bin, ext, fixext). They are stored by default as `std::vector<std::uint8_t>` to be processed outside the library.

```cpp
// CBOR byte string with payload 0xCAFE
std::vector<std::uint8_t> v = {0x42, 0xCA, 0xFE};

// read value
json j = json::from_cbor(v);

// the JSON value has type binary
j.is_binary(); // true

// get reference to stored binary value
auto& binary = j.get_binary();

// the binary value has no subtype (CBOR has no binary subtypes)
binary.has_subtype(); // false

// access std::vector<std::uint8_t> member functions
binary.size(); // 2
binary[0]; // 0xCA
binary[1]; // 0xFE

// set subtype to 0x10
binary.set_subtype(0x10);

// serialize to MessagePack
auto cbor = json::to_msgpack(j); // 0xD5 (fixext2), 0x10, 0xCA, 0xFE
```


## Supported compilers

Though it's 2022 already, the support for C++11 is still a bit sparse. Currently, the following compilers are known to work:

- GCC 4.8 - 12.0 (and possibly later)
- Clang 3.4 - 15.0 (and possibly later)
- Apple Clang 9.1 - 13.1 (and possibly later)
- Intel C++ Compiler 17.0.2 (and possibly later)
- Nvidia CUDA Compiler 11.0.221 (and possibly later)
- Microsoft Visual C++ 2015 / Build Tools 14.0.25123.0 (and possibly later)
- Microsoft Visual C++ 2017 / Build Tools 15.5.180.51428 (and possibly later)
- Microsoft Visual C++ 2019 / Build Tools 16.3.1+1def00d3d (and possibly later)
- Microsoft Visual C++ 2022 / Build Tools 19.30.30709.0 (and possibly later)

I would be happy to learn about other compilers/versions.

Please note:

- GCC 4.8 has a bug [57824](https://gcc.gnu.org/bugzilla/show_bug.cgi?id=57824)): multiline raw strings cannot be the arguments to macros. Don't use multiline raw strings directly in macros with this compiler.
- Android defaults to using very old compilers and C++ libraries. To fix this, add the following to your `Application.mk`. This will switch to the LLVM C++ library, the Clang compiler, and enable C++11 and other features disabled by default.

    ```
    APP_STL := c++_shared
    NDK_TOOLCHAIN_VERSION := clang3.6
    APP_CPPFLAGS += -frtti -fexceptions
    ```

    The code compiles successfully with [Android NDK](https://developer.android.com/ndk/index.html?hl=ml), Revision 9 - 11 (and possibly later) and [CrystaX's Android NDK](https://www.crystax.net/en/android/ndk) version 10.

- For GCC running on MinGW or Android SDK, the error `'to_string' is not a member of 'std'` (or similarly, for `strtod` or `strtof`) may occur. Note this is not an issue with the code,  but rather with the compiler itself. On Android, see above to build with a newer environment.  For MinGW, please refer to [this site](https://tehsausage.com/mingw-to-string) and [this discussion](https://github.com/nlohmann/json/issues/136) for information on how to fix this bug. For Android NDK using `APP_STL := gnustl_static`, please refer to [this discussion](https://github.com/nlohmann/json/issues/219).

- Unsupported versions of GCC and Clang are rejected by `#error` directives. This can be switched off by defining `JSON_SKIP_UNSUPPORTED_COMPILER_CHECK`. Note that you can expect no support in this case.

The following compilers are currently used in continuous integration at [AppVeyor](https://ci.appveyor.com/project/nlohmann/json), [Drone CI](https://cloud.drone.io/nlohmann/json), and [GitHub Actions](https://github.com/nlohmann/json/actions):

| Compiler                                                                                               | Operating System   | CI Provider    |
|--------------------------------------------------------------------------------------------------------|--------------------|----------------|
| Apple Clang 11.0.3 (clang-1103.0.32.62);  Xcode 11.7                                                   | macOS 11.7.1       | GitHub Actions |
| Apple Clang 12.0.0 (clang-1200.0.32.29);  Xcode 12.4                                                   | macOS 11.7.1       | GitHub Actions |
| Apple Clang 12.0.5 (clang-1205.0.22.11);  Xcode 12.5.1                                                 | macOS 11.7.1       | GitHub Actions |
| Apple Clang 13.0.0 (clang-1300.0.29.3);   Xcode 13.0                                                   | macOS 11.7.1       | GitHub Actions |
| Apple Clang 13.0.0 (clang-1300.0.29.3);   Xcode 13.1                                                   | macOS 12.6.1       | GitHub Actions |
| Apple Clang 13.0.0 (clang-1300.0.29.30);  Xcode 13.2.1                                                 | macOS 12.6.1       | GitHub Actions |
| Apple Clang 13.1.6 (clang-1316.0.21.2.3); Xcode 13.3.1                                                 | macOS 12.6.1       | GitHub Actions |
| Apple Clang 13.1.6 (clang-1316.0.21.2.5); Xcode 13.4.1                                                 | macOS 12.6.1       | GitHub Actions |
| Apple Clang 14.0.0 (clang-1400.0.29.102); Xcode 14.0                                                   | macOS 12.6.1       | GitHub Actions |
| Apple Clang 14.0.0 (clang-1400.0.29.102); Xcode 14.0.1                                                 | macOS 12.6.1       | GitHub Actions |
| Apple Clang 14.0.0 (clang-1400.0.29.202); Xcode 14.1                                                   | macOS 12.6.1       | GitHub Actions |
| Clang 3.5.2                                                                                            | Ubuntu 20.04.3 LTS | GitHub Actions |
| Clang 3.6.2                                                                                            | Ubuntu 20.04.3 LTS | GitHub Actions |
| Clang 3.7.1                                                                                            | Ubuntu 20.04.3 LTS | GitHub Actions |
| Clang 3.8.1                                                                                            | Ubuntu 20.04.3 LTS | GitHub Actions |
| Clang 3.9.1                                                                                            | Ubuntu 20.04.3 LTS | GitHub Actions |
| Clang 4.0.1                                                                                            | Ubuntu 20.04.3 LTS | GitHub Actions |
| Clang 5.0.2                                                                                            | Ubuntu 20.04.3 LTS | GitHub Actions |
| Clang 6.0.1                                                                                            | Ubuntu 20.04.3 LTS | GitHub Actions |
| Clang 7.0.1                                                                                            | Ubuntu 20.04.3 LTS | GitHub Actions |
| Clang 8.0.0                                                                                            | Ubuntu 20.04.3 LTS | GitHub Actions |
| Clang 9.0.0                                                                                            | Ubuntu 20.04.3 LTS | GitHub Actions |
| Clang 10.0.0                                                                                           | Ubuntu 20.04.3 LTS | GitHub Actions |
| Clang 10.0.0 with GNU-like command-line                                                                | Windows-10.0.17763 | GitHub Actions |
| Clang 11.0.0 with GNU-like command-line                                                                | Windows-10.0.17763 | GitHub Actions |
| Clang 11.0.0 with MSVC-like command-line                                                               | Windows-10.0.17763 | GitHub Actions |
| Clang 11.0.0                                                                                           | Ubuntu 20.04.3 LTS | GitHub Actions |
| Clang 12.0.0                                                                                           | Ubuntu 20.04.3 LTS | GitHub Actions |
| Clang 13.0.0                                                                                           | Ubuntu 20.04.3 LTS | GitHub Actions |
| Clang 14.0.0                                                                                           | Ubuntu 20.04.3 LTS | GitHub Actions |
| Clang 15.0.4                                                                                           | Ubuntu 20.04.3 LTS | GitHub Actions |
| Clang 16.0.0 (16.0.0-++20221031071727+500876226c60-1~exp1~20221031071831.439)                          | Ubuntu 20.04.3 LTS | GitHub Actions |
| GCC 4.8.5 (Ubuntu 4.8.5-4ubuntu2)                                                                      | Ubuntu 20.04.3 LTS | GitHub Actions |
| GCC 4.9.4                                                                                              | Ubuntu 20.04.3 LTS | GitHub Actions |
| GCC 5.5.0                                                                                              | Ubuntu 20.04.3 LTS | GitHub Actions |
| GCC 6.5.0                                                                                              | Ubuntu 20.04.3 LTS | GitHub Actions |
| GCC 7.5.0                                                                                              | Ubuntu 20.04.3 LTS | GitHub Actions |
| GCC 8.1.0 (i686-posix-dwarf-rev0, Built by MinGW-W64 project)                                          | Windows-10.0.17763 | GitHub Actions |
| GCC 8.1.0 (x86_64-posix-seh-rev0, Built by MinGW-W64 project)                                          | Windows-10.0.17763 | GitHub Actions |
| GCC 8.5.0                                                                                              | Ubuntu 20.04.3 LTS | GitHub Actions |
| GCC 9.5.0                                                                                              | Ubuntu 20.04.3 LTS | GitHub Actions |
| GCC 10.4.0                                                                                             | Ubuntu 20.04.3 LTS | GitHub Actions |
| GCC 11.1.0                                                                                             | Ubuntu (aarch64)   | Drone CI       |
| GCC 11.3.0                                                                                             | Ubuntu 20.04.3 LTS | GitHub Actions |
| GCC 12.2.0                                                                                             | Ubuntu 20.04.3 LTS | GitHub Actions |
| GCC 13.0.0 20220605 (experimental)                                                                     | Ubuntu 20.04.3 LTS | GitHub Actions |
| Intel C++ Compiler 2021.5.0.20211109                                                                   | Ubuntu 20.04.3 LTS | GitHub Actions |
| NVCC 11.0.221                                                                                          | Ubuntu 20.04.3 LTS | GitHub Actions |
| Visual Studio 14 2015 MSVC 19.0.24241.7 (Build Engine version 14.0.25420.1)                            | Windows-6.3.9600   | AppVeyor       |
| Visual Studio 15 2017 MSVC 19.16.27035.0 (Build Engine version 15.9.21+g9802d43bc3 for .NET Framework) | Windows-10.0.14393 | AppVeyor       |
| Visual Studio 16 2019 MSVC 19.28.29912.0 (Build Engine version 16.9.0+57a23d249 for .NET Framework)    | Windows-10.0.17763 | GitHub Actions |
| Visual Studio 16 2019 MSVC 19.28.29912.0 (Build Engine version 16.9.0+57a23d249 for .NET Framework)    | Windows-10.0.17763 | AppVeyor       |
| Visual Studio 17 2022 MSVC 19.30.30709.0 (Build Engine version 17.0.31804.368 for .NET Framework)      | Windows-10.0.20348 | GitHub Actions |


## Integration

[`json.hpp`](https://github.com/nlohmann/json/blob/develop/single_include/nlohmann/json.hpp) is the single required file in `single_include/nlohmann` or [released here](https://github.com/nlohmann/json/releases). You need to add

```cpp
#include <nlohmann/json.hpp>

// for convenience
using json = nlohmann::json;
```

to the files you want to process JSON and set the necessary switches to enable C++11 (e.g., `-std=c++11` for GCC and Clang).

You can further use file [`include/nlohmann/json_fwd.hpp`](https://github.com/nlohmann/json/blob/develop/include/nlohmann/json_fwd.hpp) for forward-declarations. The installation of json_fwd.hpp (as part of cmake's install step), can be achieved by setting `-DJSON_MultipleHeaders=ON`.

### CMake

You can also use the `nlohmann_json::nlohmann_json` interface target in CMake.  This target populates the appropriate usage requirements for `INTERFACE_INCLUDE_DIRECTORIES` to point to the appropriate include directories and `INTERFACE_COMPILE_FEATURES` for the necessary C++11 flags.

#### External

To use this library from a CMake project, you can locate it directly with `find_package()` and use the namespaced imported target from the generated package configuration:

```cmake
# CMakeLists.txt
find_package(nlohmann_json 3.2.0 REQUIRED)
...
add_library(foo ...)
...
target_link_libraries(foo PRIVATE nlohmann_json::nlohmann_json)
```

The package configuration file, `nlohmann_jsonConfig.cmake`, can be used either from an install tree or directly out of the build tree.

#### Embedded

To embed the library directly into an existing CMake project, place the entire source tree in a subdirectory and call `add_subdirectory()` in your `CMakeLists.txt` file:

```cmake
# Typically you don't care so much for a third party library's tests to be
# run from your own project's code.
set(JSON_BuildTests OFF CACHE INTERNAL "")

# If you only include this third party in PRIVATE source files, you do not
# need to install it when your main project gets installed.
# set(JSON_Install OFF CACHE INTERNAL "")

# Don't use include(nlohmann_json/CMakeLists.txt) since that carries with it
# unintended consequences that will break the build.  It's generally
# discouraged (although not necessarily well documented as such) to use
# include(...) for pulling in other CMake projects anyways.
add_subdirectory(nlohmann_json)
...
add_library(foo ...)
...
target_link_libraries(foo PRIVATE nlohmann_json::nlohmann_json)
```

##### Embedded (FetchContent)

Since CMake v3.11,
[FetchContent](https://cmake.org/cmake/help/v3.11/module/FetchContent.html) can
be used to automatically download a release as a dependency at configure time.

Example:
```cmake
include(FetchContent)

FetchContent_Declare(json URL https://github.com/nlohmann/json/releases/download/v3.11.2/json.tar.xz)
FetchContent_MakeAvailable(json)

target_link_libraries(foo PRIVATE nlohmann_json::nlohmann_json)
```

**Note**: It is recommended to use the URL approach described above which is supported as of version 3.10.0. See
<https://json.nlohmann.me/integration/cmake/#fetchcontent> for more information.

#### Supporting Both

To allow your project to support either an externally supplied or an embedded JSON library, you can use a pattern akin to the following:

``` cmake
# Top level CMakeLists.txt
project(FOO)
...
option(FOO_USE_EXTERNAL_JSON "Use an external JSON library" OFF)
...
add_subdirectory(thirdparty)
...
add_library(foo ...)
...
# Note that the namespaced target will always be available regardless of the
# import method
target_link_libraries(foo PRIVATE nlohmann_json::nlohmann_json)
```
```cmake
# thirdparty/CMakeLists.txt
...
if(FOO_USE_EXTERNAL_JSON)
  find_package(nlohmann_json 3.2.0 REQUIRED)
else()
  set(JSON_BuildTests OFF CACHE INTERNAL "")
  add_subdirectory(nlohmann_json)
endif()
...
```

`thirdparty/nlohmann_json` is then a complete copy of this source tree.

### Package Managers

:beer: If you are using OS X and [Homebrew](https://brew.sh), just type `brew install nlohmann-json` and you're set. If you want the bleeding edge rather than the latest release, use `brew install nlohmann-json --HEAD`. See [nlohmann-json](https://formulae.brew.sh/formula/nlohmann-json) for more information.

If you are using the [Meson Build System](https://mesonbuild.com), add this source tree as a [meson subproject](https://mesonbuild.com/Subprojects.html#using-a-subproject). You may also use the `include.zip` published in this project's [Releases](https://github.com/nlohmann/json/releases) to reduce the size of the vendored source tree. Alternatively, you can get a wrap file by downloading it from [Meson WrapDB](https://wrapdb.mesonbuild.com/nlohmann_json), or simply use `meson wrap install nlohmann_json`. Please see the meson project for any issues regarding the packaging.

The provided `meson.build` can also be used as an alternative to CMake for installing `nlohmann_json` system-wide in which case a pkg-config file is installed. To use it, simply have your build system require the `nlohmann_json` pkg-config dependency. In Meson, it is preferred to use the [`dependency()`](https://mesonbuild.com/Reference-manual.html#dependency) object with a subproject fallback, rather than using the subproject directly.

If you are using [Bazel](https://bazel.build/) you can simply reference this repository using `http_archive` or `git_repository` and depend on `@nlohmann_json//:json`.

If you are using [Conan](https://www.conan.io/) to manage your dependencies, merely add [`nlohmann_json/x.y.z`](https://conan.io/center/nlohmann_json) to your `conanfile`'s requires, where `x.y.z` is the release version you want to use. Please file issues [here](https://github.com/conan-io/conan-center-index/issues) if you experience problems with the packages.

If you are using [Spack](https://www.spack.io/) to manage your dependencies, you can use the [`nlohmann-json` package](https://spack.readthedocs.io/en/latest/package_list.html#nlohmann-json). Please see the [spack project](https://github.com/spack/spack) for any issues regarding the packaging.

If you are using [hunter](https://github.com/cpp-pm/hunter) on your project for external dependencies, then you can use the [nlohmann_json package](https://hunter.readthedocs.io/en/latest/packages/pkg/nlohmann_json.html). Please see the hunter project for any issues regarding the packaging.

If you are using [Buckaroo](https://buckaroo.pm), you can install this library's module with `buckaroo add github.com/buckaroo-pm/nlohmann-json`. Please file issues [here](https://github.com/buckaroo-pm/nlohmann-json). There is a demo repo [here](https://github.com/njlr/buckaroo-nholmann-json-example).

If you are using [vcpkg](https://github.com/Microsoft/vcpkg/) on your project for external dependencies, then you can install the [nlohmann-json package](https://github.com/Microsoft/vcpkg/tree/master/ports/nlohmann-json) with `vcpkg install nlohmann-json` and follow the then displayed descriptions. Please see the vcpkg project for any issues regarding the packaging.

If you are using [cget](https://cget.readthedocs.io/en/latest/), you can install the latest development version with `cget install nlohmann/json`. A specific version can be installed with `cget install nlohmann/json@v3.1.0`. Also, the multiple header version can be installed by adding the `-DJSON_MultipleHeaders=ON` flag (i.e., `cget install nlohmann/json -DJSON_MultipleHeaders=ON`).

If you are using [CocoaPods](https://cocoapods.org), you can use the library by adding pod `"nlohmann_json", '~>3.1.2'` to your podfile (see [an example](https://bitbucket.org/benman/nlohmann_json-cocoapod/src/master/)). Please file issues [here](https://bitbucket.org/benman/nlohmann_json-cocoapod/issues?status=new&status=open).

If you are using [NuGet](https://www.nuget.org), you can use the package [nlohmann.json](https://www.nuget.org/packages/nlohmann.json/). Please check [this extensive description](https://github.com/nlohmann/json/issues/1132#issuecomment-452250255) on how to use the package. Please file issues [here](https://github.com/hnkb/nlohmann-json-nuget/issues).

If you are using [conda](https://conda.io/), you can use the package [nlohmann_json](https://github.com/conda-forge/nlohmann_json-feedstock) from [conda-forge](https://conda-forge.org) executing `conda install -c conda-forge nlohmann_json`. Please file issues [here](https://github.com/conda-forge/nlohmann_json-feedstock/issues).

If you are using [MSYS2](https://www.msys2.org/), you can use the [mingw-w64-nlohmann-json](https://packages.msys2.org/base/mingw-w64-nlohmann-json) package, just type `pacman -S mingw-w64-i686-nlohmann-json` or `pacman -S mingw-w64-x86_64-nlohmann-json` for installation. Please file issues [here](https://github.com/msys2/MINGW-packages/issues/new?title=%5Bnlohmann-json%5D) if you experience problems with the packages.

If you are using [MacPorts](https://ports.macports.org), execute `sudo port install nlohmann-json` to install the [nlohmann-json](https://ports.macports.org/port/nlohmann-json/) package.

If you are using [`build2`](https://build2.org), you can use the [`nlohmann-json`](https://cppget.org/nlohmann-json) package from the public repository https://cppget.org or directly from the [package's sources repository](https://github.com/build2-packaging/nlohmann-json). In your project's `manifest` file, just add `depends: nlohmann-json` (probably with some [version constraints](https://build2.org/build2-toolchain/doc/build2-toolchain-intro.xhtml#guide-add-remove-deps)). If you are not familiar with using dependencies in `build2`, [please read this introduction](https://build2.org/build2-toolchain/doc/build2-toolchain-intro.xhtml).
Please file issues [here](https://github.com/build2-packaging/nlohmann-json) if you experience problems with the packages.

If you are using [`wsjcpp`](https://wsjcpp.org), you can use the command `wsjcpp install "https://github.com/nlohmann/json:develop"` to get the latest version. Note you can change the branch ":develop" to an existing tag or another branch.

If you are using [`CPM.cmake`](https://github.com/TheLartians/CPM.cmake), you can check this [`example`](https://github.com/TheLartians/CPM.cmake/tree/master/examples/json). After [adding CPM script](https://github.com/TheLartians/CPM.cmake#adding-cpm) to your project, implement the following snippet to your CMake:

```cmake
CPMAddPackage(
    NAME nlohmann_json
    GITHUB_REPOSITORY nlohmann/json
    VERSION 3.9.1)
```

### Pkg-config

If you are using bare Makefiles, you can use `pkg-config` to generate the include flags that point to where the library is installed:

```sh
pkg-config nlohmann_json --cflags
```

Users of the Meson build system will also be able to use a system-wide library, which will be found by `pkg-config`:

```meson
json = dependency('nlohmann_json', required: true)
```


## License

<img align="right" src="https://opensource.org/trademarks/opensource/OSI-Approved-License-100x137.png">

The class is licensed under the [MIT License](https://opensource.org/licenses/MIT):

Copyright &copy; 2013-2022 [Niels Lohmann](https://nlohmann.me)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

* * *

The class contains the UTF-8 Decoder from Bjoern Hoehrmann which is licensed under the [MIT License](https://opensource.org/licenses/MIT) (see above). Copyright &copy; 2008-2009 [Björn Hoehrmann](https://bjoern.hoehrmann.de/) <bjoern@hoehrmann.de>

The class contains a slightly modified version of the Grisu2 algorithm from Florian Loitsch which is licensed under the [MIT License](https://opensource.org/licenses/MIT) (see above). Copyright &copy; 2009 [Florian Loitsch](https://florian.loitsch.com/)

The class contains a copy of [Hedley](https://nemequ.github.io/hedley/) from Evan Nemerson which is licensed as [CC0-1.0](https://creativecommons.org/publicdomain/zero/1.0/).

The class contains parts of [Google Abseil](https://github.com/abseil/abseil-cpp) which is licensed under the [Apache 2.0 License](https://opensource.org/licenses/Apache-2.0).

## Contact

If you have questions regarding the library, I would like to invite you to [open an issue at GitHub](https://github.com/nlohmann/json/issues/new/choose). Please describe your request, problem, or question as detailed as possible, and also mention the version of the library you are using as well as the version of your compiler and operating system. Opening an issue at GitHub allows other users and contributors to this library to collaborate. For instance, I have little experience with MSVC, and most issues in this regard have been solved by a growing community. If you have a look at the [closed issues](https://github.com/nlohmann/json/issues?q=is%3Aissue+is%3Aclosed), you will see that we react quite timely in most cases.

Only if your request would contain confidential information, please [send me an email](mailto:mail@nlohmann.me). For encrypted messages, please use [this key](https://keybase.io/nlohmann/pgp_keys.asc).

## Security

[Commits by Niels Lohmann](https://github.com/nlohmann/json/commits) and [releases](https://github.com/nlohmann/json/releases) are signed with this [PGP Key](https://keybase.io/nlohmann/pgp_keys.asc?fingerprint=797167ae41c0a6d9232e48457f3cea63ae251b69).

## Thanks

I deeply appreciate the help of the following people.

<img src="https://raw.githubusercontent.com/nlohmann/json/develop/docs/avatars.png" align="right">

1. [Teemperor](https://github.com/Teemperor) implemented CMake support and lcov integration, realized escape and Unicode handling in the string parser, and fixed the JSON serialization.
2. [elliotgoodrich](https://github.com/elliotgoodrich) fixed an issue with double deletion in the iterator classes.
3. [kirkshoop](https://github.com/kirkshoop) made the iterators of the class composable to other libraries.
4. [wancw](https://github.com/wanwc) fixed a bug that hindered the class to compile with Clang.
5. Tomas Åblad found a bug in the iterator implementation.
6. [Joshua C. Randall](https://github.com/jrandall) fixed a bug in the floating-point serialization.
7. [Aaron Burghardt](https://github.com/aburgh) implemented code to parse streams incrementally. Furthermore, he greatly improved the parser class by allowing the definition of a filter function to discard undesired elements while parsing.
8. [Daniel Kopeček](https://github.com/dkopecek) fixed a bug in the compilation with GCC 5.0.
9. [Florian Weber](https://github.com/Florianjw) fixed a bug in and improved the performance of the comparison operators.
10. [Eric Cornelius](https://github.com/EricMCornelius) pointed out a bug in the handling with NaN and infinity values. He also improved the performance of the string escaping.
11. [易思龙](https://github.com/likebeta) implemented a conversion from anonymous enums.
12. [kepkin](https://github.com/kepkin) patiently pushed forward the support for Microsoft Visual studio.
13. [gregmarr](https://github.com/gregmarr) simplified the implementation of reverse iterators and helped with numerous hints and improvements. In particular, he pushed forward the implementation of user-defined types.
14. [Caio Luppi](https://github.com/caiovlp) fixed a bug in the Unicode handling.
15. [dariomt](https://github.com/dariomt) fixed some typos in the examples.
16. [Daniel Frey](https://github.com/d-frey) cleaned up some pointers and implemented exception-safe memory allocation.
17. [Colin Hirsch](https://github.com/ColinH) took care of a small namespace issue.
18. [Huu Nguyen](https://github.com/whoshuu) correct a variable name in the documentation.
19. [Silverweed](https://github.com/silverweed) overloaded `parse()` to accept an rvalue reference.
20. [dariomt](https://github.com/dariomt) fixed a subtlety in MSVC type support and implemented the `get_ref()` function to get a reference to stored values.
21. [ZahlGraf](https://github.com/ZahlGraf) added a workaround that allows compilation using Android NDK.
22. [whackashoe](https://github.com/whackashoe) replaced a function that was marked as unsafe by Visual Studio.
23. [406345](https://github.com/406345) fixed two small warnings.
24. [Glen Fernandes](https://github.com/glenfe) noted a potential portability problem in the `has_mapped_type` function.
25. [Corbin Hughes](https://github.com/nibroc) fixed some typos in the contribution guidelines.
26. [twelsby](https://github.com/twelsby) fixed the array subscript operator, an issue that failed the MSVC build, and floating-point parsing/dumping. He further added support for unsigned integer numbers and implemented better roundtrip support for parsed numbers.
27. [Volker Diels-Grabsch](https://github.com/vog) fixed a link in the README file.
28. [msm-](https://github.com/msm-) added support for American Fuzzy Lop.
29. [Annihil](https://github.com/Annihil) fixed an example in the README file.
30. [Themercee](https://github.com/Themercee) noted a wrong URL in the README file.
31. [Lv Zheng](https://github.com/lv-zheng) fixed a namespace issue with `int64_t` and `uint64_t`.
32. [abc100m](https://github.com/abc100m) analyzed the issues with GCC 4.8 and proposed a [partial solution](https://github.com/nlohmann/json/pull/212).
33. [zewt](https://github.com/zewt) added useful notes to the README file about Android.
34. [Róbert Márki](https://github.com/robertmrk) added a fix to use move iterators and improved the integration via CMake.
35. [Chris Kitching](https://github.com/ChrisKitching) cleaned up the CMake files.
36. [Tom Needham](https://github.com/06needhamt) fixed a subtle bug with MSVC 2015 which was also proposed by [Michael K.](https://github.com/Epidal).
37. [Mário Feroldi](https://github.com/thelostt) fixed a small typo.
38. [duncanwerner](https://github.com/duncanwerner) found a really embarrassing performance regression in the 2.0.0 release.
39. [Damien](https://github.com/dtoma) fixed one of the last conversion warnings.
40. [Thomas Braun](https://github.com/t-b) fixed a warning in a test case and adjusted MSVC calls in the CI.
41. [Théo DELRIEU](https://github.com/theodelrieu) patiently and constructively oversaw the long way toward [iterator-range parsing](https://github.com/nlohmann/json/issues/290). He also implemented the magic behind the serialization/deserialization of user-defined types and split the single header file into smaller chunks.
42. [Stefan](https://github.com/5tefan) fixed a minor issue in the documentation.
43. [Vasil Dimov](https://github.com/vasild) fixed the documentation regarding conversions from `std::multiset`.
44. [ChristophJud](https://github.com/ChristophJud) overworked the CMake files to ease project inclusion.
45. [Vladimir Petrigo](https://github.com/vpetrigo) made a SFINAE hack more readable and added Visual Studio 17 to the build matrix.
46. [Denis Andrejew](https://github.com/seeekr) fixed a grammar issue in the README file.
47. [Pierre-Antoine Lacaze](https://github.com/palacaze) found a subtle bug in the `dump()` function.
48. [TurpentineDistillery](https://github.com/TurpentineDistillery) pointed to [`std::locale::classic()`](https://en.cppreference.com/w/cpp/locale/locale/classic) to avoid too much locale joggling, found some nice performance improvements in the parser, improved the benchmarking code, and realized locale-independent number parsing and printing.
49. [cgzones](https://github.com/cgzones) had an idea how to fix the Coverity scan.
50. [Jared Grubb](https://github.com/jaredgrubb) silenced a nasty documentation warning.
51. [Yixin Zhang](https://github.com/qwename) fixed an integer overflow check.
52. [Bosswestfalen](https://github.com/Bosswestfalen) merged two iterator classes into a smaller one.
53. [Daniel599](https://github.com/Daniel599) helped to get Travis execute the tests with Clang's sanitizers.
54. [Jonathan Lee](https://github.com/vjon) fixed an example in the README file.
55. [gnzlbg](https://github.com/gnzlbg) supported the implementation of user-defined types.
56. [Alexej Harm](https://github.com/qis) helped to get the user-defined types working with Visual Studio.
57. [Jared Grubb](https://github.com/jaredgrubb) supported the implementation of user-defined types.
58. [EnricoBilla](https://github.com/EnricoBilla) noted a typo in an example.
59. [Martin Hořeňovský](https://github.com/horenmar) found a way for a 2x speedup for the compilation time of the test suite.
60. [ukhegg](https://github.com/ukhegg) found proposed an improvement for the examples section.
61. [rswanson-ihi](https://github.com/rswanson-ihi) noted a typo in the README.
62. [Mihai Stan](https://github.com/stanmihai4) fixed a bug in the comparison with `nullptr`s.
63. [Tushar Maheshwari](https://github.com/tusharpm) added [cotire](https://github.com/sakra/cotire) support to speed up the compilation.
64. [TedLyngmo](https://github.com/TedLyngmo) noted a typo in the README, removed unnecessary bit arithmetic, and fixed some `-Weffc++` warnings.
65. [Krzysztof Woś](https://github.com/krzysztofwos) made exceptions more visible.
66. [ftillier](https://github.com/ftillier) fixed a compiler warning.
67. [tinloaf](https://github.com/tinloaf) made sure all pushed warnings are properly popped.
68. [Fytch](https://github.com/Fytch) found a bug in the documentation.
69. [Jay Sistar](https://github.com/Type1J) implemented a Meson build description.
70. [Henry Lee](https://github.com/HenryRLee) fixed a warning in ICC and improved the iterator implementation.
71. [Vincent Thiery](https://github.com/vthiery) maintains a package for the Conan package manager.
72. [Steffen](https://github.com/koemeet) fixed a potential issue with MSVC and `std::min`.
73. [Mike Tzou](https://github.com/Chocobo1) fixed some typos.
74. [amrcode](https://github.com/amrcode) noted a misleading documentation about comparison of floats.
75. [Oleg Endo](https://github.com/olegendo) reduced the memory consumption by replacing `<iostream>` with `<iosfwd>`.
76. [dan-42](https://github.com/dan-42) cleaned up the CMake files to simplify including/reusing of the library.
77. [Nikita Ofitserov](https://github.com/himikof) allowed for moving values from initializer lists.
78. [Greg Hurrell](https://github.com/wincent) fixed a typo.
79. [Dmitry Kukovinets](https://github.com/DmitryKuk) fixed a typo.
80. [kbthomp1](https://github.com/kbthomp1) fixed an issue related to the Intel OSX compiler.
81. [Markus Werle](https://github.com/daixtrose) fixed a typo.
82. [WebProdPP](https://github.com/WebProdPP) fixed a subtle error in a precondition check.
83. [Alex](https://github.com/leha-bot) noted an error in a code sample.
84. [Tom de Geus](https://github.com/tdegeus) reported some warnings with ICC and helped to fix them.
85. [Perry Kundert](https://github.com/pjkundert) simplified reading from input streams.
86. [Sonu Lohani](https://github.com/sonulohani) fixed a small compilation error.
87. [Jamie Seward](https://github.com/jseward) fixed all MSVC warnings.
88. [Nate Vargas](https://github.com/eld00d) added a Doxygen tag file.
89. [pvleuven](https://github.com/pvleuven) helped to fix a warning in ICC.
90. [Pavel](https://github.com/crea7or) helped to fix some warnings in MSVC.
91. [Jamie Seward](https://github.com/jseward) avoided unnecessary string copies in `find()` and `count()`.
92. [Mitja](https://github.com/Itja) fixed some typos.
93. [Jorrit Wronski](https://github.com/jowr) updated the Hunter package links.
94. [Matthias Möller](https://github.com/TinyTinni) added a `.natvis` for the MSVC debug view.
95. [bogemic](https://github.com/bogemic) fixed some C++17 deprecation warnings.
96. [Eren Okka](https://github.com/erengy) fixed some MSVC warnings.
97. [abolz](https://github.com/abolz) integrated the Grisu2 algorithm for proper floating-point formatting, allowing more roundtrip checks to succeed.
98. [Vadim Evard](https://github.com/Pipeliner) fixed a Markdown issue in the README.
99. [zerodefect](https://github.com/zerodefect) fixed a compiler warning.
100. [Kert](https://github.com/kaidokert) allowed to template the string type in the serialization and added the possibility to override the exceptional behavior.
101. [mark-99](https://github.com/mark-99) helped fixing an ICC error.
102. [Patrik Huber](https://github.com/patrikhuber) fixed links in the README file.
103. [johnfb](https://github.com/johnfb) found a bug in the implementation of CBOR's indefinite length strings.
104. [Paul Fultz II](https://github.com/pfultz2) added a note on the cget package manager.
105. [Wilson Lin](https://github.com/wla80) made the integration section of the README more concise.
106. [RalfBielig](https://github.com/ralfbielig) detected and fixed a memory leak in the parser callback.
107. [agrianius](https://github.com/agrianius) allowed to dump JSON to an alternative string type.
108. [Kevin Tonon](https://github.com/ktonon) overworked the C++11 compiler checks in CMake.
109. [Axel Huebl](https://github.com/ax3l) simplified a CMake check and added support for the [Spack package manager](https://spack.io).
110. [Carlos O'Ryan](https://github.com/coryan) fixed a typo.
111. [James Upjohn](https://github.com/jammehcow) fixed a version number in the compilers section.
112. [Chuck Atkins](https://github.com/chuckatkins) adjusted the CMake files to the CMake packaging guidelines and provided documentation for the CMake integration.
113. [Jan Schöppach](https://github.com/dns13) fixed a typo.
114. [martin-mfg](https://github.com/martin-mfg) fixed a typo.
115. [Matthias Möller](https://github.com/TinyTinni) removed the dependency from `std::stringstream`.
116. [agrianius](https://github.com/agrianius) added code to use alternative string implementations.
117. [Daniel599](https://github.com/Daniel599) allowed to use more algorithms with the `items()` function.
118. [Julius Rakow](https://github.com/jrakow) fixed the Meson include directory and fixed the links to [cppreference.com](cppreference.com).
119. [Sonu Lohani](https://github.com/sonulohani) fixed the compilation with MSVC 2015 in debug mode.
120. [grembo](https://github.com/grembo) fixed the test suite and re-enabled several test cases.
121. [Hyeon Kim](https://github.com/simnalamburt) introduced the macro `JSON_INTERNAL_CATCH` to control the exception handling inside the library.
122. [thyu](https://github.com/thyu) fixed a compiler warning.
123. [David Guthrie](https://github.com/LEgregius) fixed a subtle compilation error with Clang 3.4.2.
124. [Dennis Fischer](https://github.com/dennisfischer) allowed to call `find_package` without installing the library.
125. [Hyeon Kim](https://github.com/simnalamburt) fixed an issue with a double macro definition.
126. [Ben Berman](https://github.com/rivertam) made some error messages more understandable.
127. [zakalibit](https://github.com/zakalibit) fixed a compilation problem with the Intel C++ compiler.
128. [mandreyel](https://github.com/mandreyel) fixed a compilation problem.
129. [Kostiantyn Ponomarenko](https://github.com/koponomarenko) added version and license information to the Meson build file.
130. [Henry Schreiner](https://github.com/henryiii) added support for GCC 4.8.
131. [knilch](https://github.com/knilch0r) made sure the test suite does not stall when run in the wrong directory.
132. [Antonio Borondo](https://github.com/antonioborondo) fixed an MSVC 2017 warning.
133. [Dan Gendreau](https://github.com/dgendreau) implemented the `NLOHMANN_JSON_SERIALIZE_ENUM` macro to quickly define an enum/JSON mapping.
134. [efp](https://github.com/efp) added line and column information to parse errors.
135. [julian-becker](https://github.com/julian-becker) added BSON support.
136. [Pratik Chowdhury](https://github.com/pratikpc) added support for structured bindings.
137. [David Avedissian](https://github.com/davedissian) added support for Clang 5.0.1 (PS4 version).
138. [Jonathan Dumaresq](https://github.com/dumarjo) implemented an input adapter to read from `FILE*`.
139. [kjpus](https://github.com/kjpus) fixed a link in the documentation.
140. [Manvendra Singh](https://github.com/manu-chroma) fixed a typo in the documentation.
141. [ziggurat29](https://github.com/ziggurat29) fixed an MSVC warning.
142. [Sylvain Corlay](https://github.com/SylvainCorlay) added code to avoid an issue with MSVC.
143. [mefyl](https://github.com/mefyl) fixed a bug when JSON was parsed from an input stream.
144. [Millian Poquet](https://github.com/mpoquet) allowed to install the library via Meson.
145. [Michael Behrns-Miller](https://github.com/moodboom) found an issue with a missing namespace.
146. [Nasztanovics Ferenc](https://github.com/naszta) fixed a compilation issue with libc 2.12.
147. [Andreas Schwab](https://github.com/andreas-schwab) fixed the endian conversion.
148. [Mark-Dunning](https://github.com/Mark-Dunning) fixed a warning in MSVC.
149. [Gareth Sylvester-Bradley](https://github.com/garethsb-sony) added `operator/` for JSON Pointers.
150. [John-Mark](https://github.com/johnmarkwayve) noted a missing header.
151. [Vitaly Zaitsev](https://github.com/xvitaly) fixed compilation with GCC 9.0.
152. [Laurent Stacul](https://github.com/stac47) fixed compilation with GCC 9.0.
153. [Ivor Wanders](https://github.com/iwanders) helped to reduce the CMake requirement to version 3.1.
154. [njlr](https://github.com/njlr) updated the Buckaroo instructions.
155. [Lion](https://github.com/lieff) fixed a compilation issue with GCC 7 on CentOS.
156. [Isaac Nickaein](https://github.com/nickaein) improved the integer serialization performance and  implemented the `contains()` function.
157. [past-due](https://github.com/past-due) suppressed an unfixable warning.
158. [Elvis Oric](https://github.com/elvisoric) improved Meson support.
159. [Matěj Plch](https://github.com/Afforix) fixed an example in the README.
160. [Mark Beckwith](https://github.com/wythe) fixed a typo.
161. [scinart](https://github.com/scinart) fixed bug in the serializer.
162. [Patrick Boettcher](https://github.com/pboettch) implemented `push_back()` and `pop_back()` for JSON Pointers.
163. [Bruno Oliveira](https://github.com/nicoddemus) added support for Conda.
164. [Michele Caini](https://github.com/skypjack) fixed links in the README.
165. [Hani](https://github.com/hnkb) documented how to install the library with NuGet.
166. [Mark Beckwith](https://github.com/wythe) fixed a typo.
167. [yann-morin-1998](https://github.com/yann-morin-1998) helped to reduce the CMake requirement to version 3.1.
168. [Konstantin Podsvirov](https://github.com/podsvirov) maintains a package for the MSYS2 software distro.
169. [remyabel](https://github.com/remyabel) added GNUInstallDirs to the CMake files.
170. [Taylor Howard](https://github.com/taylorhoward92) fixed a unit test.
171. [Gabe Ron](https://github.com/Macr0Nerd) implemented the `to_string` method.
172. [Watal M. Iwasaki](https://github.com/heavywatal) fixed a Clang warning.
173. [Viktor Kirilov](https://github.com/onqtam) switched the unit tests from [Catch](https://github.com/philsquared/Catch) to [doctest](https://github.com/onqtam/doctest)
174. [Juncheng E](https://github.com/ejcjason) fixed a typo.
175. [tete17](https://github.com/tete17) fixed a bug in the `contains` function.
176. [Xav83](https://github.com/Xav83) fixed some cppcheck warnings.
177. [0xflotus](https://github.com/0xflotus) fixed some typos.
178. [Christian Deneke](https://github.com/chris0x44) added a const version of `json_pointer::back`.
179. [Julien Hamaide](https://github.com/crazyjul) made the `items()` function work with custom string types.
180. [Evan Nemerson](https://github.com/nemequ) updated fixed a bug in Hedley and updated this library accordingly.
181. [Florian Pigorsch](https://github.com/flopp) fixed a lot of typos.
182. [Camille Bégué](https://github.com/cbegue) fixed an issue in the conversion from  `std::pair` and `std::tuple` to `json`.
183. [Anthony VH](https://github.com/AnthonyVH) fixed a compile error in an enum deserialization.
184. [Yuriy Vountesmery](https://github.com/ua-code-dragon) noted a subtle bug in a preprocessor check.
185. [Chen](https://github.com/dota17) fixed numerous issues in the library.
186. [Antony Kellermann](https://github.com/aokellermann) added a CI step for GCC 10.1.
187. [Alex](https://github.com/gistrec) fixed an MSVC warning.
188. [Rainer](https://github.com/rvjr) proposed an improvement in the floating-point serialization in CBOR.
189. [Francois Chabot](https://github.com/FrancoisChabot) made performance improvements in the input adapters.
190. [Arthur Sonzogni](https://github.com/ArthurSonzogni) documented how the library can be included via `FetchContent`.
191. [Rimas Misevičius](https://github.com/rmisev) fixed an error message.
192. [Alexander Myasnikov](https://github.com/alexandermyasnikov) fixed some examples and a link in the README.
193. [Hubert Chathi](https://github.com/uhoreg) made CMake's version config file architecture-independent.
194. [OmnipotentEntity](https://github.com/OmnipotentEntity) implemented the binary values for CBOR, MessagePack, BSON, and UBJSON.
195. [ArtemSarmini](https://github.com/ArtemSarmini) fixed a compilation issue with GCC 10 and fixed a leak.
196. [Evgenii Sopov](https://github.com/sea-kg) integrated the library to the wsjcpp package manager.
197. [Sergey Linev](https://github.com/linev) fixed a compiler warning.
198. [Miguel Magalhães](https://github.com/magamig) fixed the year in the copyright.
199. [Gareth Sylvester-Bradley](https://github.com/garethsb-sony) fixed a compilation issue with MSVC.
200. [Alexander “weej” Jones](https://github.com/alex-weej) fixed an example in the README.
201. [Antoine Cœur](https://github.com/Coeur) fixed some typos in the documentation.
202. [jothepro](https://github.com/jothepro) updated links to the Hunter package.
203. [Dave Lee](https://github.com/kastiglione) fixed link in the README.
204. [Joël Lamotte](https://github.com/Klaim) added instruction for using Build2's package manager.
205. [Paul Jurczak](https://github.com/pauljurczak) fixed an example in the README.
206. [Sonu Lohani](https://github.com/sonulohani) fixed a warning.
207. [Carlos Gomes Martinho](https://github.com/gocarlos) updated the Conan package source.
208. [Konstantin Podsvirov](https://github.com/podsvirov) fixed the MSYS2 package documentation.
209. [Tridacnid](https://github.com/Tridacnid) improved the CMake tests.
210. [Michael](https://github.com/MBalszun) fixed MSVC warnings.
211. [Quentin Barbarat](https://github.com/quentin-dev) fixed an example in the documentation.
212. [XyFreak](https://github.com/XyFreak) fixed a compiler warning.
213. [TotalCaesar659](https://github.com/TotalCaesar659) fixed links in the README.
214. [Tanuj Garg](https://github.com/tanuj208) improved the fuzzer coverage for UBSAN input.
215. [AODQ](https://github.com/AODQ) fixed a compiler warning.
216. [jwittbrodt](https://github.com/jwittbrodt) made `NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE` inline.
217. [pfeatherstone](https://github.com/pfeatherstone) improved the upper bound of arguments of the `NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE`/`NLOHMANN_DEFINE_TYPE_INTRUSIVE` macros.
218. [Jan Procházka](https://github.com/jprochazk) fixed a bug in the CBOR parser for binary and string values.
219. [T0b1-iOS](https://github.com/T0b1-iOS) fixed a bug in the new hash implementation.
220. [Matthew Bauer](https://github.com/matthewbauer) adjusted the CBOR writer to create tags for binary subtypes.
221. [gatopeich](https://github.com/gatopeich) implemented an ordered map container for `nlohmann::ordered_json`.
222. [Érico Nogueira Rolim](https://github.com/ericonr) added support for pkg-config.
223. [KonanM](https://github.com/KonanM) proposed an implementation for the `NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE`/`NLOHMANN_DEFINE_TYPE_INTRUSIVE` macros.
224. [Guillaume Racicot](https://github.com/gracicot) implemented `string_view` support and allowed C++20 support.
225. [Alex Reinking](https://github.com/alexreinking) improved CMake support for `FetchContent`.
226. [Hannes Domani](https://github.com/ssbssa) provided a GDB pretty printer.
227. Lars Wirzenius reviewed the README file.
228. [Jun Jie](https://github.com/ongjunjie) fixed a compiler path in the CMake scripts.
229. [Ronak Buch](https://github.com/rbuch) fixed typos in the documentation.
230. [Alexander Karzhenkov](https://github.com/karzhenkov) fixed a move constructor and the Travis builds.
231. [Leonardo Lima](https://github.com/leozz37) added CPM.Cmake support.
232. [Joseph Blackman](https://github.com/jbzdarkid) fixed a warning.
233. [Yaroslav](https://github.com/YarikTH) updated doctest and implemented unit tests.
234. [Martin Stump](https://github.com/globberwops) fixed a bug in the CMake files.
235. [Jaakko Moisio](https://github.com/jasujm) fixed a bug in the input adapters.
236. [bl-ue](https://github.com/bl-ue) fixed some Markdown issues in the README file.
237. [William A. Wieselquist](https://github.com/wawiesel) fixed an example from the README.
238. [abbaswasim](https://github.com/abbaswasim) fixed an example from the README.
239. [Remy Jette](https://github.com/remyjette) fixed a warning.
240. [Fraser](https://github.com/frasermarlow) fixed the documentation.
241. [Ben Beasley](https://github.com/musicinmybrain) updated doctest.
242. [Doron Behar](https://github.com/doronbehar) fixed pkg-config.pc.
243. [raduteo](https://github.com/raduteo) fixed a warning.
244. [David Pfahler](https://github.com/theShmoo) added the possibility to compile the library without I/O support.
245. [Morten Fyhn Amundsen](https://github.com/mortenfyhn) fixed a typo.
246. [jpl-mac](https://github.com/jpl-mac) allowed to treat the library as a system header in CMake.
247. [Jason Dsouza](https://github.com/jasmcaus) fixed the indentation of the CMake file.
248. [offa](https://github.com/offa) added a link to Conan Center to the documentation.
249. [TotalCaesar659](https://github.com/TotalCaesar659) updated the links in the documentation to use HTTPS.
250. [Rafail Giavrimis](https://github.com/grafail) fixed the Google Benchmark default branch.
251. [Louis Dionne](https://github.com/ldionne) fixed a conversion operator.
252. [justanotheranonymoususer](https://github.com/justanotheranonymoususer) made the examples in the README more consistent.
253. [Finkman](https://github.com/Finkman) suppressed some `-Wfloat-equal` warnings.
254. [Ferry Huberts](https://github.com/fhuberts) fixed `-Wswitch-enum` warnings.
255. [Arseniy Terekhin](https://github.com/senyai) made the GDB pretty-printer robust against unset variable names.
256. [Amir Masoud Abdol](https://github.com/amirmasoudabdol) updated the Homebrew command as nlohmann/json is now in homebrew-core.
257. [Hallot](https://github.com/Hallot) fixed some `-Wextra-semi-stmt warnings`.
258. [Giovanni Cerretani](https://github.com/gcerretani) fixed `-Wunused` warnings on `JSON_DIAGNOSTICS`.
259. [Bogdan Popescu](https://github.com/Kapeli) hosts the [docset](https://github.com/Kapeli/Dash-User-Contributions/tree/master/docsets/JSON_for_Modern_C%2B%2B) for offline documentation viewers.
260. [Carl Smedstad](https://github.com/carlsmedstad) fixed an assertion error when using `JSON_DIAGNOSTICS`.
261. [miikka75](https://github.com/miikka75) provided an important fix to compile C++17 code with Clang 9.
262. [Maarten Becker](https://github.com/kernie) fixed a warning for shadowed variables.
263. [Cristi Vîjdea](https://github.com/axnsan12) fixed typos in the `operator[]` documentation.
264. [Alex Beregszaszi](https://github.com/axic) fixed spelling mistakes in comments.
265. [Dirk Stolle](https://github.com/striezel) fixed typos in documentation.
266. [Daniel Albuschat](https://github.com/daniel-kun) corrected the parameter name in the `parse` documentation.
267. [Prince Mendiratta](https://github.com/Prince-Mendiratta) fixed a link to the FAQ.
268. [Florian Albrechtskirchinger](https://github.com/falbrechtskirchinger) implemented `std::string_view` support for object keys and made dozens of other improvements.
269. [Qianqian Fang](https://github.com/fangq) implemented the Binary JData (BJData) format.
270. [pketelsen](https://github.com/pketelsen) added macros `NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT` and `NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT`.
271. [DarkZeros](https://github.com/DarkZeros) adjusted to code to not clash with Arduino defines.
272. [flagarde](https://github.com/flagarde) fixed the output of `meta()` for MSVC.
273. [Giovanni Cerretani](https://github.com/gcerretani) fixed a check for `std::filesystem`.
274. [Dimitris Apostolou](https://github.com/rex4539) fixed a typo.
275. [Ferry Huberts](https://github.com/fhuberts) fixed a typo.
276. [Michael Nosthoff](https://github.com/heinemml) fixed a typo.
277. [JungHoon Lee](https://github.com/jhnlee) fixed a typo.
278. [Faruk D.](https://github.com/fdiblen) fixed the CITATION.CFF file.
279. [Andrea Cocito](https://github.com/puffetto) added a clarification on macro usage to the documentation.
280. [Krzysiek Karbowiak](https://github.com/kkarbowiak) refactored the tests to use `CHECK_THROWS_WITH_AS`.
281. [Chaoqi Zhang](https://github.com/prncoprs) fixed a typo.
282. [ivanovmp](https://github.com/ivanovmp) fixed a whitespace error.
283. [KsaNL](https://github.com/KsaNL) fixed a build error when including `<windows.h>`.
284. [Andrea Pappacoda](https://github.com/Tachi107) moved `.pc` and `.cmake` files to `share` directory.
285. [Wolf Vollprecht](https://github.com/wolfv) added the `patch_inplace` function.
286. [Jake Zimmerman](https://github.com/jez) highlighted common usage patterns in the README file.
287. [NN](https://github.com/NN---) added the Visual Studio output directory to `.gitignore`.
288. [Romain Reignier](https://github.com/romainreignier) improved the performance the vector output adapter.
289. [Mike](https://github.com/Mike-Leo-Smith) fixed the `std::iterator_traits`.
290. [Richard Hozák](https://github.com/zxey) added macro `JSON_NO_ENUM` to disable default enum conversions.
291. [vakokako](https://github.com/vakokako) fixed tests when compiling with C++20.
292. [Alexander “weej” Jones](https://github.com/alexweej) fixed an example in the README.
293. [Eli Schwartz](https://github.com/eli-schwartz) added more files to the `include.zip` archive.
294. [Kevin Lu](https://github.com/kevinlul) fixed a compilation issue when typedefs with certain names were present.
295. [Trevor Hickey](https://github.com/luxe) improved the description of an example.
296. [Jef LeCompte](https://github.com/jef) updated the year in the README file.
297. [Alexandre Hamez](https://github.com/ahamez) fixed a warning.
298. [Maninderpal Badhan](https://github.com/mbadhan) fixed a typo.
299. [kevin--](https://github.com/kevin--) added a note to an example in the README file.
300. [I](https://github.com/wx257osn2) fixed a typo.
301. [Gregorio Litenstein](https://github.com/Lord-Kamina) fixed the Clang detection.
302. [Andreas Smas](https://github.com/andoma) added a Doozer badge.
303. [WanCW](https://github.com/wancw) fixed the string conversion with Clang.
304. [zhaohuaxishi](https://github.com/zhaohuaxishi) fixed a Doxygen error.
305. [emvivre](https://github.com/emvivre) removed an invalid parameter from CMake.
306. [Tobias Hermann](https://github.com/Dobiasd) fixed a link in the README file.
307. [Michael](https://github.com/traits) fixed a warning.
308. [Ryan Mulder](https://github.com/ryanjmulder) added `ensure_ascii` to the `dump` function.
309. [Muri Nicanor](https://github.com/murinicanor) fixed the `sed` discovery in the Makefile.
310. [David Avedissian](https://github.com/dgavedissian) implemented SFINAE-friendly `iterator_traits`.
311. [AQNOUCH Mohammed](https://github.com/aqnouch) fixed a typo in the README.
312. [Gareth Sylvester-Bradley](https://github.com/garethsb) added `operator/=` and `operator/` to construct JSON pointers.
313. [Michael Macnair](https://github.com/mykter) added support for afl-fuzz testing.
314. [Berkus Decker](https://github.com/berkus) fixed a typo in the README.
315. [Illia Polishchuk](https://github.com/effolkronium) improved the CMake testing.
316. [Ikko Ashimine](https://github.com/eltociear) fixed a typo.

Thanks a lot for helping out! Please [let me know](mailto:mail@nlohmann.me) if I forgot someone.


## Used third-party tools

The library itself consists of a single header file licensed under the MIT license. However, it is built, tested, documented, and whatnot using a lot of third-party tools and services. Thanks a lot!

- [**amalgamate.py - Amalgamate C source and header files**](https://github.com/edlund/amalgamate) to create a single header file
- [**American fuzzy lop**](https://lcamtuf.coredump.cx/afl/) for fuzz testing
- [**AppVeyor**](https://www.appveyor.com) for [continuous integration](https://ci.appveyor.com/project/nlohmann/json) on Windows
- [**Artistic Style**](http://astyle.sourceforge.net) for automatic source code indentation
- [**Clang**](https://clang.llvm.org) for compilation with code sanitizers
- [**CMake**](https://cmake.org) for build automation
- [**Codacy**](https://www.codacy.com) for further [code analysis](https://www.codacy.com/app/nlohmann/json)
- [**Coveralls**](https://coveralls.io) to measure [code coverage](https://coveralls.io/github/nlohmann/json)
- [**Coverity Scan**](https://scan.coverity.com) for [static analysis](https://scan.coverity.com/projects/nlohmann-json)
- [**cppcheck**](http://cppcheck.sourceforge.net) for static analysis
- [**doctest**](https://github.com/onqtam/doctest) for the unit tests
- [**git-update-ghpages**](https://github.com/rstacruz/git-update-ghpages) to upload the documentation to gh-pages
- [**GitHub Changelog Generator**](https://github.com/skywinder/github-changelog-generator) to generate the [ChangeLog](https://github.com/nlohmann/json/blob/develop/ChangeLog.md)
- [**Google Benchmark**](https://github.com/google/benchmark) to implement the benchmarks
- [**Hedley**](https://nemequ.github.io/hedley/) to avoid re-inventing several compiler-agnostic feature macros
- [**lcov**](http://ltp.sourceforge.net/coverage/lcov.php) to process coverage information and create an HTML view
- [**libFuzzer**](https://llvm.org/docs/LibFuzzer.html) to implement fuzz testing for OSS-Fuzz
- [**Material for MkDocs**](https://squidfunk.github.io/mkdocs-material/) for the style of the documentation site
- [**MkDocs**](https://www.mkdocs.org) for the documentation site
- [**OSS-Fuzz**](https://github.com/google/oss-fuzz) for continuous fuzz testing of the library ([project repository](https://github.com/google/oss-fuzz/tree/master/projects/json))
- [**Probot**](https://probot.github.io) for automating maintainer tasks such as closing stale issues, requesting missing information, or detecting toxic comments.
- [**Valgrind**](https://valgrind.org) to check for correct memory management


## Projects using JSON for Modern C++

The library is currently used in Apple macOS Sierra-Monterey and iOS 10-15. I am not sure what they are using the library for, but I am happy that it runs on so many devices.


## Notes

### Character encoding

The library supports **Unicode input** as follows:

- Only **UTF-8** encoded input is supported which is the default encoding for JSON according to [RFC 8259](https://tools.ietf.org/html/rfc8259.html#section-8.1).
- `std::u16string` and `std::u32string` can be parsed, assuming UTF-16 and UTF-32 encoding, respectively. These encodings are not supported when reading from files or other input containers.
- Other encodings such as Latin-1 or ISO 8859-1 are **not** supported and will yield parse or serialization errors.
- [Unicode noncharacters](https://www.unicode.org/faq/private_use.html#nonchar1) will not be replaced by the library.
- Invalid surrogates (e.g., incomplete pairs such as `\uDEAD`) will yield parse errors.
- The strings stored in the library are UTF-8 encoded. When using the default string type (`std::string`), note that its length/size functions return the number of stored bytes rather than the number of characters or glyphs.
- When you store strings with different encodings in the library, calling [`dump()`](https://json.nlohmann.me/api/basic_json/dump/) may throw an exception unless `json::error_handler_t::replace` or `json::error_handler_t::ignore` are used as error handlers.
- To store wide strings (e.g., `std::wstring`), you need to convert them to a UTF-8 encoded `std::string` before, see [an example](https://json.nlohmann.me/home/faq/#wide-string-handling).

### Comments in JSON

This library does not support comments by default. It does so for three reasons:

1. Comments are not part of the [JSON specification](https://tools.ietf.org/html/rfc8259). You may argue that `//` or `/* */` are allowed in JavaScript, but JSON is not JavaScript.
2. This was not an oversight: Douglas Crockford [wrote on this](https://plus.google.com/118095276221607585885/posts/RK8qyGVaGSr) in May 2012:

	> I removed comments from JSON because I saw people were using them to hold parsing directives, a practice which would have destroyed interoperability.  I know that the lack of comments makes some people sad, but it shouldn't.

	> Suppose you are using JSON to keep configuration files, which you would like to annotate. Go ahead and insert all the comments you like. Then pipe it through JSMin before handing it to your JSON parser.

3. It is dangerous for interoperability if some libraries would add comment support while others don't. Please check [The Harmful Consequences of the Robustness Principle](https://tools.ietf.org/html/draft-iab-protocol-maintenance-01) on this.

However, you can pass set parameter `ignore_comments` to true in the `parse` function to ignore `//` or `/* */` comments. Comments will then be treated as whitespace.

### Order of object keys

By default, the library does not preserve the **insertion order of object elements**. This is standards-compliant, as the [JSON standard](https://tools.ietf.org/html/rfc8259.html) defines objects as "an unordered collection of zero or more name/value pairs".

If you do want to preserve the insertion order, you can try the type [`nlohmann::ordered_json`](https://github.com/nlohmann/json/issues/2179). Alternatively, you can use a more sophisticated ordered map like [`tsl::ordered_map`](https://github.com/Tessil/ordered-map) ([integration](https://github.com/nlohmann/json/issues/546#issuecomment-304447518)) or [`nlohmann::fifo_map`](https://github.com/nlohmann/fifo_map) ([integration](https://github.com/nlohmann/json/issues/485#issuecomment-333652309)).

### Memory Release

We checked with Valgrind and the Address Sanitizer (ASAN) that there are no memory leaks.

If you find that a parsing program with this library does not release memory, please consider the following case, and it may be unrelated to this library.

**Your program is compiled with glibc.** There is a tunable threshold that glibc uses to decide whether to actually return memory to the system or whether to cache it for later reuse. If in your program you make lots of small allocations and those small allocations are not a contiguous block and are presumably below the threshold, then they will not get returned to the OS.
Here is a related issue [#1924](https://github.com/nlohmann/json/issues/1924).

### Further notes

- The code contains numerous debug **assertions** which can be switched off by defining the preprocessor macro `NDEBUG`, see the [documentation of `assert`](https://en.cppreference.com/w/cpp/error/assert). In particular, note [`operator[]`](https://json.nlohmann.me/api/basic_json/operator%5B%5D/) implements **unchecked access** for const objects: If the given key is not present, the behavior is undefined (think of a dereferenced null pointer) and yields an [assertion failure](https://github.com/nlohmann/json/issues/289) if assertions are switched on. If you are not sure whether an element in an object exists, use checked access with the [`at()` function](https://json.nlohmann.me/api/basic_json/at/). Furthermore, you can define `JSON_ASSERT(x)` to replace calls to `assert(x)`.
- As the exact number type is not defined in the [JSON specification](https://tools.ietf.org/html/rfc8259.html), this library tries to choose the best fitting C++ number type automatically. As a result, the type `double` may be used to store numbers which may yield [**floating-point exceptions**](https://github.com/nlohmann/json/issues/181) in certain rare situations if floating-point exceptions have been unmasked in the calling code. These exceptions are not caused by the library and need to be fixed in the calling code, such as by re-masking the exceptions prior to calling library functions.
- The code can be compiled without C++ **runtime type identification** features; that is, you can use the `-fno-rtti` compiler flag.
- **Exceptions** are used widely within the library. They can, however, be switched off with either using the compiler flag `-fno-exceptions` or by defining the symbol `JSON_NOEXCEPTION`. In this case, exceptions are replaced by `abort()` calls. You can further control this behavior by defining `JSON_THROW_USER` (overriding `throw`), `JSON_TRY_USER` (overriding `try`), and `JSON_CATCH_USER` (overriding `catch`). Note that `JSON_THROW_USER` should leave the current scope (e.g., by throwing or aborting), as continuing after it may yield undefined behavior. Note the explanatory [`what()`](https://en.cppreference.com/w/cpp/error/exception/what) string of exceptions is not available for MSVC if exceptions are disabled, see [#2824](https://github.com/nlohmann/json/discussions/2824).

## Execute unit tests

To compile and run the tests, you need to execute

```sh
$ mkdir build
$ cd build
$ cmake .. -DJSON_BuildTests=On
$ cmake --build .
$ ctest --output-on-failure
```

Note that during the `ctest` stage, several JSON test files are downloaded from an [external repository](https://github.com/nlohmann/json_test_data). If policies forbid downloading artifacts during testing, you can download the files yourself and pass the directory with the test files via `-DJSON_TestDataDirectory=path` to CMake. Then, no Internet connectivity is required. See [issue #2189](https://github.com/nlohmann/json/issues/2189) for more information.

If the test suite is not found, several test suites will fail like this:

```
===============================================================================
json/tests/src/make_test_data_available.hpp:21:
TEST CASE:  check test suite is downloaded

json/tests/src/make_test_data_available.hpp:23: FATAL ERROR: REQUIRE( utils::check_testsuite_downloaded() ) is NOT correct!
  values: REQUIRE( false )
  logged: Test data not found in 'json/cmake-build-debug/json_test_data'.
          Please execute target 'download_test_data' before running this test suite.
          See <https://github.com/nlohmann/json#execute-unit-tests> for more information.

===============================================================================
```

In case you have downloaded the library rather than checked out the code via Git, test `cmake_fetch_content_configure` will fail. Please execute `ctest -LE git_required` to skip these tests. See [issue #2189](https://github.com/nlohmann/json/issues/2189) for more information.

Some tests change the installed files and hence make the whole process not reproducible. Please execute `ctest -LE not_reproducible` to skip these tests. See [issue #2324](https://github.com/nlohmann/json/issues/2324) for more information.

Note you need to call `cmake -LE "not_reproducible|git_required"` to exclude both labels. See [issue #2596](https://github.com/nlohmann/json/issues/2596) for more information.

As Intel compilers use unsafe floating point optimization by default, the unit tests may fail. Use flag [`/fp:precise`](https://software.intel.com/content/www/us/en/develop/documentation/cpp-compiler-developer-guide-and-reference/top/compiler-reference/compiler-options/compiler-option-details/floating-point-options/fp-model-fp.html) then.
