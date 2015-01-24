# JSON for Modern C++

*What if JSON was part of modern C++?*

[![Build Status](https://travis-ci.org/nlohmann/json.png?branch=master)](https://travis-ci.org/nlohmann/json)
[![Coverage Status](https://img.shields.io/coveralls/nlohmann/json.svg)](https://coveralls.io/r/nlohmann/json)
[![Github Issues](https://img.shields.io/github/issues/nlohmann/json.svg)](http://github.com/nlohmann/json/issues)

## Design goals

There are myriads of [JSON](http://json.org) libraries out there, and each may even have its reason to exist. Our class had these design goals:

- **Intuitive syntax**. In languages such as Python, JSON feels like a first class data type. We used all the operator magic of modern C++ to achieve the same feeling in your code. Check out the [examples below](#examples) and the [reference](https://github.com/nlohmann/json/blob/master/doc/Reference.md), and you know, what I mean.

- **Trivial integration**. Our whole code consists of a class in just two files: A header file `json.h` and a source file `json.cc`. That's it. No library, no subproject, no dependencies. The class is written in vanilla C++11. All in all, everything should require no adjustment of your compiler flags or project settings.

- **Serious testing**. Our class is heavily [unit-tested](https://github.com/nlohmann/json/blob/master/test/json_unit.cc) and covers [100%](https://coveralls.io/r/nlohmann/json) of the code, including all exceptional behavior. Furthermore, we checked with [Valgrind](http://valgrind.org) that there are no memory leaks.

Other aspects were not so important to us:

- **Memory efficiency**. Each JSON object has an overhead of one pointer (the maximal size of a union) and one enumeration element (1 byte). We use the following C++ data types: `std::string` for strings, `int64_t` or `double` for numbers, `std::map` for objects, `std::vector` for arrays, and `bool` for Booleans. We know that there are more efficient ways to store the values, but we are happy enough right now.

- **Speed**. We currently implement the parser as naive [recursive descent parser](http://en.wikipedia.org/wiki/Recursive_descent_parser) with hand coded string handling. It is fast enough, but a [LALR-parser](http://en.wikipedia.org/wiki/LALR_parser) with a decent regular expression processor should be even faster (but would consist of more files which makes the integration harder).

- **Rigorous standard compliance**. Any [compliant](http://json.org) JSON file can be read by our class, and any output of the class is standard-compliant. However, we do not check for some details in the format of numbers and strings. For instance, `-0` will be treated as `0` whereas the standard forbids this. Furthermore, we allow for more escape symbols in strings as the JSON specification. While this may not be a problem in reality, we are aware of it, but as long as we have a hand-written parser, we won't invest too much to be fully compliant.

## Integration

The two required source files are in the `src` directory. All you need to do is add

```cpp
#include "json.h"

// for convenience
using json = nlohmann::json;
```

to the files you want to use JSON objects. Furthermore, you need to compile the file `json.cc` and link it to your binaries. Do not forget to set the necessary switches to enable C++11 (e.g., `-std=c++11` for GCC and Clang).

If you want a single header file, use the `json.h` file from the `header_only` directory.

## Examples

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

Note that in all theses cases, you never need to "tell" the compiler which JSON value you want to use. If you want to be explicit or express some edge cases, the functions `json::array` and `json::object` will help:

```cpp
// ways to express the empty array []
json empty_array_implicit = {{}};
json empty_array_explicit = json::array();

// a way to express the empty object {}
json empty_object_explicit = json::object();

// a way to express an _array_ of key/value pairs [["currency", "USD"], ["value", 42.99]]
json array_not_object = { json::array({"currency", "USD"}), json::array({"value", 42.99}) };
```

### Serialization / Deserialization

You can create an object (deserialization) by appending `_json` to a string literal:

```cpp
// create object from string literal
json j = "{ \"happy\": true, \"pi\": 3.141 }"_json;

// or even nicer (thanks http://isocpp.org/blog/2015/01/json-for-modern-cpp)
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
std::cout << j.dump(4) << std::endl;
// {
//     "happy": true,
//     "pi": 3.141
// }
```

You can also use streams to serialize and deserialize:

```cpp
// deserialize from standard input
json j;
j << std::cin;

// serialize to standard output
std::cout << j;
```

These operators work for any subclasses of `std::istream` or `std::ostream`.

### STL-like access

We designed the JSON class to behave just like an STL container:

```cpp
// create an array using push_back
json j;
j.push_back("foo");
j.push_back(1);
j.push_back(true);

// iterate the array
for (json::iterator it = j.begin(); it != j.end(); ++it) {
  std::cout << *it << '\n';
}

// range-based for
for (auto element : j) {
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

// comparison
j == "[\"foo\", 1, true]"_json;  // true

// create an object
json o;
o["foo"] = 23;
o["bar"] = false;
o["baz"] = 3.141;

// find an entry
if (o.find("foo") != o.end()) {
  // there is an entry with key "foo"
}

// iterate the object
for (json::iterator it = o.begin(); it != o.end(); ++it) {
  std::cout << it.key() << ':' << it.value() << '\n';
}
```

### Conversion from STL containers

Any sequence container (`std::array`, `std::vector`, `std::deque`, `std::forward_list`, `std::list`) whose values can be used to construct JSON types (e.g., integers, floating point numbers, Booleans, string types, or again STL containers described in this section) can be used to create a JSON array. The same holds for similar associative containers (`std::set`, `std::multiset`, `std::unordered_set`, `std::unordered_multiset`), but in these cases the order of the elements of the array depends how the elements are ordered in the respective STL container.

```cpp
std::vector<int> c_vector {1, 2, 3, 4};
json j_vec(c_vector);

std::set<std::string> c_set {"one", "two", "three", "four", "one"};
json j_set(c_set); // only one entry for "one" is used

std::unordered_set<std::string> c_uset {"one", "two", "three", "four", "one"};
json j_uset(c_uset); // only one entry for "one" is used

std::multiset<std::string> c_mset {"one", "two", "one", "four"};
json j_mset(c_mset); // only one entry for "one" is used

std::unordered_multiset<std::string> c_umset {"one", "two", "one", "four"};
json j_umset(c_umset); // both entries for "one" are used

std::deque<float> c_deque {1.2, 2.3, 3.4, 5.6};
json j_deque(c_deque);

std::list<bool> c_list {true, true, false, true};
json j_list(c_list);

std::forward_list<int64_t> c_flist {12345678909876, 23456789098765, 34567890987654, 45678909876543};
json j_flist(c_flist);

std::array<unsigned long, 4> c_array {{1, 2, 3, 4}};
json j_array(c_array);
```

Likewise, any associative key-value containers (`std::map`, `std::multimap`, `std::unordered_map`, `std::unordered_multimap`) whose keys are can construct an `std::string` and whose values can be used to construct JSON types (see examples above) can be used to to create a JSON object. Note that in case of multimaps only one key is used in the JSON object and the value depends on the internal order of the STL container.

```cpp
std::map<std::string, int> c_map { {"one", 1}, {"two", 2}, {"three", 3} };
json j_map(c_map);

std::unordered_map<const char*, float> c_umap { {"one", 1.2}, {"two", 2.3}, {"three", 3.4} };
json j_umap(c_umap);

std::multimap<std::string, bool> c_mmap { {"one", true}, {"two", true}, {"three", false}, {"three", true} };
json j_mmap(c_mmap); // only one entry for key "three" is used

std::unordered_multimap<std::string, bool> c_ummap { {"one", true}, {"two", true}, {"three", false}, {"three", true} };
json j_ummap(c_ummap); // only one entry for key "three" is used
```

### Implicit conversions

The type of the JSON object is determined automatically by the expression to store. Likewise, the stored value is implicitly converted.

```cpp
/// strings
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

## License

<img align="right" src="http://opensource.org/trademarks/opensource/OSI-Approved-License-100x137.png">

The class is licensed under the [MIT License](http://opensource.org/licenses/MIT):

Copyright &copy; 2013-2014 [Niels Lohmann](http://nlohmann.me)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## Thanks

I deeply appreciate the help of the following people.

- [Teemperor](https://github.com/Teemperor) implemented CMake support and lcov integration, realized escape and Unicode handling in the string parser, and fixed the JSON serialization.
- [elliotgoodrich](https://github.com/elliotgoodrich) fixed an issue with double deletion in the iterator classes.
- [kirkshoop](https://github.com/kirkshoop) made the iterators of the class composable to other libraries.
- [wancw](https://github.com/wanwc) fixed a bug that hindered the class to compile with Clang.
- Tomas Åblad found a bug in the iterator implementation.

Thanks a lot for helping out!

## Execute unit tests with CMake

To compile and run the tests, you need to execute

```sh
$ cmake .
$ make
$ ctest
```

If you want to generate a coverage report with the lcov/genhtml tools, execute this instead:

```sh
$ cmake .
$ make coverage
```

**Note: You need to use GCC for now as otherwise the target coverage doesn't exist!**

The report is now in the subfolder coverage/index.html

## Execute unit tests with automake

To compile the unit tests, you need to execute

```sh
$ autoreconf -i
$ ./configure
$ make
```

The unit tests can then be executed with

```sh
$ ./json_unit

===============================================================================
All tests passed (887 assertions in 10 test cases)
```

For more information, have a look at the file [.travis.yml](https://github.com/nlohmann/json/blob/master/.travis.yml).
