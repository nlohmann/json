# JSON for Modern C++

*What if JSON was party of modern C++?*

[![Build Status](https://travis-ci.org/nlohmann/json.png?branch=master)](https://travis-ci.org/nlohmann/json)
[![Coverage Status](https://img.shields.io/coveralls/nlohmann/json.svg)](https://coveralls.io/r/nlohmann/json)
[![Github Issues](https://img.shields.io/github/issues/nlohmann/json.svg)](http://github.com/nlohmann/json/issues)

## Design goals

There are myriads of [JSON](http://json.org) libraries out there, and each may even have its reason to exist. Our class had these design goals:

- **Intuitive syntax**. In languages such as Python, JSON feels like a first class data type. We used all the operator magic of modern C++ to achieve the same feeling in your code. Check out the [examples below](#examples) and the [reference](https://github.com/nlohmann/json/blob/master/doc/Reference.md), and you know, what I mean.

- **Trivial integration**. Our whole code consists of a class in just two files: A header file `JSON.h` and a source file `JSON.cc`. That's it. No library, no subproject, no dependencies. The class is written in vanilla C++11. All in all, everything should require no adjustment of your compiler flags or project settings.

- **Serious testing**. Our class is heavily [unit-tested](https://github.com/nlohmann/json/blob/master/test/JSON_unit.cc) and covers [100%](https://coveralls.io/r/nlohmann/json) of the code, including all exceptional behavior. Furthermore, we checked with [Valgrind](http://valgrind.org) that there are no memory leaks.

Other aspects were not so important to us:

- **Memory efficiency**. Each JSON object has an overhead of one pointer (the maximal size of a union) and one enumeration element (1 byte). We use the following C++ data types: `std::string` for strings, `int` or `double` for numbers, `std::map` for objects, `std::vector` for arrays, and `bool` for Booleans. We know that there are more efficient ways to store the values, but we are happy enough right now.

- **Speed**. We currently implement the parser as naive [recursive descent parser](http://en.wikipedia.org/wiki/Recursive_descent_parser) with hand coded string handling. It is fast enough, but a [LALR-parser](http://en.wikipedia.org/wiki/LALR_parser) with a decent regular expression processor should be even faster (but would consist of more files which makes the integration harder).

- **Rigorous standard compliance**. Any [compliant](http://json.org) JSON file can be read by our class, and any output of the class is standard-compliant. However, we do not check for some details in the format of numbers and strings. For instance, `-0` will be treated as `0` whereas the standard forbids this. Furthermore, we allow for more escape symbols in strings as the JSON specification. While this may not be a problem in reality, we are aware of it, but as long as we have a hand-written parser, we won't invest too much to be fully compliant.

## Integration

All you need to do is add

```cpp
#include "JSON.h"
```

to the files you want to use JSON objects. Furthermore, you need to compile the file `JSON.cc` and link it to your binaries. Do not forget to set the necessary switches to enable C++11 (e.g., `-std=c++11` for GCC and Clang).

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
    "value": "42.99"
  }
}
```

With the JSON class, you could write:

```cpp
// create an empty structure (null)
JSON j;

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
j["object"] = { {"currency", "USD"}, {"value", "42.99"} };

// instead, you could also write (which looks very similar to the JSON above)
JSON j2 = {
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
    {"value", "42.99"}
  }}
};
*/
```

Note that in all cases, you never need to "tell" the compiler which JSON value you want to use.

### Serialization / Deserialization

You can create an object (deserialization) by appending `_json` to a string literal:

```cpp
// create object from string literal
JSON j = "{ \"pi\": 3.141, \"happy\": true }"_json;
```

You can also get a string representation (serialize):

```cpp
// explicit conversion to string
std::string s = j.toString();
```

The value of s could be `{"pi": 3.141, "happy": true}`, but the order of the entries in the object is not fixed.

You can also use streams to serialize and deserialize:

```cpp
// deserialize from standard input
JSON j;
j << std::cin;

// serialize to standard output
std::cout << j;
```

These operators work for any subclasses of `std::istream` or `std::ostream`.

### STL-like access

We designed the JSON class to behave just like an STL container:

```cpp
// create an array using push_back
JSON j;
j.push_back("foo");
j.push_back(1);
j.push_back(true);

// iterate the array
for (JSON::iterator it = j.begin(); it != j.end(); ++it) {
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
j.type();     // JSON::value_type::array
j.clear();    // the array is empty again

// create an object
JSON o;
o["foo"] = 23;
o["bar"] = false;
o["baz"] = 3.141;

// find an entry
if (o.find("foo") != o.end()) {
  // there is an entry with key "foo"
}

// iterate the object
for (JSON::iterator it = o.begin(); it != o.end(); ++it) {
  std::cout << it.key() << ':' << it.value() << '\n';
}
```

### Implicit conversions

The type of the JSON object is determined automatically by the expression to store. Likewise, the stored value is implicitly converted.

```cpp
/// strings
std::string s1 = "Hello, world!";
JSON js = s1;
std::string s2 = js;

// Booleans
bool b1 = true;
JSON jb = b1;
bool b2 = jb;

// numbers
int i = 42;
JSON jn = i;
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

## Execute unit tests

To compile the unit tests, you need to execute

```sh
  autoreconf -i
  ./configure
  make
```

The unit tests can then be executed with

```sh
./json_unit
```

For more information, have a look at the file [.travis.yml](https://github.com/nlohmann/json/blob/master/.travis.yml).
