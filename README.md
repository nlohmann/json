# Yet another JSON class for C++

[![Build Status](https://travis-ci.org/nlohmann/json.png?branch=master)](https://travis-ci.org/nlohmann/json)
[![Coverage Status](https://img.shields.io/coveralls/nlohmann/json.svg)](https://coveralls.io/r/nlohmann/json)
[![Github Issues](https://img.shields.io/github/issues/nlohmann/json.svg)](http://github.com/nlohmann/json/issues)

## Design goals

There are myriads of [JSON](http://json.org) libraries out there, and each may even have its reason to exist. Our class had these design goals:

- **Trivial integration**. Our whole code consists of just two files: A header file `JSON.h` and a source file `JSON.cc`. That's it. No library, no subproject, no dependencies. The class is written in vanilla C++11. All in all, the class should require no adjustment of your compiler flags or project settings.

- **Intuitive syntax**. In languages such as Python, JSON feels like a first class data type. We used all the operator magic of C++ to achieve the same feeling in your code. Check out the [examples below](#examples) and you know, what I mean.

Other aspects were not so important to us:

- **Memory efficiency**. Each JSON object has an overhead of one pointer (the maximal size of a union) and one enumeration element (1 byte). We use the following C++ data types: `std::string` for strings, `int` or `double` for numbers, `std::map` for objects, `std::vector` for arrays, and `bool` for Booleans. We know that there are more efficient ways to store the values, but we are happy enough right now. And by the way: [Valgrind](http://valgrind.org) says our code is free of leaks.

- **Speed**. We currently implement the parser as naive [recursive descent parser](http://en.wikipedia.org/wiki/Recursive_descent_parser) with hand coded string handling. It is fast enough, but a [LALR-parser](http://en.wikipedia.org/wiki/LALR_parser) with a decent regular expression processor should be even faster (but would consist of more files which makes the integration harder).

- **Rigorous standard compliance**. We followed the [specification](http://json.org) as close as possible, but did not invest too much in a 100% compliance with respect to Unicode support. As a result, there might be edge cases of false positives and false negatives, but as long as we have a hand-written parser, we won't invest too much to be fully compliant.

## Integration

All you need to do is add

```cpp
#include "JSON.h"
```

to the files you want to use JSON objects. Furthermore, you need to compile the file `JSON.cc` and link it to your binaries.

## Examples

Here are some examples to give you an idea how to use the class:

```cpp
// create an empty structure
JSON j;

// add a number that is stored as double
j["pi"] = 3.141;

// add a Boolean that is stored as bool
j["happy"] = true;

// add a string that is stored as std::string
j["name"] = "Niels";

// add a null object
j["nothing"] = nullptr;

// add an object inside the object
j["further"]["entry"] = 42;

// add an array that is stored as std::vector
j["list"] = { 1, 0, 2 };

// add another object
j["object"] = { {"currency", "USD"}, {"value", "42.99"} };
```

### Input / Output

```cpp
// create object from stream
JSON j;
j << "{ \"pi\": 3.141, \"happy\": true }";

// write string representation to stream
std::cout << j;
```

These operators work for any subclasses of `std::istream` or `std::ostream`.

```cpp
// create object from string literal
JSON j = "{ \"pi\": 3.141, \"happy\": true }"_json;
```

### STL-like access

```cpp
// create an array
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

// other stuff
j.size();     // 3
j.empty();    // false
j.type();     // JSON::valeu_type::array

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

The type of the JSON object is determined automatically by the expression to store. Likewise, the stored value is implicitly converted 

```cpp
/// strings
std::string s1 = "Hello, world!";
JSON js = s;
std::string s2 = j;

// Booleans
bool b1 = true;
JSON jb = b1;
bool b2 = jb;

// numbers
int i = 42;
JSON jn = i;
double f = jn;
```

