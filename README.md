# Yet another JSON class for C++

[![Build Status](https://travis-ci.org/nlohmann/json.png?branch=master)](https://travis-ci.org/nlohmann/json)

## Design goals

There are myriads of [JSON](http://json.org) libraries out there, and each may even have its reason to exist. Our class had these design goals:

- **Trivial integration**. Our whole code consists of just two files: A header file `JSON.h` and a source file `JSON.cc`. That's it. No library, no subproject, no dependencies. The class is written in vanilla C++98 and -- if possible -- uses some features of C++11 such as move constructors. All in all, the class should require no adjustment of your compiler flags or project settings.

- **Intiuitve syntax**. In languages such as Python, JSON feels like a first class data type. We used all the operator magic of C++ to achieve the same feeling in your code. Check out the examples below and you know, what I mean.

Other aspects were not so important to us:

- **Memory efficiency**. Each JSON object has an overhead of one pointer and one enumeration element (1 byte). We use the following C++ data types: `std::string` for strings, `int` or `double` for numbers, `std::map` for objects, `std::vector` for arrays, and `bool` for Booleans. We know that there are more efficient ways to store the values, but we are happy enough right now. And by the way: [Valgrind](http://valgrind.org) says our code is free of leaks.

- **Speed**. We currently implement the parser as naive [recursive descent parser](http://en.wikipedia.org/wiki/Recursive_descent_parser) with hand coded string handling. It is fast enough, but a [LALR-parser](http://en.wikipedia.org/wiki/LALR_parser) with a decent regular expression processor should be even faster.

- **Rigourous standard compliance**. We followed the [specification](http://json.org) as close as possible, but did not invest too much in a 100% compliance with respect to Unicode support. As a result, there might be edge cases of false positives and false negatives, but as long as we have a hand-written parser, we won't invest too much to be fully compliant.

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

// add an object inside the object
j["further"]["entry"] = 42;

// add an array that is stored as std::vector
j["list"] = { 1, 0, 2 };
```

## Input / Output

## STL-like access

