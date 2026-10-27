<!--
Feature slides for the animated slideshow. build.py adds the title slide before them and the closing slide after them.

# Title            one slide per heading; `{badge: TEXT}` at the end adds a red chip
- bullet           bullets; a long bullet may continue on indented lines
```cpp ... ```     the code shown on the right (a line starting with `$ ` is a shell command)
-->

# Trivial integration

- single header file
- no build system needed
- vanilla C++11
- works with GCC 4.8+, Clang 3.4+ and MSVC 2015+

```cpp
#include <nlohmann/json.hpp>

// for convenience
using json = nlohmann::json;

int main()
{
    // a JSON pretty-printer in 3 lines
    json j;
    std::cin >> j;
    std::cout << std::setw(4) << j << std::endl;
}

$ g++ pretty.cpp -std=c++11 -o pretty
```

# First-class datatype

- write JSON like any other C++ literal
- initializer lists become arrays and objects

```cpp
json j = {
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

# Array construction

- arrays work the way you expect
- adding to a null value makes it an array

```cpp
// create null value
json j;

// add via member function
j.push_back("Hello");
j.emplace_back("World");

// add via += operator
j += false;

// add via index
j[2] = 42.3;

// gaps are filled with null
j[4] = "World";
```

# Object construction

- objects work the way you expect
- adding to a null value makes it an object

```cpp
// create null value
json j;

// add via member function
j.emplace("key2", "value");
j.push_back({"key", "value"});

// add via += operator
j += {"another key", false};

// add via key
j["pi"] = 3.1415926;
j["answer"]["everything"] = 42;
```

# Container operations

- use JSON like an STL container
- satisfies the ReversibleContainer requirements

```cpp
// container empty?
j.empty();

// current number of elements
j.size();

// maximal number of elements
j.max_size();

// swap elements
j.swap(j2);
std::swap(j, j2);

// clear a container
j.clear();
```

# STL containers

- switch between STL and JSON containers
- conversion works in both directions

```cpp
// some STL containers
std::vector<int> v;
std::unordered_map<std::string, bool> m;

// automatic transformation
json j_array(v);
json j_object(m);

// works both ways
auto l = j_array.get<std::list<int>>();
auto u = j_object
    .get<std::map<std::string, bool>>();
```

# Type conversion

- convert your own types to and from JSON
- one macro writes to_json and from_json
- or write both functions for full control

```cpp
// some user-defined type
struct person {
    std::string name;
    int age;
};

// defines to_json and from_json
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(person,
                                   name, age)

// conversion in action
person p {"Ned Flanders", 60};
json j = p;
// {"age": 60, "name": "Ned Flanders"}

auto p2 = j.get<person>();
```

# Type deduction

- types are deduced automatically
- member functions tell you the type

```cpp
// type deduction
json j1 = nullptr;
json j2 = false;
json j3 = 12.23;
json j4 = {1, 2, 3};
json j5 = {{"key", "value"}};
json j6 = "Hello";

// quick checks
j1.is_null();
j2.is_boolean();
j3.is_number();
j4.is_array();
j5.is_object();
j6.is_string();
```

# Serialization

- to a string or a stream
- pretty-printing included

```cpp
// default serialization
auto s1 = j.dump();

// pretty-printed
int indent = 4;
std::string s2 = j.dump(indent);

// to stream
std::cout << j << std::endl;

// pretty-printed
std::cout << std::setw(indent) << j << std::endl;
```

# Deserialization

- parse strings, streams and files
- the _json literal puts plain JSON in your code
- comments and trailing commas on request

```cpp
// from string
json j1 = json::parse("[1,null,false]");

// from file
std::ifstream f("example.json");
json j2 = json::parse(f);

// from string literal
json j3 = "[3.14159]"_json;

// from raw string literal
json j4 = R"(
  {"one": 1, "two": 2, "three": [1, 2, 3]}
)"_json;
```

# SAX parsing

- the parser can emit SAX events
- process input without building a JSON value

```cpp
// define a SAX event processor
struct sax_processor : json::json_sax_t
{
    bool boolean(bool val) override
    {
        return true;
    }

    // implement other functions...
};

// create object
sax_processor my_processor;

// use it to process input
json::sax_parse(input, &my_processor);
```

# Zero-copy views {badge: NEW IN 3.13}

- parse without building a tree: 16 bytes per value
- strings and numbers stay in the source text
- materialize a json value only where you need one

```cpp
#include <nlohmann/json_view.hpp>

// parse into a flat index, not a tree
std::ifstream f("big.json");
auto doc = nlohmann::json_document::parse(f);

// read-only views with familiar access
auto view = doc.root();
double pi = view["pi"].get<double>();
for (auto v : view["list"])
    std::cout << v.get<int>() << '\n';

// build a json value only where needed
json part = view["list"].materialize();
```

# JSON Pointer

- address any element with a JSON Pointer
- flatten a value to pointer/value pairs, and back

```cpp
json j = {"good", "bad", "ugly"};

// JSON pointer to the 3rd list element
auto ptr = json::json_pointer("/2");

// use JSON pointer to access element
j[ptr] = {{"it", "cattivo"}};

// user-defined string literal
j["/2/en"_json_pointer] = "ugly";
// ["good","bad",{"en":"ugly","it":"cattivo"}]

json flat = j.flatten();
// {"/0":"good","/1":"bad","/2/en":"ugly",
//  "/2/it":"cattivo"}

json j2 = flat.unflatten();  // j == j2
```

# JSON Patches

- use JSON Patch to describe edit operations
- create diffs from two JSON values
- or use a JSON Merge Patch that looks like the document

```cpp
json source = R"({"F": "Paris", "D": "Berlin"})"_json;

// a JSON Patch (RFC 6902)
json p1 = R"([
  {"op": "add", "path": "/GB", "value": "London"}
])"_json;
json target = source.patch(p1);

// create a diff from two JSON values
json p2 = json::diff(target, source);
// [{"op": "remove", "path": "/GB"}]

// a JSON Merge Patch (RFC 7396)
target.merge_patch(R"({"F": null})"_json);
// {"D": "Berlin", "GB": "London"}
```

# Binary formats

- compact binary representations
- BJData, BON8, BSON, CBOR, MessagePack and UBJSON

```cpp
// a JSON value
json j = R"({"compact": true, "schema": 0})"_json;

// serialize to CBOR
std::vector<std::uint8_t> v = json::to_cbor(j);
// 0xA2, 0x67, 0x63, 0x6F, 0x6D, 0x70, 0x61,
// 0x63, 0x74, 0xF5, 0x66, 0x73, 0x63, 0x68,
// 0x65, 0x6D, 0x61, 0x00

// roundtrip
json j_from_cbor = json::from_cbor(v);

// the same for the other formats
auto b = json::to_bon8(j);
auto m = json::to_msgpack(j);
```

# Algorithms

- the standard algorithms just work
- sort, find, count, merge and more

```cpp
// sort JSON containers
std::sort(j.begin(), j.end());

// find element
auto pos = std::find(j.begin(), j.end(),
                     json("needle"));

// count all numbers
auto n = std::count_if(j.begin(), j.end(),
    [](const json& v) { return v.is_number(); });

// merge two sorted containers
std::merge(j1.begin(), j1.end(),
           j2.begin(), j2.end(),
           std::back_inserter(j3));
```

# Iterators

- iterators, const iterators, and reverse iterators
- random access for arrays
- items() gives you keys and values

```cpp
json j = {1, 2, 3, 4, 5};

// range for
for (auto& el : j)
{
    // print all values
    std::cerr << el << '\n';
}

// classical iterators
for (auto it = j.begin(); it != j.end(); ++it)
{
    // double all values
    *it = it->get<int>() * 2;
}
```

# Structured bindings

- since C++17, unpack keys and values with structured bindings

```cpp
// JSON object
auto j = R"({"foo": 23, "bar": 42})"_json;

// structured bindings
for (auto& [key, val] : j.items())
{
    std::cerr << key << ':' << val << '\n';
}
```
