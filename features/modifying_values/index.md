# Modifying values

Once a JSON value exists, its content can be changed: elements can be added, replaced, merged, and removed. This page gives an overview of the available operations. For read access, see [element access](https://json.nlohmann.me/features/element_access/index.md).

## Adding to arrays

New elements are appended to an array with [`push_back`](https://json.nlohmann.me/api/basic_json/push_back/index.md) or constructed in place with [`emplace_back`](https://json.nlohmann.me/api/basic_json/emplace_back/index.md). If the value is `null`, it is converted to an array first, so these functions can also be used to build an array from scratch.

```
json j;                 // null
j.push_back(1);         // [1]
j.push_back(2);         // [1,2]
j.emplace_back(3);      // [1,2,3]

// operator+= is a shorthand for push_back
j += 4;                 // [1,2,3,4]
```

## Adding to objects

The most common way to add or replace a member is [`operator[]`](https://json.nlohmann.me/features/element_access/unchecked_access/index.md), which inserts the key if it does not exist yet:

```
json j;
j["name"] = "Mary";     // {"name":"Mary"}
j["name"] = "John";     // {"name":"John"}  (replaced)
```

[`emplace`](https://json.nlohmann.me/api/basic_json/emplace/index.md) inserts a member only if the key is not already present, and reports whether the insertion happened — useful for "add if absent" semantics.

## Merging objects

To merge one object into another, [`update`](https://json.nlohmann.me/api/basic_json/update/index.md) copies all members from another object, overwriting existing keys (similar to Python's `dict.update`). This is the idiomatic way to combine two objects.

Example

```
#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace nlohmann::literals;

int main()
{
    // create two JSON objects
    json o1 = R"( {"color": "red", "price": 17.99, "names": {"de": "Flugzeug"}} )"_json;
    json o2 = R"( {"color": "blue", "speed": 100, "names": {"en": "plane"}} )"_json;
    json o3 = o1;

    // add all keys from o2 to o1 (updating "color", replacing "names")
    o1.update(o2);

    // add all keys from o2 to o1 (updating "color", merging "names")
    o3.update(o2, true);

    // output updated object o1 and o3
    std::cout << std::setw(2) << o1 << '\n';
    std::cout << std::setw(2) << o3 << '\n';
}
```

Output:

```
{
  "color": "blue",
  "names": {
    "en": "plane"
  },
  "price": 17.99,
  "speed": 100
}
{
  "color": "blue",
  "names": {
    "de": "Flugzeug",
    "en": "plane"
  },
  "price": 17.99,
  "speed": 100
}
```

For a recursive merge that follows [RFC 7386](https://tools.ietf.org/html/rfc7386), see [JSON Merge Patch](https://json.nlohmann.me/features/merge_patch/index.md). To apply a sequence of well-defined edit operations, see [JSON Patch](https://json.nlohmann.me/features/json_patch/index.md).

## Removing elements

Elements are removed with [`erase`](https://json.nlohmann.me/api/basic_json/erase/index.md), which accepts an object key, an array index, or an iterator. [`clear`](https://json.nlohmann.me/api/basic_json/clear/index.md) empties a value while keeping its type, and [`operator[]`](https://json.nlohmann.me/features/element_access/unchecked_access/index.md) combined with assignment can overwrite a value entirely.

```
json j = {{"a", 1}, {"b", 2}, {"c", 3}};
j.erase("b");           // {"a":1,"c":3}

json a = {1, 2, 3, 4};
a.erase(1);             // [1,3,4]  (erase by index)
```

## See also

- [`push_back`](https://json.nlohmann.me/api/basic_json/push_back/index.md) / [`emplace_back`](https://json.nlohmann.me/api/basic_json/emplace_back/index.md) - append to an array
- [`emplace`](https://json.nlohmann.me/api/basic_json/emplace/index.md) - insert into an object if the key is absent
- [`update`](https://json.nlohmann.me/api/basic_json/update/index.md) - merge objects
- [`erase`](https://json.nlohmann.me/api/basic_json/erase/index.md) / [`clear`](https://json.nlohmann.me/api/basic_json/clear/index.md) - remove elements
- [JSON Patch and Diff](https://json.nlohmann.me/features/json_patch/index.md) and [JSON Merge Patch](https://json.nlohmann.me/features/merge_patch/index.md) - structured modifications
