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

To merge one object into another, [`update`](https://json.nlohmann.me/api/basic_json/update/index.md) copies all members from another object (similar to Python's `dict.update`). This is the idiomatic way to combine two objects. It has two modes:

- By default, the merge is shallow: existing keys are overwritten, even if both values are objects.
- With `merge_objects = #!cpp true`, keys whose values are objects in both JSON values are merged recursively. Everything else is overwritten. In particular, arrays are replaced, not concatenated.

Example

```
#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using nlohmann::json;
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

A common use of the recursive mode is combining defaults with user settings. Nested defaults that the user did not set are kept:

```
json defaults = {{"log", {{"level", "info"}, {"file", "app.log"}}}, {"retries", 3}};
json user_settings = {{"log", {{"level", "debug"}}}};

json config = defaults;
config.update(user_settings, true);
// {"log":{"file":"app.log","level":"debug"},"retries":3}
```

[JSON Merge Patch](https://json.nlohmann.me/features/merge_patch/index.md) ([RFC 7396](https://tools.ietf.org/html/rfc7396)) also merges objects recursively, but it is a different tool: a `null` in the patch means "remove this key". It is meant for applying merge patch documents (e.g., received via HTTP PATCH). To merge configuration-like objects, use `update(..., true)`. To apply a sequence of well-defined edit operations, see [JSON Patch](https://json.nlohmann.me/features/json_patch/index.md).

## Removing elements

Elements are removed with [`erase`](https://json.nlohmann.me/api/basic_json/erase/index.md), which accepts an object key, an array index, or an iterator. [`clear`](https://json.nlohmann.me/api/basic_json/clear/index.md) empties a value while keeping its type, and [`operator[]`](https://json.nlohmann.me/features/element_access/unchecked_access/index.md) combined with assignment can overwrite a value entirely.

```
json j = {{"a", 1}, {"b", 2}, {"c", 3}};
j.erase("b");           // {"a":1,"c":3}

json a = {1, 2, 3, 4};
a.erase(1);             // [1,3,4]  (erase by index)
```

## Editing a document

The operations above work on a `basic_json` value. A JSON text that was parsed into a [document](https://json.nlohmann.me/features/json_view/#editing-a-document) can also be changed in place, without building a `basic_json` tree for the parts that are not touched: [`set`](https://json.nlohmann.me/api/basic_json_document/set/index.md) replaces a value, adds or replaces an object member, or replaces an array element (also through a JSON pointer), [`push_back`](https://json.nlohmann.me/api/basic_json_document/push_back/index.md) appends to an array, [`insert`](https://json.nlohmann.me/api/basic_json_document/insert/index.md) inserts into an array (unlike `basic_json::insert`, it has no object overload; members are added with `set`), and [`erase`](https://json.nlohmann.me/api/basic_json_document/erase/index.md) removes a member or an element. These functions are available on the editable document types, such as [`json_editable_document`](https://json.nlohmann.me/api/json_editable_document/index.md).

## See also

- [`push_back`](https://json.nlohmann.me/api/basic_json/push_back/index.md) - / [`emplace_back`](https://json.nlohmann.me/api/basic_json/emplace_back/index.md) - append to an array
- [`emplace`](https://json.nlohmann.me/api/basic_json/emplace/index.md) - insert into an object if the key is absent
- [`update`](https://json.nlohmann.me/api/basic_json/update/index.md) - merge objects (shallow, or recursive with `merge_objects`)
- [`merge_patch`](https://json.nlohmann.me/api/basic_json/merge_patch/index.md) - apply an RFC 7396 merge patch
- [`erase`](https://json.nlohmann.me/api/basic_json/erase/index.md) - / [`clear`](https://json.nlohmann.me/api/basic_json/clear/index.md) - remove elements
- [JSON Patch and Diff](https://json.nlohmann.me/features/json_patch/index.md) - and [JSON Merge Patch](https://json.nlohmann.me/features/merge_patch/index.md) - structured modifications
- [Editing a document](https://json.nlohmann.me/features/json_view/#editing-a-document) - change a parsed document in place
- [`insert`](https://json.nlohmann.me/api/basic_json/insert/index.md) - insert elements at an iterator position or merge a range
- [`operator+=`](https://json.nlohmann.me/api/basic_json/operator%2B%3D/index.md) - shorthand for `push_back`
- [Element Access](https://json.nlohmann.me/features/element_access/index.md) - read elements
- [Iterators](https://json.nlohmann.me/features/iterators/index.md) - iterate over elements
