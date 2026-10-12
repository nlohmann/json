# Modifying values

Once a JSON value exists, its content can be changed: elements can be added, replaced, merged, and removed. This page
gives an overview of the available operations. For read access, see [element access](element_access/index.md).

## Adding to arrays

New elements are appended to an array with [`push_back`](../api/basic_json/push_back.md) or constructed in place with
[`emplace_back`](../api/basic_json/emplace_back.md). If the value is `#!json null`, it is converted to an array first, so
these functions can also be used to build an array from scratch.

```cpp
json j;                 // null
j.push_back(1);         // [1]
j.push_back(2);         // [1,2]
j.emplace_back(3);      // [1,2,3]

// operator+= is a shorthand for push_back
j += 4;                 // [1,2,3,4]
```

## Adding to objects

The most common way to add or replace a member is [`operator[]`](element_access/unchecked_access.md), which inserts the
key if it does not exist yet:

```cpp
json j;
j["name"] = "Mary";     // {"name":"Mary"}
j["name"] = "John";     // {"name":"John"}  (replaced)
```

[`emplace`](../api/basic_json/emplace.md) inserts a member only if the key is not already present, and reports whether
the insertion happened — useful for "add if absent" semantics.

## Merging objects

To merge one object into another, [`update`](../api/basic_json/update.md) copies all members from another object
(similar to Python's `dict.update`). This is the idiomatic way to combine two objects. It has two modes:

- By default, the merge is shallow: existing keys are overwritten, even if both values are objects.
- With `merge_objects = #!cpp true`, keys whose values are objects in both JSON values are merged recursively.
  Everything else is overwritten. In particular, arrays are replaced, not concatenated.

??? example

    ```cpp
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

    ```json
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

A common use of the recursive mode is combining defaults with user settings. Nested defaults that the user did not set
are kept:

```cpp
json defaults = {{"log", {{"level", "info"}, {"file", "app.log"}}}, {"retries", 3}};
json user_settings = {{"log", {{"level", "debug"}}}};

json config = defaults;
config.update(user_settings, true);
// {"log":{"file":"app.log","level":"debug"},"retries":3}
```

[JSON Merge Patch](merge_patch.md) ([RFC 7386](https://tools.ietf.org/html/rfc7386)) also merges objects recursively,
but it is a different tool: a `#!json null` in the patch means "remove this key". It is meant for applying merge patch
documents (e.g., received via HTTP PATCH). To merge configuration-like objects, use `#!cpp update(..., true)`. To apply
a sequence of well-defined edit operations, see [JSON Patch](json_patch.md).

## Removing elements

Elements are removed with [`erase`](../api/basic_json/erase.md), which accepts an object key, an array index, or an
iterator. [`clear`](../api/basic_json/clear.md) empties a value while keeping its type, and
[`operator[]`](element_access/unchecked_access.md) combined with assignment can overwrite a value entirely.

```cpp
json j = {{"a", 1}, {"b", 2}, {"c", 3}};
j.erase("b");           // {"a":1,"c":3}

json a = {1, 2, 3, 4};
a.erase(1);             // [1,3,4]  (erase by index)
```

## See also

- [`push_back`](../api/basic_json/push_back.md) / [`emplace_back`](../api/basic_json/emplace_back.md) - append to an array
- [`emplace`](../api/basic_json/emplace.md) - insert into an object if the key is absent
- [`update`](../api/basic_json/update.md) - merge objects (shallow, or recursive with `merge_objects`)
- [`merge_patch`](../api/basic_json/merge_patch.md) - apply an RFC 7386 merge patch
- [`erase`](../api/basic_json/erase.md) / [`clear`](../api/basic_json/clear.md) - remove elements
- [JSON Patch and Diff](json_patch.md) and [JSON Merge Patch](merge_patch.md) - structured modifications
