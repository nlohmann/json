# Element Access

There are many ways elements in a JSON value can be accessed:

- unchecked access via [`operator[]`](https://json.nlohmann.me/features/element_access/unchecked_access/index.md)
- checked access via [`at`](https://json.nlohmann.me/features/element_access/checked_access/index.md)
- access with default value via [`value`](https://json.nlohmann.me/features/element_access/default_value/index.md)
- [iterators](https://json.nlohmann.me/features/iterators/index.md)
- [JSON pointers](https://json.nlohmann.me/features/json_pointer/index.md)

Testing whether a key or index exists before accessing it is also possible, with [`contains`](https://json.nlohmann.me/api/basic_json/contains/index.md) or [`find`](https://json.nlohmann.me/api/basic_json/find/index.md) (which returns an iterator to the value, or `end()` if it is not found).

How do I get a value out? Start at the top and follow the first question that applies:

```
flowchart TD
    A["getting a value out"] --> P{{"nested path such as /server/port?"}}
    P -->|"yes"| JP["JSON Pointer: at(ptr), value(ptr, default), contains(ptr)"]
    P -->|"no, one key or index"| T{{"only testing whether it exists?"}}
    T -->|"yes"| CF["contains() / find()"]
    T -->|"no"| M{{"may it be missing?"}}
    M -->|"yes, a fallback is fine"| V["value(key, default)"]
    M -->|"yes, and missing is an error"| AT["at(): throws out_of_range"]
    M -->|"no, it exists and its type is known"| OP["operator[] and get#lt;T#gt;()"]
    OP -.- W["non-const operator[] inserts null for a missing key"]
```

Decision tree for reading a value: the labels on the arrows are the answers to the questions, and the boxes name the functions to use. The dashed line marks a side effect of the non-const `operator[]`.

## Does this key exist?

Use [`contains`](https://json.nlohmann.me/api/basic_json/contains/index.md) to test for a key; it does not modify the value and does not throw:

```
json j = {{"name", "Mary"}, {"address", {{"city", "Berlin"}}}};

j.contains("name");                   // true
j.contains("age");                    // false
j.contains("city");                   // false: contains() only looks at the top level
j["address"].contains("city");        // true
j.contains(json::json_pointer("/address/city"));  // true: a JSON pointer tests a nested path in one call
```

If the value is needed afterwards, [`find`](https://json.nlohmann.me/api/basic_json/find/index.md) tests and accesses with a single lookup:

```
if (auto it = j.find("name"); it != j.end())
{
    std::cout << *it << '\n';
}
```

`contains` also returns `true` for a key whose value is `null`; use `j.contains("k") && !j["k"].is_null()` if a `null` should count as missing. To read a value with a fallback instead, see [`value`](https://json.nlohmann.me/features/element_access/default_value/index.md).

`operator[]` inserts missing keys

Like `std::map::operator[]`, the non-const [`operator[]`](https://json.nlohmann.me/features/element_access/unchecked_access/index.md) adds a `null` value if the key is missing. Testing a key with it therefore *changes the object*:

```
json j = {{"foo", 1}};
bool absent = j["bar"].is_null();   // true, but j is now {"bar": null, "foo": 1}
```

Use `contains`/`find` to test, and [`at`](https://json.nlohmann.me/features/element_access/checked_access/index.md) to access a value that must exist (it throws an [`out_of_range`](https://json.nlohmann.me/home/exceptions/#out-of-range) exception otherwise).

## See also

- [`operator[]`](https://json.nlohmann.me/api/basic_json/operator%5B%5D/index.md) - unchecked access
- [`at`](https://json.nlohmann.me/api/basic_json/at/index.md) - checked access
- [`value`](https://json.nlohmann.me/api/basic_json/value/index.md) - access with default value
- [`contains`](https://json.nlohmann.me/api/basic_json/contains/index.md) - and [`find`](https://json.nlohmann.me/api/basic_json/find/index.md) - test for existence
- [`front`](https://json.nlohmann.me/api/basic_json/front/index.md) - and [`back`](https://json.nlohmann.me/api/basic_json/back/index.md) - first and last element
- [`items`](https://json.nlohmann.me/api/basic_json/items/index.md) - iterate over keys and values
- [Checked access: at](https://json.nlohmann.me/features/element_access/checked_access/index.md) - access with range checking
- [Unchecked access: operator[]](https://json.nlohmann.me/features/element_access/unchecked_access/index.md) - access without range checking
- [Access with default value: value](https://json.nlohmann.me/features/element_access/default_value/index.md) - fall back to a default instead of throwing
- [Iterators](https://json.nlohmann.me/features/iterators/index.md) - visit all elements of arrays and objects
- [JSON Pointer](https://json.nlohmann.me/features/json_pointer/index.md) - address nested values with a single string
- [Modifying values](https://json.nlohmann.me/features/modifying_values/index.md) - add, merge and remove elements
- [`basic_json`](https://json.nlohmann.me/api/basic_json/index.md) - all member functions
