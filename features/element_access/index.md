# Element Access

There are many ways elements in a JSON value can be accessed:

- unchecked access via [`operator[]`](https://json.nlohmann.me/features/element_access/unchecked_access/index.md)
- checked access via [`at`](https://json.nlohmann.me/features/element_access/checked_access/index.md)
- access with default value via [`value`](https://json.nlohmann.me/features/element_access/default_value/index.md)
- [iterators](https://json.nlohmann.me/features/iterators/index.md)
- [JSON pointers](https://json.nlohmann.me/features/json_pointer/index.md)

Testing whether a key or index exists before accessing it is also possible, with [`contains`](https://json.nlohmann.me/api/basic_json/contains/index.md) or [`find`](https://json.nlohmann.me/api/basic_json/find/index.md) (which returns an iterator to the value, or `end()` if it is not found).

```
flowchart TD
    A["accessing a value"] --> B{"must it exist?"}
    B -->|"yes, missing is an error"| C["at() -- throws"]
    B -->|"yes, but checking is my job"| D["operator[] -- unchecked"]
    B -->|"no, a fallback is fine"| E["value() -- default value"]
    A --> F{"just testing first?"}
    F -->|"yes"| G["contains() / find()"]
```

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

- [**operator[]**](https://json.nlohmann.me/api/basic_json/operator%5B%5D/index.md) - unchecked access
- [**at**](https://json.nlohmann.me/api/basic_json/at/index.md) - checked access
- [**value**](https://json.nlohmann.me/api/basic_json/value/index.md) - access with default value
- [**contains**](https://json.nlohmann.me/api/basic_json/contains/index.md) and [**find**](https://json.nlohmann.me/api/basic_json/find/index.md) - test for existence
- [**front**](https://json.nlohmann.me/api/basic_json/front/index.md) and [**back**](https://json.nlohmann.me/api/basic_json/back/index.md) - first and last element
- [**items**](https://json.nlohmann.me/api/basic_json/items/index.md) - iterate over keys and values
