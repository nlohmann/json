# nlohmann::basic_json::find

```
// (1)
iterator find(const typename object_t::key_type& key);
const_iterator find(const typename object_t::key_type& key) const;

// (2)
template<typename KeyType>
iterator find(KeyType&& key);
template<typename KeyType>
const_iterator find(KeyType&& key) const;
```

1. Finds an element in a JSON object with a key equivalent to `key`. If the element is not found or the JSON value is not an object, `end()` is returned.
1. See 1. This overload is only available if `KeyType` is comparable with `typename object_t::key_type` and `typename object_comparator_t::is_transparent` denotes a type.

## Template parameters

`KeyType` : A type for an object key other than [`json_pointer`](https://json.nlohmann.me/api/json_pointer/index.md) that is comparable with [`string_t`](https://json.nlohmann.me/api/basic_json/string_t/index.md) using [`object_comparator_t`](https://json.nlohmann.me/api/basic_json/object_comparator_t/index.md). This can also be a string view (C++17).

## Parameters

`key` (in) : key value of the element to search for.

## Return value

Iterator to an element with a key equivalent to `key`. If no such element is found or the JSON value is not an object, a past-the-end iterator (see `end()`) is returned.

## Exception safety

Strong exception safety: if an exception occurs, the original value stays intact.

## Complexity

Logarithmic in the size of the JSON object.

## Notes

This method always returns `end()` when executed on a JSON type that is not an object.

## Examples

Example: (1) find object element by key

The example shows how `find()` is used.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create a JSON object
    json j_object = {{"one", 1}, {"two", 2}};

    // call find
    auto it_two = j_object.find("two");
    auto it_three = j_object.find("three");

    // print values
    std::cout << std::boolalpha;
    std::cout << "\"two\" was found: " << (it_two != j_object.end()) << '\n';
    std::cout << "value at key \"two\": " << *it_two << '\n';
    std::cout << "\"three\" was found: " << (it_three != j_object.end()) << '\n';
}
```

Output:

```
"two" was found: true
value at key "two": 2
"three" was found: false
```

Example: (2) find object element by key using string_view

The example shows how `find()` is used.

```
#include <iostream>
#include <string_view>
#include <nlohmann/json.hpp>

using namespace std::string_view_literals;
using json = nlohmann::json;

int main()
{
    // create a JSON object
    json j_object = {{"one", 1}, {"two", 2}};

    // call find
    auto it_two = j_object.find("two"sv);
    auto it_three = j_object.find("three"sv);

    // print values
    std::cout << std::boolalpha;
    std::cout << "\"two\" was found: " << (it_two != j_object.end()) << '\n';
    std::cout << "value at key \"two\": " << *it_two << '\n';
    std::cout << "\"three\" was found: " << (it_three != j_object.end()) << '\n';
}
```

Output:

```
"two" was found: true
value at key "two": 2
"three" was found: false
```

## See also

- [count](https://json.nlohmann.me/api/basic_json/count/index.md) returns the number of occurrences of a key
- [contains](https://json.nlohmann.me/api/basic_json/contains/index.md) checks whether a key exists

## Version history

1. Added in version 3.11.0.
1. Added in version 1.0.0. Changed to support comparable types in version 3.11.0.
