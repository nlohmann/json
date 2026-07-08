# nlohmann::basic_json::count

```
// (1)
size_type count(const typename object_t::key_type& key) const;

// (2)
template<typename KeyType>
size_type count(KeyType&& key) const;
```

1. Returns the number of elements with key `key`. If `ObjectType` is the default `std::map` type, the return value will always be `0` (`key` was not found) or `1` (`key` was found).
1. See 1. This overload is only available if `KeyType` is comparable with `typename object_t::key_type` and `typename object_comparator_t::is_transparent` denotes a type.

## Template parameters

`KeyType` : A type for an object key other than [`json_pointer`](https://json.nlohmann.me/api/json_pointer/index.md) that is comparable with [`string_t`](https://json.nlohmann.me/api/basic_json/string_t/index.md) using [`object_comparator_t`](https://json.nlohmann.me/api/basic_json/object_comparator_t/index.md). This can also be a string view (C++17).

## Parameters

`key` (in) : key value of the element to count.

## Return value

Number of elements with key `key`. If the JSON value is not an object, the return value will be `0`.

## Exception safety

Strong exception safety: if an exception occurs, the original value stays intact.

## Complexity

Logarithmic in the size of the JSON object.

## Notes

This method always returns `0` when executed on a JSON type that is not an object.

## Examples

Example: (1) count number of elements

The example shows how `count()` is used.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create a JSON object
    json j_object = {{"one", 1}, {"two", 2}};

    // call count()
    auto count_two = j_object.count("two");
    auto count_three = j_object.count("three");

    // print values
    std::cout << "number of elements with key \"two\": " << count_two << '\n';
    std::cout << "number of elements with key \"three\": " << count_three << '\n';
}
```

Output:

```
number of elements with key "two": 1
number of elements with key "three": 0
```

Example: (2) count number of elements using string_view

The example shows how `count()` is used.

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

    // call count()
    auto count_two = j_object.count("two"sv);
    auto count_three = j_object.count("three"sv);

    // print values
    std::cout << "number of elements with key \"two\": " << count_two << '\n';
    std::cout << "number of elements with key \"three\": " << count_three << '\n';
}
```

Output:

```
number of elements with key "two": 1
number of elements with key "three": 0
```

## See also

- [find](https://json.nlohmann.me/api/basic_json/find/index.md) find a value in an object
- [contains](https://json.nlohmann.me/api/basic_json/contains/index.md) checks whether a key exists

## Version history

1. Added in version 3.11.0.
1. Added in version 1.0.0. Changed parameter `key` type to `KeyType&&` in version 3.11.0.
