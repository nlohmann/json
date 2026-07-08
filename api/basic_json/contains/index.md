# nlohmann::basic_json::contains

```
// (1)
bool contains(const typename object_t::key_type& key) const;

// (2)
template<typename KeyType>
bool contains(KeyType&& key) const;

// (3)
bool contains(const json_pointer& ptr) const;
```

1. Check whether an element exists in a JSON object with a key equivalent to `key`. If the element is not found or the JSON value is not an object, `false` is returned.
1. See 1. This overload is only available if `KeyType` is comparable with `typename object_t::key_type` and `typename object_comparator_t::is_transparent` denotes a type.
1. Check whether the given JSON pointer `ptr` can be resolved in the current JSON value.

## Template parameters

`KeyType` : A type for an object key other than [`json_pointer`](https://json.nlohmann.me/api/json_pointer/index.md) that is comparable with [`string_t`](https://json.nlohmann.me/api/basic_json/string_t/index.md) using [`object_comparator_t`](https://json.nlohmann.me/api/basic_json/object_comparator_t/index.md). This can also be a string view (C++17).

## Parameters

`key` (in) : key value to check its existence.

`ptr` (in) : JSON pointer to check its existence.

## Return value

1. `true` if an element with specified `key` exists. If no such element with such a key is found or the JSON value is not an object, `false` is returned.
1. See 1.
1. `true` if the JSON pointer can be resolved to a stored value, `false` otherwise.

## Exception safety

Strong exception safety: if an exception occurs, the original value stays intact.

## Exceptions

1. The function does not throw exceptions.
1. The function does not throw exceptions.
1. The function does not throw exceptions.

## Complexity

Logarithmic in the size of the JSON object.

## Notes

- This method always returns `false` when executed on a JSON type that is not an object.
- This method can be executed on any JSON value type.

Postconditions

If `j.contains(x)` returns `true` for a key or JSON pointer `x`, then it is safe to call `j[x]`.

## Examples

Example: (1) check with key

The example shows how `contains()` is used.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace nlohmann::literals;

int main()
{
    // create some JSON values
    json j_object = R"( {"key": "value"} )"_json;
    json j_array = R"( [1, 2, 3] )"_json;

    // call contains
    std::cout << std::boolalpha <<
              "j_object contains 'key': " << j_object.contains("key") << '\n' <<
              "j_object contains 'another': " << j_object.contains("another") << '\n' <<
              "j_array contains 'key': " << j_array.contains("key") << std::endl;
}
```

Output:

```
j_object contains 'key': true
j_object contains 'another': false
j_array contains 'key': false
```

Example: (2) check with key using string_view

The example shows how `contains()` is used.

```
#include <iostream>
#include <string_view>
#include <nlohmann/json.hpp>

using namespace std::string_view_literals;
using json = nlohmann::json;
using namespace nlohmann::literals;

int main()
{
    // create some JSON values
    json j_object = R"( {"key": "value"} )"_json;
    json j_array = R"( [1, 2, 3] )"_json;

    // call contains
    std::cout << std::boolalpha <<
              "j_object contains 'key': " << j_object.contains("key"sv) << '\n' <<
              "j_object contains 'another': " << j_object.contains("another"sv) << '\n' <<
              "j_array contains 'key': " << j_array.contains("key"sv) << std::endl;
}
```

Output:

```
j_object contains 'key': true
j_object contains 'another': false
j_array contains 'key': false
```

Example: (3) check with JSON pointer

The example shows how `contains()` is used.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace nlohmann::literals;

int main()
{
    // create a JSON value
    json j =
    {
        {"number", 1}, {"string", "foo"}, {"array", {1, 2}}
    };

    std::cout << std::boolalpha
              << j.contains("/number"_json_pointer) << '\n'
              << j.contains("/string"_json_pointer) << '\n'
              << j.contains("/array"_json_pointer) << '\n'
              << j.contains("/array/1"_json_pointer) << '\n'
              << j.contains("/array/-"_json_pointer) << '\n'
              << j.contains("/array/4"_json_pointer) << '\n'
              << j.contains("/baz"_json_pointer) << std::endl;

    try
    {
        // try to use an array index with leading '0'
        j.contains("/array/01"_json_pointer);
    }
    catch (const json::parse_error& e)
    {
        std::cout << e.what() << '\n';
    }

    try
    {
        // try to use an array index that is not a number
        j.contains("/array/one"_json_pointer);
    }
    catch (const json::parse_error& e)
    {
        std::cout << e.what() << '\n';
    }
}
```

Output:

```
true
true
true
true
false
false
false
```

## See also

- [find](https://json.nlohmann.me/api/basic_json/find/index.md) find a value in an object
- [count](https://json.nlohmann.me/api/basic_json/count/index.md) returns the number of occurrences of a key

## Version history

1. Added in version 3.11.0.
1. Added in version 3.6.0. Extended template `KeyType` to support comparable types in version 3.11.0.
1. Added in version 3.7.0.
