# nlohmann::basic_json::value

```
// (1)
template<class ValueType>
ValueType value(const typename object_t::key_type& key,
                ValueType&& default_value) const;

// (2)
template<class ValueType, class KeyType>
ValueType value(KeyType&& key,
                ValueType&& default_value) const;

// (3)
template<class ValueType>
ValueType value(const json_pointer& ptr,
                const ValueType& default_value) const;
```

1. Returns either a copy of an object's element at the specified key `key` or a given default value if no element with key `key` exists.

   The function is basically equivalent to executing

   ```
   try {
      return at(key);
   } catch(out_of_range) {
      return default_value;
   }
   ```

1. See 1. This overload is only available if `KeyType` is comparable with `typename object_t::key_type` and `typename object_comparator_t::is_transparent` denotes a type.

1. Returns either a copy of an object's element at the specified JSON pointer `ptr` or a given default value if no value at `ptr` exists.

   The function is basically equivalent to executing

   ```
   try {
      return at(ptr);
   } catch(out_of_range) {
      return default_value;
   }
   ```

Differences to `at` and `operator[]`

- Unlike [`at`](https://json.nlohmann.me/api/basic_json/at/index.md), this function does not throw if the given `key`/`ptr` was not found.
- Unlike [`operator[]`](https://json.nlohmann.me/api/basic_json/operator%5B%5D/index.md), this function does not implicitly add an element to the position defined by `key`/`ptr` key. This function is furthermore also applicable to const objects.

## Template parameters

`KeyType` : A type for an object key other than [`json_pointer`](https://json.nlohmann.me/api/json_pointer/index.md) that is comparable with [`string_t`](https://json.nlohmann.me/api/basic_json/string_t/index.md) using [`object_comparator_t`](https://json.nlohmann.me/api/basic_json/object_comparator_t/index.md). This can also be a string view (C++17).

`ValueType` : type compatible to JSON values, for instance `int` for JSON integer numbers, `bool` for JSON booleans, or `std::vector` types for JSON arrays. Note the type of the expected value at `key`/`ptr` and the default value `default_value` must be compatible.

## Parameters

`key` (in) : key of the element to access

`default_value` (in) : the value to return if `key`/`ptr` found no value

`ptr` (in) : a JSON pointer to the element to access

## Return value

1. copy of the element at key `key` or `default_value` if `key` is not found
1. copy of the element at key `key` or `default_value` if `key` is not found
1. copy of the element at JSON Pointer `ptr` or `default_value` if no value for `ptr` is found

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes to any JSON value.

## Exceptions

1. The function can throw the following exceptions:
   - Throws [`type_error.302`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error302) if `default_value` does not match the type of the value at `key`
   - Throws [`type_error.306`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error306) if the JSON value is not an object; in that case, using `value()` with a key makes no sense.
1. See 1.
1. The function can throw the following exceptions:
   - Throws [`type_error.302`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error302) if `default_value` does not match the type of the value at `ptr`
   - Throws [`type_error.306`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error306) if the JSON value is not an array or object; in that case, using `value()` with a JSON pointer makes no sense.
   - Throws [`parse_error.106`](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error106) if an array index in the passed JSON pointer `ptr` begins with '0'.
   - Throws [`parse_error.109`](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error109) if an array index in the passed JSON pointer `ptr` is not a number.

## Complexity

1. Logarithmic in the size of the container.
1. Logarithmic in the size of the container.
1. Logarithmic in the size of the container.

## Notes

Return type

The value function is a template, and the return type of the function is determined by the type of the provided default value unless otherwise specified. This can have unexpected effects. In the example below, we store a 64-bit unsigned integer. We get exactly that value when using [`operator[]`](https://json.nlohmann.me/api/basic_json/operator%5B%5D/index.md). However, when we call `value` and provide `0` as default value, then `-1` is returned. This occurs, because `0` has type `int` which overflows when handling the value `18446744073709551615`.

To address this issue, either provide a correctly typed default value or use the template parameter to specify the desired return type. Note that this issue occurs even when a value is stored at the provided key, and the default value is not used as the return value.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    json j = json::parse(R"({"uint64": 18446744073709551615})");

    std::cout << "operator[]:                " << j["uint64"] << '\n'
              << "default value (int):       " << j.value("uint64", 0) << '\n'
              << "default value (uint64_t):  " << j.value("uint64", std::uint64_t(0)) << '\n'
              << "explicit return value type: " << j.value<std::uint64_t>("uint64", 0) << '\n';
}
```

Output:

```
operator[]:                18446744073709551615
default value (int):       -1
default value (uint64_t):  18446744073709551615
explicit return value type: 18446744073709551615
```

## Examples

Example: (1) access specified object element with default value

The example below shows how object elements can be queried with a default value.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create a JSON object with different entry types
    json j =
    {
        {"integer", 1},
        {"floating", 42.23},
        {"string", "hello world"},
        {"boolean", true},
        {"object", {{"key1", 1}, {"key2", 2}}},
        {"array", {1, 2, 3}}
    };

    // access existing values
    int v_integer = j.value("integer", 0);
    double v_floating = j.value("floating", 47.11);

    // access nonexisting values and rely on default value
    std::string v_string = j.value("nonexisting", "oops");
    bool v_boolean = j.value("nonexisting", false);

    // output values
    std::cout << std::boolalpha << v_integer << " " << v_floating
              << " " << v_string << " " << v_boolean << "\n";
}
```

Output:

```
1 42.23 oops false
```

Example: (2) access specified object element using string_view with default value

The example below shows how object elements can be queried with a default value.

```
#include <iostream>
#include <string_view>
#include <nlohmann/json.hpp>

using namespace std::string_view_literals;
using json = nlohmann::json;

int main()
{
    // create a JSON object with different entry types
    json j =
    {
        {"integer", 1},
        {"floating", 42.23},
        {"string", "hello world"},
        {"boolean", true},
        {"object", {{"key1", 1}, {"key2", 2}}},
        {"array", {1, 2, 3}}
    };

    // access existing values
    int v_integer = j.value("integer"sv, 0);
    double v_floating = j.value("floating"sv, 47.11);

    // access nonexisting values and rely on default value
    std::string v_string = j.value("nonexisting"sv, "oops");
    bool v_boolean = j.value("nonexisting"sv, false);

    // output values
    std::cout << std::boolalpha << v_integer << " " << v_floating
              << " " << v_string << " " << v_boolean << "\n";
}
```

Output:

```
1 42.23 oops false
```

Example: (3) access specified object element via JSON Pointer with default value

The example below shows how object elements can be queried with a default value.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace nlohmann::literals;

int main()
{
    // create a JSON object with different entry types
    json j =
    {
        {"integer", 1},
        {"floating", 42.23},
        {"string", "hello world"},
        {"boolean", true},
        {"object", {{"key1", 1}, {"key2", 2}}},
        {"array", {1, 2, 3}}
    };

    // access existing values
    int v_integer = j.value("/integer"_json_pointer, 0);
    double v_floating = j.value("/floating"_json_pointer, 47.11);

    // access nonexisting values and rely on default value
    std::string v_string = j.value("/nonexisting"_json_pointer, "oops");
    bool v_boolean = j.value("/nonexisting"_json_pointer, false);

    // output values
    std::cout << std::boolalpha << v_integer << " " << v_floating
              << " " << v_string << " " << v_boolean << "\n";
}
```

Output:

```
1 42.23 oops false
```

## See also

- see [`at`](https://json.nlohmann.me/api/basic_json/at/index.md) for access by reference with range checking
- see [`operator[]`](https://json.nlohmann.me/api/basic_json/operator%5B%5D/index.md) for unchecked access by reference

## Version history

1. Added in version 1.0.0. Changed parameter `default_value` type from `const ValueType&` to `ValueType&&` in version 3.11.0.
1. Added in version 3.11.0. Made `ValueType` the first template parameter in version 3.11.2.
1. Added in version 2.0.2. Extended to work with arrays in version 3.12.x.
