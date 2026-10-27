# <small>nlohmann::basic_json::</small>object_comparator_t

```cpp
using object_comparator_t = typename object_t::key_compare;
// or
using object_comparator_t = default_object_comparator_t;
```

The comparator used by [`object_t`](object_t.md). Defined as `#!cpp typename object_t::key_compare` if available,
and [`default_object_comparator_t`](default_object_comparator_t.md) otherwise.

## Examples

??? example

    The example below demonstrates the used object comparator.

    ```cpp
    #include <iostream>
    #include <nlohmann/json.hpp>
    
    using nlohmann::json;
    
    int main()
    {
        std::cout << std::boolalpha
                  << "json::object_comparator_t(\"one\", \"two\") = " << json::object_comparator_t{}("one", "two") << "\n"
                  << "json::object_comparator_t(\"three\", \"four\") = " << json::object_comparator_t{}("three", "four") << '\n';
    }
    
    ```
    
    Output:
    
    ```json
    json::object_comparator_t("one", "two") = true
    json::object_comparator_t("three", "four") = false
    
    ```

## See also

- [`object_t`](object_t.md) - the type used to store JSON objects
- [`default_object_comparator_t`](default_object_comparator_t.md) - the fallback comparator used when `object_t` has no `key_compare` member type
- [Template Parameter Requirements](../../features/types/template_parameters.md) - requirements on the `ObjectType` template parameter
- [Object order](../../features/object_order.md) - preserve the insertion order of keys

## Version history

- Added in version 3.0.0.
- Changed to be conditionally defined as `#!cpp typename object_t::key_compare` or `default_object_comparator_t` in
  version 3.11.0.
- Fixed the fallback to `default_object_comparator_t`, which previously failed to compile for object types without a
  `key_compare` member type, in version 3.13.0.
