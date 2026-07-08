# nlohmann::basic_json::object_comparator_t

```
using object_comparator_t = typename object_t::key_compare;
// or
using object_comparator_t = default_object_comparator_t;
```

The comparator used by [`object_t`](https://json.nlohmann.me/api/basic_json/object_t/index.md). Defined as `typename object_t::key_compare` if available, and [`default_object_comparator_t`](https://json.nlohmann.me/api/basic_json/default_object_comparator_t/index.md) otherwise.

## Examples

Example

The example below demonstrates the used object comparator.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    std::cout << std::boolalpha
              << "json::object_comparator_t(\"one\", \"two\") = " << json::object_comparator_t{}("one", "two") << "\n"
              << "json::object_comparator_t(\"three\", \"four\") = " << json::object_comparator_t{}("three", "four") << std::endl;
}
```

Output:

```
json::object_comparator_t("one", "two") = true
json::object_comparator_t("three", "four") = false
```

## Version history

- Added in version 3.0.0.
- Changed to be conditionally defined as `typename object_t::key_compare` or `default_object_comparator_t` in version 3.11.0.
