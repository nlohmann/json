# NLOHMANN_JSON_NAMESPACE_BEGIN, NLOHMANN_JSON_NAMESPACE_END

```
#define NLOHMANN_JSON_NAMESPACE_BEGIN /* value */  // (1)
#define NLOHMANN_JSON_NAMESPACE_END   /* value */  // (2)
```

These macros can be used to open and close the `nlohmann` namespace. See [`nlohmann` Namespace](https://json.nlohmann.me/features/namespace/#structure) for details.

1. Opens the namespace.
1. Closes the namespace.

## Default definition

The default definitions open and close the `nlohmann` namespace. The precise definition of \[`NLOHMANN_JSON_NAMESPACE_BEGIN`\] varies as described [here](https://json.nlohmann.me/features/namespace/#structure).

1. Default definition of `NLOHMANN_JSON_NAMESPACE_BEGIN`:

   ```
   namespace nlohmann
   {
   inline namespace json_abi_v3_12_0
   {
   ```

1. Default definition of `NLOHMANN_JSON_NAMESPACE_END`:

   ```
   }  // namespace json_abi_v3_12_0
   }  // namespace nlohmann
   ```

When these macros are not defined, the library will define them to their default definitions.

## Examples

Example

The example shows how to use `NLOHMANN_JSON_NAMESPACE_BEGIN`/`NLOHMANN_JSON_NAMESPACE_END` from the [How do I convert third-party types?](https://json.nlohmann.me/features/arbitrary_types/#how-do-i-convert-third-party-types) page.

```
#include <iostream>
#include <optional>
#include <nlohmann/json.hpp>

// partial specialization (see https://json.nlohmann.me/features/arbitrary_types/)
NLOHMANN_JSON_NAMESPACE_BEGIN
template <typename T>
struct adl_serializer<std::optional<T>>
{
    static void to_json(json& j, const std::optional<T>& opt)
    {
        if (opt == std::nullopt)
        {
            j = nullptr;
        }
        else
        {
            j = *opt;
        }
    }
};
NLOHMANN_JSON_NAMESPACE_END

int main()
{
    std::optional<int> o1 = 1;
    std::optional<int> o2 = std::nullopt;

    NLOHMANN_JSON_NAMESPACE::json j;
    j.push_back(o1);
    j.push_back(o2);
    std::cout << j << std::endl;
}
```

Output:

```
[1,null]
```

## See also

- [`nlohmann` Namespace](https://json.nlohmann.me/features/namespace/index.md)
- [NLOHMANN_JSON_NAMESPACE](https://json.nlohmann.me/api/macros/nlohmann_json_namespace/index.md)
- [`NLOHMANN_JSON_NAMESPACE_NO_VERSION`](https://json.nlohmann.me/api/macros/nlohmann_json_namespace_no_version/index.md)

## Version history

- Added in version 3.11.0. Changed inline namespace name in version 3.11.2.
