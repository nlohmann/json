# NLOHMANN_JSON_NAMESPACE_NO_VERSION

```
#define NLOHMANN_JSON_NAMESPACE_NO_VERSION /* value */
```

If defined to `1`, the version component is omitted from the inline namespace. See [`nlohmann` Namespace](https://json.nlohmann.me/features/namespace/#structure) for details.

## Default definition

The default value is `0`.

```
#define NLOHMANN_JSON_NAMESPACE_NO_VERSION 0
```

When the macro is not defined, the library will define it to its default value.

## Examples

Example

The example shows how to use `NLOHMANN_JSON_NAMESPACE_NO_VERSION` to disable the version component of the inline namespace.

```
#include <iostream>

#define NLOHMANN_JSON_NAMESPACE_NO_VERSION 1
#include <nlohmann/json.hpp>

// macro needed to output the NLOHMANN_JSON_NAMESPACE as string literal
#define Q(x) #x
#define QUOTE(x) Q(x)

int main()
{
    std::cout << QUOTE(NLOHMANN_JSON_NAMESPACE) << std::endl;
}
```

Output:

```
nlohmann::json_abi
```

## See also

- [`nlohmann` Namespace](https://json.nlohmann.me/features/namespace/index.md)
- [`NLOHMANN_JSON_NAMESPACE`](https://json.nlohmann.me/api/macros/nlohmann_json_namespace/index.md)
- [`NLOHMANN_JSON_NAMESPACE_BEGIN, NLOHMANN_JSON_NAMESPACE_END`](https://json.nlohmann.me/api/macros/nlohmann_json_namespace_begin/index.md)

## Version history

- Added in version 3.11.2.
