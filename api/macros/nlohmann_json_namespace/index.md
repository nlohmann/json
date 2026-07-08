# NLOHMANN_JSON_NAMESPACE

```
#define NLOHMANN_JSON_NAMESPACE /* value */
```

This macro evaluates to the full name of the `nlohmann` namespace.

## Default definition

The default value consists of the root namespace (`nlohmann`) and an inline ABI namespace. See [`nlohmann` Namespace](https://json.nlohmann.me/features/namespace/#structure) for details.

When the macro is not defined, the library will define it to its default value. Overriding this value has no effect on the library.

## Examples

Example

The example shows how to use `NLOHMANN_JSON_NAMESPACE` instead of just `nlohmann`, as well as how to output the value of `NLOHMANN_JSON_NAMESPACE`.

```
#include <iostream>
#include <nlohmann/json.hpp>

// possible use case: use NLOHMANN_JSON_NAMESPACE instead of nlohmann
using json = NLOHMANN_JSON_NAMESPACE::json;

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
nlohmann::json_abi_v3_12_0
```

## See also

- [`NLOHMANN_JSON_NAMESPACE_BEGIN, NLOHMANN_JSON_NAMESPACE_END`](https://json.nlohmann.me/api/macros/nlohmann_json_namespace_begin/index.md)
- [`NLOHMANN_JSON_NAMESPACE_NO_VERSION`](https://json.nlohmann.me/api/macros/nlohmann_json_namespace_no_version/index.md)

## Version history

- Added in version 3.11.0. Changed inline namespace name in version 3.11.2.
