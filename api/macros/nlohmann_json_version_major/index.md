# NLOHMANN_JSON_VERSION_MAJOR, NLOHMANN_JSON_VERSION_MINOR, NLOHMANN_JSON_VERSION_PATCH

```
#define NLOHMANN_JSON_VERSION_MAJOR /* value */
#define NLOHMANN_JSON_VERSION_MINOR /* value */
#define NLOHMANN_JSON_VERSION_PATCH /* value */
```

These macros are defined by the library and contain the version numbers according to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

## Default definition

The macros are defined according to the current library version.

## Examples

Example

The example below shows how `NLOHMANN_JSON_VERSION_MAJOR`, `NLOHMANN_JSON_VERSION_MINOR`, and `NLOHMANN_JSON_VERSION_PATCH` are defined by the library.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    std::cout << "JSON for Modern C++ version "
              << NLOHMANN_JSON_VERSION_MAJOR << "."
              << NLOHMANN_JSON_VERSION_MINOR << "."
              << NLOHMANN_JSON_VERSION_PATCH << std::endl;
}
```

Output:

```
JSON for Modern C++ version 3.12.0
```

## See also

- [meta](https://json.nlohmann.me/api/basic_json/meta/index.md) - returns version information on the library
- [JSON_SKIP_LIBRARY_VERSION_CHECK](https://json.nlohmann.me/api/macros/json_skip_library_version_check/index.md) - skip library version check

## Version history

- Added in version 3.1.0.
