# Modules

This library has experimental support for C++ modules, introduced in C++20. The library can be imported by writing `import nlohmann.json;` instead of `#include <nlohmann/json.hpp>`. 

Please be aware that the module is experimental and a full test is outstanding, and the exported symbols are subject to change.

## Requirements
The `nlohmann.json` module requires that the build system is configured to build and resolve modules when imported. Obviously, as modules were introduced in C++20, this feature can only be used in C++20 and subsequent versions.

To enable building the `nlohmann.json` module (which is not done by default), the macro `NLOHMANN_JSON_BUILD_MODULES` must be passed to the build system.

## Example
When using modules rather than headers, the previous example for creating a `json` object through a JSON file, would instead be:
```cpp
import std;
import nlohmann.json;

using json = nlohmann::json;

// ...

std::ifstream f("example.json");
json data = json::parse(f);
```

## Modules do not export macros
It should be noted that as modules do not export macros, the `nlohmann.json` module will not export any macros, but rather only the following symbols:
- `nlohmann::adl_serializer`
- `nlohmann::basic_json`
- `nlohmann::json`
- `nlohmann::json_pointer`
- `nlohmann::ordered_map`
- `nlohmann::ordered_json`
