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
It should be noted that as modules do not export macros, the `nlohmann.json` module will not export any macros.

## Exported symbols

Only the following symbols are exported from `nlohmann.json`:

- `nlohmann::adl_serializer`
- `nlohmann::basic_json`
- `nlohmann::json`
- `nlohmann::json_pointer`
- `nlohmann::ordered_json`
- `nlohmann::ordered_map`
- `nlohmann::to_string`
- `nlohmann::literals::json_literals::operator""_json`
- `nlohmann::literals::json_literals::operator""_json_pointer`

Additionally, the following `nlohmann::detail` symbols are exported, solely to work around an MSVC compilation issue
([#3970](https://github.com/nlohmann/json/issues/3970)). They are implementation details, not part of the public API,
and should not be used directly:

- `nlohmann::detail::json_sax_dom_callback_parser`
- `nlohmann::detail::unknown_size`

## Known issues

C++20 modules support is exercised in CI against current GCC and Clang on Ubuntu, and the default MSVC toolset on Windows Server 2022 — there is no documented minimum compiler version, unlike feature-test-macro-gated features such as [`JSON_HAS_RANGES`](../api/macros/json_has_ranges.md).

!!! info "Known compiler issues"

    - **GCC** may emit "redefinition" errors when `#include <nlohmann/json.hpp>` appears in a module preamble together with other imports. This is an upstream GCC bug, not yet resolved as of GCC 16. Workarounds: include `nlohmann/json.hpp` before other `#include`s, use `import nlohmann.json;` instead, or upgrade GCC. ([issue #5103](https://github.com/nlohmann/json/issues/5103))
    - **MSVC** could fail with `C2039: 'json_sax_dom_callback_parser' is not a member of ... detail`; fixed by exporting the required internal symbols from `json.cppm` (see [Exported symbols](#exported-symbols) above). ([issue #3970](https://github.com/nlohmann/json/issues/3970))

    If you hit a different module-related build failure, search [existing issues](https://github.com/nlohmann/json/issues?q=is%3Aissue+modules) before filing a new one.
