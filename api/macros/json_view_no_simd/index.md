# JSON_VIEW_NO_SIMD

```
#define JSON_VIEW_NO_SIMD
```

When defined, the parser of [`basic_json_document`](https://json.nlohmann.me/api/basic_json_document/index.md) (`<nlohmann/json_view.hpp>`) uses only portable C++ to scan strings. By default, it scans long runs of string bytes 16 at a time with NEON on AArch64 (with GCC and Clang) and SSE2 on x86-64, which are part of the baseline instruction sets of these architectures, and validates non-ASCII text with NEON (or SSSE3, see [`JSON_VIEW_USE_SSSE3`](https://json.nlohmann.me/api/macros/json_view_use_ssse3/index.md)).

The same input is accepted or rejected either way, with the same values, and errors are reported the same way; only the speed differs. The macro exists for platforms whose compilers lack the intrinsics headers, and to test the portable code.

ABI compatibility

The macro selects between two definitions of the same inline functions. Whether it is defined is encoded in the [namespace](https://json.nlohmann.me/features/namespace/index.md) (tag `_vns`), resulting in distinct symbol names. Translation units compiled with and without it can therefore be linked into the same program without One Definition Rule (ODR) violations, but they cannot exchange instances of library types.

## Default definition

By default, `JSON_VIEW_NO_SIMD` is not defined, and the vector code is used where available.

```
#undef JSON_VIEW_NO_SIMD
```

## Examples

Example

The code below uses the portable string scanning of the view.

```
#define JSON_VIEW_NO_SIMD
#include <nlohmann/json_view.hpp>

...
```

## See also

- [JSON_VIEW_USE_SSSE3](https://json.nlohmann.me/api/macros/json_view_use_ssse3/index.md) - validate non-ASCII strings with SSSE3 on x86-64
- [json_view](https://json.nlohmann.me/features/json_view/index.md) - the zero-copy view

## Version history

- Added in version 3.13.0 unreleased.
