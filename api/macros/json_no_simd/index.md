# JSON_NO_SIMD

```
#define JSON_NO_SIMD
```

When defined, the library uses only portable C++ code where it would otherwise use vector instructions: when scanning strings during parsing, and when writing floating-point numbers during serialization. This includes the parser of [`basic_json_document`](https://json.nlohmann.me/api/basic_json_document/index.md) (`<nlohmann/json_view.hpp>`).

The macro is an escape hatch, for example for toolchains that cannot compile the vector code, for sanitizers or analyzers that do not understand it, or to compare the speed of both variants. It does not change any result: values, exceptions, and error positions are the same either way. Only the speed differs.

## Default definition

By default, `JSON_NO_SIMD` is not defined, and vector instructions are used where the target has them.

```
#undef JSON_NO_SIMD
```

## Notes

Which instructions are used

- **x86-64:** SSE2, which every x86-64 CPU has, finds the end of runs of plain string characters 16 bytes at a time and writes the digits of floating-point numbers. The UTF-8 check of non-ASCII text needs SSSE3, which is not part of x86-64: it is compiled for SSSE3 with a function attribute and used when the CPU has SSSE3 (every x86-64 CPU since about 2011), else the portable check. Code compiled for SSSE3 anyway (e.g., with `-mssse3` or `-march=native`) skips this check of the CPU. 32-bit x86 uses SSE2 for strings when the compiler targets it.
- **AArch64:** NEON, which every 64-bit Arm CPU has, checks UTF-8 text and long runs of plain string characters 16 bytes at a time, and writes the digits of floating-point numbers. With MSVC, only the floating-point digits use NEON.
- **Other targets:** portable code only.

Strings are only scanned this way for contiguous input and for the characters a `std::istream` holds in its stream buffer (see [`JSON_DISABLE_STREAM_BULK_SCAN`](https://json.nlohmann.me/api/macros/json_disable_stream_bulk_scan/index.md)); other inputs are read one character at a time.

Interaction with `JSON_USE_SIMDUTF`

With [`JSON_USE_SIMDUTF`](https://json.nlohmann.me/api/macros/json_use_simdutf/index.md), runs of string characters are first validated by simdutf; the code described here is used for what simdutf does not accept, so that errors are reported at the same position. `JSON_NO_SIMD` does not affect simdutf.

ABI compatibility

The macro selects between two definitions of the library's internal scanning and formatting functions. Whether it is defined is encoded in the [namespace](https://json.nlohmann.me/features/namespace/index.md) (tag `_ns`), resulting in distinct symbol names. Translation units compiled with and without it can therefore be linked into the same program without One Definition Rule (ODR) violations, but they cannot exchange instances of library types.

## Examples

Example: switching off vector instructions

The program parses and serializes the same values with and without the macro:

```
#define JSON_NO_SIMD
#include <iostream>
#include <nlohmann/json.hpp>

using nlohmann::json;

int main()
{
    const json j = json::parse(R"({"name": "日本語 text", "pi": 3.141592653589793})");
    std::cout << j.dump() << '\n';  // {"name":"日本語 text","pi":3.141592653589793}
}
```

## See also

- [**parse**](https://json.nlohmann.me/api/basic_json/parse/index.md) - deserialize from a compatible input
- [**dump**](https://json.nlohmann.me/api/basic_json/dump/index.md) - serialization
- [**JSON_USE_SIMDUTF**](https://json.nlohmann.me/api/macros/json_use_simdutf/index.md) - use the simdutf library to accelerate UTF-8 validation
- [**JSON_DISABLE_STREAM_BULK_SCAN**](https://json.nlohmann.me/api/macros/json_disable_stream_bulk_scan/index.md) - read a `std::istream` one character at a time
- [Parsing: input sources and performance](https://json.nlohmann.me/features/parsing/#input-sources-and-performance)
- [json_view](https://json.nlohmann.me/features/json_view/index.md) - the zero-copy view, whose parser the macro also affects

## Version history

- Added in version 3.13.0 unreleased.
