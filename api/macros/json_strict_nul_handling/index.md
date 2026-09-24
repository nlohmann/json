# JSON_STRICT_NUL_HANDLING

```
#define JSON_STRICT_NUL_HANDLING /* value */
```

When defined to `1`, a `'\0'` (NUL) byte in JSON text input is rejected with `parse_error.101`, like any other unexpected byte, instead of being silently treated as end of input.

The macro only affects the JSON text parser ([`parse`](https://json.nlohmann.me/api/basic_json/parse/index.md), [`accept`](https://json.nlohmann.me/api/basic_json/accept/index.md), [`sax_parse`](https://json.nlohmann.me/api/basic_json/sax_parse/index.md), and [`operator>>`](https://json.nlohmann.me/api/operator_gtgt/index.md)). There are three cases where a NUL byte is still not rejected:

- The binary formats ([`from_bjdata`](https://json.nlohmann.me/api/basic_json/from_bjdata/index.md), [`from_bson`](https://json.nlohmann.me/api/basic_json/from_bson/index.md), [`from_cbor`](https://json.nlohmann.me/api/basic_json/from_cbor/index.md), [`from_msgpack`](https://json.nlohmann.me/api/basic_json/from_msgpack/index.md), [`from_ubjson`](https://json.nlohmann.me/api/basic_json/from_ubjson/index.md)) are never affected: there, `0x00` is ordinary data.
- A bare `const char*` pointer has no length of its own, so its length is still determined with `strlen()`. The first NUL byte therefore still marks the end of the input, and nothing after it is read.
- One trailing `'\0'` at the end of a `char` array (e.g., a string literal) is trimmed; see the warning below.

## Default definition

The default value is `0` (disabled — existing behavior is preserved).

```
#define JSON_STRICT_NUL_HANDLING 0
```

## Notes

Background

By default, a `'\0'` byte anywhere in the input is treated the same as the real end of the input, rather than as an ordinary (and, outside of a string, invalid) byte. Everything from that byte onward is silently ignored, without a parse error - including further, otherwise well-formed JSON:

```
json::parse(std::string("123") + '\0');          // == 123, no error
json::parse(std::string("123") + '\0' + "true"); // == 123, the "true" is silently ignored too
```

This falls out of the same convention used when no explicit input length is given at all: parsing from a `const char*` already stops at the first NUL byte via `strlen()`, since a bare pointer has no length of its own. The library applies that same NUL-terminated-C-string convention uniformly, rather than only when a length is genuinely unavailable - so a `std::string`, iterator range, or container whose content happens to include a NUL byte is affected the same way a raw `const char*` would be (see the [FAQ entry](https://json.nlohmann.me/home/faq/#nul-bytes-in-the-input) for a fuller explanation).

This was not fixed unconditionally, because doing so is backwards-incompatible for any caller who happens to depend on the current behavior - even unknowingly, for instance because their input already contains trailing padding they never noticed was being discarded (see [#5530](https://github.com/nlohmann/json/issues/5530)). This macro instead offers an opt-in path to the corrected behavior ahead of version 4.0.0, where it is planned to become the default.

Opt-in only

This macro must be defined **before** including `<nlohmann/json.hpp>`. Defining it after the include has no effect.

Enabling it also changes how a `char` array (including a string literal, e.g. `json::parse("123")`) is read: such an array normally carries a trailing `'\0'` contributed by the compiler, not by the source text. With this macro enabled, that one trailing byte is trimmed if present so that parsing a string literal keeps working; every other byte in the array - including any `'\0'` that is not the very last element - is read as real data and rejected like any other unexpected byte. Arrays of any other element type (`unsigned char`, `std::uint8_t`, ...), as used for CBOR or MessagePack, are never affected by this trimming; their full extent - including a genuine trailing `0x00` - is always preserved, in both states of this macro.

Workaround without the macro

To reject a NUL byte without enabling this macro, trim your input yourself before calling `parse()`:

```
s.resize(s.find('\0')); // drop everything from the first NUL onward, if any
json::parse(s);
```

## Examples

Default behavior (macro not defined)

Without the macro, a NUL byte silently ends parsing at that point:

```
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    json j = json::parse(std::string("123") + '\0' + "true");
    // j is 123 -- the '\0' and everything after it is silently ignored
}
```

Opt-in strict handling (macro defined to 1)

With the macro, a NUL byte is rejected like any other unexpected byte:

```
#define JSON_STRICT_NUL_HANDLING 1
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    json j = json::parse(std::string("123") + '\0' + "true");
    // throws parse_error.101 -- the NUL byte is now invalid input,
    // exactly like any other unexpected trailing byte

    json ok = json::parse("123");
    // ok is 123 -- parsing from a string literal still works
}
```

## See also

- [FAQ: NUL bytes in the input](https://json.nlohmann.me/home/faq/#nul-bytes-in-the-input)
- [**parse**](https://json.nlohmann.me/api/basic_json/parse/index.md) - deserialize from a compatible input
- [**accept**](https://json.nlohmann.me/api/basic_json/accept/index.md) - check if the input is valid JSON
- [**operator>>**](https://json.nlohmann.me/api/operator_gtgt/index.md) - deserialize from stream

## Version history

- Added in version 3.13.0.
- Planned to become the default (with the macro removed) in version 4.0.0.
