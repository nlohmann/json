# JSON_PRECISE_STREAM_POSITION

```
#define JSON_PRECISE_STREAM_POSITION /* value */
```

When defined to `1`, [`operator>>`](https://json.nlohmann.me/api/operator_gtgt/index.md) and [`sax_parse`](https://json.nlohmann.me/api/basic_json/sax_parse/index.md) with `strict = false` leave a `std::istream` positioned right after the parsed value for every value type. By default, the character that terminates a number is consumed as well.

The macro only affects reading from a `std::istream` when the rest of the stream is not required to be consumed. [`parse`](https://json.nlohmann.me/api/basic_json/parse/index.md), [`accept`](https://json.nlohmann.me/api/basic_json/accept/index.md), and all other inputs (strings, iterators, containers, `FILE*`) are never affected.

## Default definition

The default value is `0` (disabled — existing behavior is preserved).

```
#define JSON_PRECISE_STREAM_POSITION 0
```

## Notes

Background

A number is the only JSON value whose end can be detected solely by reading the character that follows it. By default, that character is consumed and not put back, so the stream is left one byte too far after a number, and only after a number:

```
std::istringstream input("1true");
json j;
input >> j;  // j == 1, but the stream now starts at "rue"
```

With this macro, the character is only looked at and left in the stream, so the stream starts at `true`. This does not require the stream buffer to support putting a character back.

This was not changed unconditionally, because code can depend on the consumed character, even unknowingly (see [#5340](https://github.com/nlohmann/json/issues/5340)). Both of the following work by default only because the character after each number is swallowed, and behave differently with this macro:

```
std::istringstream input("1,2,3");
json j1, j2, j3;
input >> j1 >> j2 >> j3;  // default: 1, 2, 3
                          // with the macro: throws parse_error.101 at the ','
```

```
std::istringstream input("42\nfoo");
json j;
std::string line;
input >> j;
std::getline(input, line);  // default: "foo"
                            // with the macro: "" (like after reading an int with >>)
```

In both cases, the behavior with the macro is what you already get today when the value is not a number: `"a","b"` fails at the `,`, and `std::getline` after `{}` returns an empty string. This macro offers an opt-in path to the consistent behavior ahead of version 4.0.0, where it is planned to become the default.

Opt-in only

This macro must be defined **before** including `<nlohmann/json.hpp>`. Defining it after the include has no effect.

ABI compatibility

The value of this macro is encoded in the [namespace](https://json.nlohmann.me/features/namespace/index.md) (tag `_psp`), resulting in distinct symbol names. Translation units compiled with and without it can therefore be linked into the same program without One Definition Rule (ODR) violations, but they cannot exchange instances of library types.

Workaround without the macro

Separate the values in the stream with whitespace. The character consumed after a number is then the separator, and whitespace before the next value is skipped anyway.

## Examples

Default behavior (macro not defined)

Without the macro, the character after a number is consumed:

```
#include <iostream>
#include <sstream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    std::istringstream input("1true");
    json j1, j2;
    input >> j1;  // j1 == 1
    input >> j2;  // throws parse_error.101: the stream now starts at "rue"
}
```

Opt-in precise stream position (macro defined to 1)

With the macro, the stream is positioned right after the number:

```
#define JSON_PRECISE_STREAM_POSITION 1
#include <iostream>
#include <sstream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    std::istringstream input("1true");
    json j1, j2;
    input >> j1;  // j1 == 1
    input >> j2;  // j2 == true
}
```

## See also

- [**operator>>**](https://json.nlohmann.me/api/operator_gtgt/index.md) - deserialize from stream
- [**sax_parse**](https://json.nlohmann.me/api/basic_json/sax_parse/index.md) - generate SAX events

## Version history

- Added in version 3.13.0.
- Planned to become the default (with the macro removed) in version 4.0.0.
