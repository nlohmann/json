# JSON_PRECISE_STREAM_POSITION

```cpp
#define JSON_PRECISE_STREAM_POSITION /* value */
```

When defined to `1`, [`operator>>`](../operator_gtgt.md) and [`sax_parse`](../basic_json/sax_parse.md) with
`strict = false` leave a `#!cpp std::istream` positioned right after the parsed value for every value type. By default,
the character that terminates a number is consumed as well.

The macro only affects reading from a `#!cpp std::istream` when the rest of the stream is not required to be consumed.
[`parse`](../basic_json/parse.md), [`accept`](../basic_json/accept.md), and all other inputs (strings, iterators,
containers, `#!cpp FILE*`) are never affected.

## Default definition

The default value is `0` (disabled — existing behavior is preserved).

```cpp
#define JSON_PRECISE_STREAM_POSITION 0
```

## Notes

!!! note "Background"

    A number is the only JSON value whose end can be detected solely by reading the character that follows it. By
    default, that character is consumed and not put back, so the stream is left one byte too far after a number, and
    only after a number:

    ```cpp
    std::istringstream input("1true");
    json j;
    input >> j;  // j == 1, but the stream now starts at "rue"
    ```

    With this macro, the character is only looked at and left in the stream, so the stream starts at `true`. This
    does not require the stream buffer to support putting a character back.

    This was not changed unconditionally, because code can depend on the consumed character, even unknowingly (see
    [#5340](https://github.com/nlohmann/json/issues/5340)). Both of the following work by default only because the
    character after each number is swallowed, and behave differently with this macro:

    ```cpp
    std::istringstream input("1,2,3");
    json j1, j2, j3;
    input >> j1 >> j2 >> j3;  // default: 1, 2, 3
                              // with the macro: throws parse_error.101 at the ','
    ```

    ```cpp
    std::istringstream input("42\nfoo");
    json j;
    std::string line;
    input >> j;
    std::getline(input, line);  // default: "foo"
                                // with the macro: "" (like after reading an int with >>)
    ```

    In both cases, the behavior with the macro is what you already get today when the value is not a number: `"a","b"`
    fails at the `,`, and `std::getline` after `{}` returns an empty string. This macro offers an opt-in path to
    the consistent behavior ahead of version 4.0.0, where it is planned to become the default.

!!! warning "Opt-in only"

    This macro must be defined **before** including `<nlohmann/json.hpp>`. Defining it after the include has no
    effect.

!!! note "ABI compatibility"

    The value of this macro is encoded in the [namespace](../../features/namespace.md) (tag `_psp`), resulting in
    distinct symbol names. Translation units compiled with and without it can therefore be linked into the same program
    without One Definition Rule (ODR) violations, but they cannot exchange instances of library types.

!!! tip "Workaround without the macro"

    Separate the values in the stream with whitespace. The character consumed after a number is then the separator,
    and whitespace before the next value is skipped anyway.

## Examples

??? example "Default behavior (macro not defined)"

    Without the macro, the character after a number is consumed:

    ```cpp
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

??? example "Opt-in precise stream position (macro defined to 1)"

    With the macro, the stream is positioned right after the number:

    ```cpp
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

- [**operator>>**](../operator_gtgt.md) - deserialize from stream
- [**sax_parse**](../basic_json/sax_parse.md) - generate SAX events

## Version history

- Added in version 3.13.0.
- Planned to become the default (with the macro removed) in version 4.0.0.
