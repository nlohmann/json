# format_as(basic_json)

```cpp
template <typename BasicJsonType>
std::string format_as(const BasicJsonType& j);
```

This function implements the [`format_as`](https://fmt.dev/latest/api/#formatting-user-defined-types)
customization point used by the [{fmt}](https://github.com/fmtlib/fmt) library (fmtlib). It has no
dependency on any `fmt` header and no effect at all unless a caller's translation unit also includes
`fmt` and calls `fmt::format`/`fmt::print` on a JSON value.

## Template parameters

`BasicJsonType`
:   a specialization of [`basic_json`](index.md)

## Return value

string containing the serialization of the JSON value (same as [`dump()`](dump.md))

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes to any JSON value.

## Exceptions

Throws [`type_error.316`](../../home/exceptions.md#jsonexceptiontype_error316) if a string stored inside the JSON value
is not UTF-8 encoded

## Complexity

Linear.

## Possible implementation

```cpp
template <typename BasicJsonType>
std::string format_as(const BasicJsonType& j)
{
    return j.dump();
}
```

## Notes

!!! warning "Version-dependent effect on fmt"

    `fmt` only picks up a `format_as` overload that returns a `std::string` in fmt **10.0.0 through
    11.0.2**. Starting with fmt **11.1.0**, `fmt` restricts automatic `format_as` pickup to overloads that
    return an arithmetic type, so this function has no effect there (it is simply unused, not a compile
    error).

    If you use fmt \>= 11.1.0, or want the same pretty-print spec support that
    [`std::formatter<basic_json>`](std_formatter.md) has (`#!cpp "{:#}"`, a width to set the indent such
    as `#!cpp "{:2}"`/`#!cpp "{:#2}"`, and fill-and-align to pick the indent character such as
    `#!cpp "{:.>#}"`), define your own `fmt::formatter` specialization mirroring the same logic:

    ```cpp
    --8<-- "../../../tests/fmt_formatter/project/main.cpp:formatter_recipe"
    ```

    This recipe isn't shipped by the library itself, since doing so would make `fmt` a build dependency
    (see the FAQ entry on
    [using JSON values with `std::format` or `fmt`](../../home/faq.md#using-json-values-with-stdformat-or-fmt)
    for more background) — but it *is* compiled and exercised against a real, current `fmt` release as
    part of the library's own test suite (`tests/fmt_formatter`, via CMake `FetchContent`), so it's kept in
    sync with `std::formatter<basic_json>` and verified to actually work, not just illustrative.

## Examples

??? example

    The following code shows how the library's `format_as()` function integrates with `fmt::format`,
    allowing argument-dependent lookup.

    ```cpp
    --8<-- "examples/format_as.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/format_as.output"
    ```

## See also

- [dump](dump.md)
- [std::formatter<basic_json>](std_formatter.md) - the `std::format` (C++20) equivalent
- [Serialization](../../features/serialization.md) - the serialization article

## Version history

- Added in version 3.12.x.
