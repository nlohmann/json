# <small>nlohmann::basic_json_view::</small>number_format

```cpp
enum class number_format {
    shortest,
    source
};
```

This enumeration is used in [`dump`](dump.md) to choose how numbers are written. Two values are differentiated:

shortest
:   integers are copied from the source text -- already canonical in JSON -- except that `#!cpp -0` becomes
    `#!cpp 0`, the way [`BasicJsonType::parse()`](../basic_json/parse.md) reads it; floats are written with the
    library's shortest round-trip conversion, exactly as [`BasicJsonType::dump()`](../basic_json/dump.md) would (e.g.
    `#!cpp 1.5`, `#!cpp 100.0`, `#!cpp 1e+100`)

source
:   every number is copied exactly as it appears in the source text -- `#!cpp 1.50`, `#!cpp 1E2`, `#!cpp -0`, all
    digits of an integer literal with more digits than any number type holds -- something `BasicJsonType` cannot do,
    since parsing already reduces every number to its parsed value

## Examples

??? example

    The example below writes back a price list received from a supplier: with `number_format::shortest` (the
    default), a trailing zero and scientific notation are normalized away and a long account number that overflows
    every number type is rounded, the same way `#!cpp materialize().dump()` (or `basic_json::dump()`) would;
    `number_format::source` keeps every number exactly as it was written in the source text instead.

    ```cpp
    --8<-- "examples/basic_json_view__number_format.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_view__number_format.output"
    ```

## See also

- [dump](dump.md) - serialize to a JSON-formatted string
- [number_token](number_token.md) - get a single number's token text without dumping the whole value
- [`BasicJsonType::error_handler_t`](../basic_json/error_handler_t.md) - the analogous enumeration for
  `BasicJsonType::dump`'s decoding-error behavior

## Version history

- Added in version 3.13.0.
