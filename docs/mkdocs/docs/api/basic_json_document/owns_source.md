# <small>nlohmann::basic_json_document::</small>owns_source

```cpp
bool owns_source() const noexcept;
```

Returns whether the document holds its own copy of the parsed text, as opposed to borrowing the caller's buffer.

## Return value

`#!cpp true` if the document owns the text returned by [`source()`](source.md), `#!cpp false` if it borrows it (or if
the document is [discarded](is_discarded.md)).

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Notes

See the ownership table on [`parse`](parse.md#notes) for which inputs are borrowed and which are owned. A borrowed
document (`#!cpp owns_source() == false`) is only valid while the buffer it was parsed from is still alive.

## Examples

??? example

    ```cpp
    --8<-- "examples/basic_json_document__owns_source.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_document__owns_source.output"
    ```

## See also

- [parse](parse.md) - deserialize from a compatible input
- [parse_copy](parse_copy.md) - deserialize a copy of a compatible input, always owned
- [source](source.md) - the parsed text

## Version history

- Added in version 3.13.0.
