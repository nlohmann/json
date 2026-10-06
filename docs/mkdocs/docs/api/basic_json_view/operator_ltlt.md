# <small>nlohmann::basic_json_view::</small>operator<<

```cpp
std::ostream& operator<<(std::ostream& o, const basic_json_view& v);
```

Not available when [`JSON_NO_IO`](../macros/json_no_io.md) is defined.

Serializes the given view `v` to the output stream `o`, using [`dump`](dump.md) -- exactly as
`#!cpp operator<<(std::ostream&, const basic_json&)` does for a `basic_json` value.

- The indentation of the output can be controlled with the member variable `width` of the output stream `o`. For
  instance, using the manipulator `std::setw(4)` on `o` sets the indentation level to `4`, and the serialization
  result is the same as calling `#!cpp v.dump(4)`. A `width` of `0` or less (the default) selects the most compact
  representation, as `#!cpp v.dump(-1)` does.
- The indentation character can be controlled with the member variable `fill` of the output stream `o`. For instance,
  the manipulator `std::setfill('\t')` sets indentation to use a tab character rather than the default space
  character.
- As for `basic_json`, `o`'s `width` is reset to `0` after this call, whether or not it was greater than `0` before.

Numbers are always written as `#!cpp v.dump()` writes them by default, i.e. as with
[`number_format::shortest`](number_format.md); there is no way to select `#!cpp number_format::source` through the
stream.

## Parameters

`o` (in, out)
:   stream to write to

`v` (in)
:   view to serialize

## Return value

the stream `o`

## Exceptions

May throw `#!cpp std::bad_alloc`, propagated from [`dump`](dump.md#exceptions). Unlike
`#!cpp operator<<(std::ostream&, const basic_json&)`, there is no UTF-8 decoding step that could throw
[`type_error.316`](../../home/exceptions.md#jsonexceptiontype_error316), and no `error_handler` to choose between --
see the [Exceptions](dump.md#exceptions) of `dump`.

## Complexity

Linear, as [`dump`](dump.md#complexity).

## Examples

??? example

    The example below writes one record out of a larger batch straight to a log stream -- compact for a one-line
    entry, and pretty-printed with `std::setw`/`std::setfill` for a readable dump -- without ever building a
    `BasicJsonType` value for the record, or for the rest of the batch.

    ```cpp
    --8<-- "examples/basic_json_view__operator_ltlt.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_view__operator_ltlt.output"
    ```

## See also

- [dump](dump.md) - serialize to a JSON-formatted string
- [`operator<<(std::ostream&)`](../operator_ltlt.md) - the corresponding operator for `basic_json`
- [`JSON_NO_IO`](../macros/json_no_io.md) - switch off functions relying on certain C++ I/O headers

## Version history

- Added in version 3.13.0.
