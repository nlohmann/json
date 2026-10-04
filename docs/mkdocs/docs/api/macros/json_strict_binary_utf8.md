# JSON_STRICT_BINARY_UTF8

```cpp
#define JSON_STRICT_BINARY_UTF8 /* value */
```

When defined to `1`, the `error_handler` parameter of the binary writers [`to_cbor`](../basic_json/to_cbor.md),
[`to_ubjson`](../basic_json/to_ubjson.md), [`to_bjdata`](../basic_json/to_bjdata.md), and
[`to_bson`](../basic_json/to_bson.md) defaults to [`error_handler_t::strict`](../basic_json/error_handler_t.md) instead
of `error_handler_t::keep`. These writers then check every string value and object key for valid UTF-8 and throw
[`type_error.316`](../../home/exceptions.md#jsonexceptiontype_error316) for ill-formed UTF-8, like
[`dump`](../basic_json/dump.md) does. Without it, they write the bytes unchanged. An `error_handler` passed explicitly
always takes precedence.

The macro does not affect:

- [`to_msgpack`](../basic_json/to_msgpack.md): the MessagePack specification allows a `str` value to contain bytes that
  are not valid UTF-8, so its `error_handler` always defaults to `keep`.
- [`to_bon8`](../basic_json/to_bon8.md): BON8 always checks, because the UTF-8 lead bytes mark where a string ends.
- The binary readers ([`from_cbor`](../basic_json/from_cbor.md), [`from_msgpack`](../basic_json/from_msgpack.md),
  [`from_ubjson`](../basic_json/from_ubjson.md), [`from_bjdata`](../basic_json/from_bjdata.md),
  [`from_bson`](../basic_json/from_bson.md)): none of these formats requires a decoder to reject ill-formed UTF-8, so
  they always return the bytes unchanged.

## Default definition

The default value is `0` (disabled, the behavior of version 3.12.0 and earlier is preserved).

```cpp
#define JSON_STRICT_BINARY_UTF8 0
```

## Notes

!!! note "Background"

    CBOR, UBJSON, BJData, and BSON all require strings to be UTF-8. Up to version 3.12.0, the writers did not check
    this, so they could produce output that other decoders reject. Checking by default would break code that stores
    other encodings (for instance ISO 8859-1) in a string and only ever writes it to a binary format. You can pass
    `error_handler_t::strict` to each call, or use this macro to check by default ahead of version 4.0.0, where
    `strict` is planned to become the default (see
    [#5529](https://github.com/nlohmann/json/issues/5529) and [#5651](https://github.com/nlohmann/json/issues/5651)).

!!! warning "Opt-in only"

    This macro must be defined **before** including `<nlohmann/json.hpp>`. Defining it after the include has no
    effect.

!!! note "ABI compatibility"

    The value of this macro is encoded in the [namespace](../../features/namespace.md) (tag `_sbu8`), resulting in
    distinct symbol names. Translation units compiled with and without it can therefore be linked into the same program
    without One Definition Rule (ODR) violations, but they cannot exchange instances of library types.

## Examples

??? example "Example: default behavior (macro not defined)"

    Without the macro, the bytes are written unchanged:

    ```cpp
    #include <nlohmann/json.hpp>

    using json = nlohmann::json;

    int main()
    {
        auto v = json::to_cbor(json("\xFF"));
        // v is {0x61, 0xFF}
    }
    ```

??? example "Example: opt-in check (macro defined to 1)"

    With the macro, ill-formed UTF-8 is rejected:

    ```cpp
    #define JSON_STRICT_BINARY_UTF8 1
    #include <nlohmann/json.hpp>

    using json = nlohmann::json;

    int main()
    {
        auto v = json::to_cbor(json("\xFF"));
        // throws type_error.316: invalid UTF-8 byte at index 0: 0xFF
    }
    ```

## See also

- [**to_cbor**](../basic_json/to_cbor.md) - create a CBOR serialization of a JSON value
- [**to_ubjson**](../basic_json/to_ubjson.md) - create a UBJSON serialization of a JSON value
- [**to_bjdata**](../basic_json/to_bjdata.md) - create a BJData serialization of a JSON value
- [**to_bson**](../basic_json/to_bson.md) - create a BSON serialization of a JSON value
- [**error_handler_t**](../basic_json/error_handler_t.md) - how [`dump`](../basic_json/dump.md) treats ill-formed UTF-8

## Version history

- Added in version 3.13.0.
- Planned to become the default (with the macro removed) in version 4.0.0.
