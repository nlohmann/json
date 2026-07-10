# <small>nlohmann::basic_json::</small>string_t

```cpp
using string_t = StringType;
```

The type used to store JSON strings.

[RFC 8259](https://tools.ietf.org/html/rfc8259) describes JSON strings as follows:
> A string is a sequence of zero or more Unicode characters.

To store strings in C++, a type is defined by the template parameter described below. Unicode values are split by the
JSON class into byte-sized characters during deserialization.

## Template parameters

`StringType`
:   the container to store strings (e.g., `std::string`). Note this container is used for keys/names in objects, see
    [object_t](object_t.md).

    `StringType` must have a `char`-compatible `value_type`: the library relies on UTF-8/`char`-based storage and
    processing internally, so `std::wstring`, `std::u16string`, and `std::u32string` are **not** valid choices for
    `StringType`. To work with wide-character data, convert it to/from UTF-8 at the boundary instead -- see the
    FAQ's [wide string handling](../../home/faq.md#wide-string-handling) section for a conversion recipe.

## Notes

#### Default type

With the default values for `StringType` (`std::string`), the default value for `string_t` is `#!cpp std::string`.

#### Encoding

Strings are stored in UTF-8 encoding. Therefore, functions like `std::string::size()` or `std::string::length()` return
the number of bytes in the string rather than the number of characters or glyphs.

#### String comparison

[RFC 8259](https://tools.ietf.org/html/rfc8259) states:
> Software implementations are typically required to test names of object members for equality. Implementations that
> transform the textual representation into sequences of Unicode code units and then perform the comparison numerically,
> code unit by code unit, are interoperable in the sense that implementations will agree in all cases on equality or
> inequality of two strings. For example, implementations that compare strings with escaped characters unconverted may
> incorrectly find that `"a\\b"` and `"a\u005Cb"` are not equal.

This implementation is interoperable as it does compare strings code unit by code unit.

#### Storage

String values are stored as pointers in a `basic_json` type. That is, for any access to string values, a pointer of type
`string_t*` must be dereferenced.

#### Cross-`basic_json` conversion requirements

When converting a string value from one `basic_json` specialization to another via the
[converting constructor](basic_json.md#overload-4), the target `string_t` must be directly
constructible from the source `basic_json`'s `string_t` type. If this requirement is not met, the
conversion does not fail; instead, the string is silently converted as an array of character codes,
which is incorrect. See [issue #3425](https://github.com/nlohmann/json/issues/3425) for details
and an example.

## Examples

??? example

    The following code shows that `string_t` is by default, a typedef to `#!cpp std::string`.
     
    ```cpp
    --8<-- "examples/string_t.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/string_t.output"
    ```

## Version history

- Added in version 1.0.0.
