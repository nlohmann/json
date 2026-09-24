# <small>nlohmann::basic_json::</small>is_primitive

```cpp
constexpr bool is_primitive() const noexcept;
```

This function returns `#!cpp true` if and only if the JSON type is primitive (string, number, boolean, `#!json null`,
binary).
    
## Return value

`#!cpp true` if type is primitive (string, number, boolean, `#!json null`, or binary), `#!cpp false` otherwise.

## Exception safety

No-throw guarantee: this member function never throws exceptions.

## Complexity

Constant.

## Possible implementation

```cpp
constexpr bool is_primitive() const noexcept
{
    return is_null() || is_string() || is_boolean() || is_number() || is_binary();
}
```

## Notes

The term *primitive* stems from [RFC 8259](https://tools.ietf.org/html/rfc8259):

> JSON can represent four primitive types (strings, numbers, booleans, and null) and two structured types (objects and
> arrays).

This library extends primitive types to binary types, because binary types are roughly comparable to strings. Hence,
`is_primitive()` returns `#!cpp true` for binary values.

## Examples

??? example

    The following code exemplifies `is_primitive()` for all JSON types.
    
    ```cpp
    --8<-- "examples/is_primitive.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/is_primitive.output"
    ```

## See also

- [is_structured()](is_structured.md) returns whether the JSON value is structured
- [is_null()](is_null.md) returns whether the JSON value is `null`
- [is_string()](is_string.md) returns whether the JSON value is a string
- [is_boolean()](is_boolean.md) returns whether the JSON value is a boolean
- [is_number()](is_number.md) returns whether the JSON value is a number
- [is_binary()](is_binary.md) returns whether the JSON value is a binary array

## Version history

- Added in version 1.0.0.
- Extended to return `#!cpp true` for binary types in version 3.8.0.
