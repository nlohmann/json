# <small>nlohmann::basic_json::</small>is_structured

```cpp
constexpr bool is_structured() const noexcept;
```

This function returns `#!cpp true` if and only if the JSON type is structured (array or object).
    
## Return value

`#!cpp true` if type is structured (array or object), `#!cpp false` otherwise.

## Exception safety

No-throw guarantee: this member function never throws exceptions.

## Complexity

Constant.

## Possible implementation

```cpp
constexpr bool is_primitive() const noexcept
{
    return is_array() || is_object();
}
```

## Notes

The term *structured* stems from [RFC 8259](https://tools.ietf.org/html/rfc8259):

> JSON can represent four primitive types (strings, numbers, booleans, and null) and two structured types (objects and
> arrays).

Note that though strings are containers in C++, they are treated as primitive values in JSON.

## Examples

??? example

    The following code exemplifies `is_structured()` for all JSON types.
    
    ```cpp
    --8<-- "examples/is_structured.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/is_structured.output"
    ```

## See also

- [is_primitive()](is_primitive.md) returns whether JSON value is primitive
- [is_array()](is_array.md) returns whether value is an array
- [is_object()](is_object.md) returns whether value is an object

## Version history

- Added in version 1.0.0.
