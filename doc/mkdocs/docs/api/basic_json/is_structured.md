# basic_json::is_structured

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

## Notes

The term *structured* stems from [RFC 8259](https://tools.ietf.org/html/rfc8259):

> JSON can represent four primitive types (strings, numbers, booleans, and null) and two structured types (objects and
> arrays).

Note that though strings are containers in C++, they are treated as primitive values in JSON.

## Example

??? example

    The following code exemplifies `is_structured()` for all JSON types.
    
    ```cpp
    --8<-- "examples/is_structured.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/is_structured.output"
    ```

## Version history

- Added in version 1.0.0.
