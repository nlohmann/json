# <small>nlohmann::json_pointer::</small>operator string_t

```cpp
operator string_t() const
```

Return a string representation of the JSON pointer.

## Return value

A string representation of the JSON pointer

## Possible implementation

```cpp
operator string_t() const
{
    return to_string();
}
```

## Notes

!!! warning "Deprecation"

    This function is deprecated in favor of [`to_string`](to_string.md) and will be removed in a future major version
    release.

## Examples

??? example

    The example shows how JSON Pointers can be implicitly converted to strings.
     
    ```cpp
    --8<-- "examples/json_pointer__operator_string_t.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/json_pointer__operator_string_t.output"
    ```

## See also

- [string_t](../basic_json/string_t.md)- type for strings

## Version history

- Since version 2.0.0.
- Changed type to `string_t` and deprecated in version 3.11.0.
