# <small>nlohmann::json_pointer::</small>to_string

```cpp
string_t to_string() const;
```

Return a string representation of the JSON pointer.

## Return value

A string representation of the JSON pointer

## Exception safety

Strong exception safety: if an exception occurs, the original value stays intact.

## Complexity

Linear in the total length of the reference tokens.

## Notes

For each JSON pointer `ptr`, it holds:

```cpp
ptr == json_pointer(ptr.to_string());
```

## Examples

??? example

    The example shows the result of `to_string`.
     
    ```cpp
    --8<-- "examples/json_pointer__to_string.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/json_pointer__to_string.output"
    ```

## See also

- [operator string_t](operator_string_t.md) return a string representation of the JSON pointer (deprecated)
- [operator<<](../operator_ltlt.md) write a JSON pointer to a stream

## Version history

- Since version 2.0.0.
- Changed return type to `string_t` in version 3.11.0.
