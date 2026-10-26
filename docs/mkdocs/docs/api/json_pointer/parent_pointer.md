# <small>nlohmann::json_pointer::</small>parent_pointer

```cpp
json_pointer parent_pointer() const;
```

Returns the parent of this JSON pointer.

## Return value

Parent of this JSON pointer; in case this JSON pointer is the root, the root itself is returned.

## Exception safety

Strong exception safety: if an exception occurs, the original value stays intact. The function is not `#!cpp noexcept`
and allocates a new JSON pointer, so it can throw `#!cpp std::bad_alloc`; it throws no library exceptions.

## Complexity

Linear in the length of the JSON pointer.

## Examples

??? example

    The example shows the result of `parent_pointer` for different JSON Pointers.
     
    ```cpp
    --8<-- "examples/json_pointer__parent_pointer.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/json_pointer__parent_pointer.output"
    ```

## See also

- [pop_back](pop_back.md) remove the last reference token
- [back](back.md) return the last reference token

## Version history

Added in version 3.6.0.
