# <small>nlohmann::json_pointer::</small>pop_back

```cpp
void pop_back();
```

Remove the last reference token.

## Exception safety

Strong exception safety: if an exception occurs, the original value stays intact.

## Exceptions

Throws [out_of_range.405](../../home/exceptions.md#jsonexceptionout_of_range405) if the JSON pointer has no parent.

## Complexity

Constant.

## Examples

??? example

    The example shows the usage of `pop_back`.
     
    ```cpp
    --8<-- "examples/json_pointer__pop_back.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/json_pointer__pop_back.output"
    ```

## See also

- [back](back.md) return last reference token
- [push_back](push_back.md) append an unescaped token at the end of the pointer
- [parent_pointer](parent_pointer.md) returns the parent of this JSON pointer

## Version history

Added in version 3.6.0.
