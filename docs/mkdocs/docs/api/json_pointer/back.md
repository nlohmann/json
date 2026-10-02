# <small>nlohmann::json_pointer::</small>back

```cpp
const string_t& back() const;
```

Return the last reference token.

## Return value

Last reference token.

## Exception safety

Strong exception safety: if an exception occurs, the original value stays intact.

## Exceptions

Throws [out_of_range.405](../../home/exceptions.md#jsonexceptionout_of_range405) if the JSON pointer has no parent.

## Complexity

Constant.

## Examples

??? example

    The example shows the usage of `back`.
     
    ```cpp
    --8<-- "examples/json_pointer__back.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/json_pointer__back.output"
    ```

## See also

- [front](front.md) return first reference token
- [pop_back](pop_back.md) remove the last reference token
- [push_back](push_back.md) append an unescaped token at the end of the pointer
- [parent_pointer](parent_pointer.md) returns the parent of this JSON pointer

## Version history

- Added in version 3.6.0.
- Changed return type to `string_t` in version 3.11.0.
