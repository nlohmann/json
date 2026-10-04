# <small>nlohmann::json_pointer::</small>front

```cpp
const string_t& front() const;
```

Return the first reference token.

## Return value

First reference token.

## Exception safety

Strong exception safety: if an exception occurs, the original value stays intact.

## Exceptions

Throws [out_of_range.405](../../home/exceptions.md#jsonexceptionout_of_range405) if the JSON pointer has no parent.

## Complexity

Constant.

## Examples

??? example

    The example shows the usage of `front`.
     
    ```cpp
    --8<-- "examples/json_pointer__front.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/json_pointer__front.output"
    ```

## See also

- [back](back.md) return last reference token
- [pop_front](pop_front.md) remove the first reference token
- [push_front](push_front.md) append an unescaped token at the start of the pointer

## Version history

- Added in version 3.13.0.
