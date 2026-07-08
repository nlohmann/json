# <small>nlohmann::json_pointer::</small>pop_back

```cpp
void pop_back();
```

Remove the last reference token.

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

## Version history

Added in version 3.6.0.
