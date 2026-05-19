# <small>nlohmann::json_pointer::</small>pop_front

```cpp
void pop_front();
```

Remove the first reference token.

## Exceptions

Throws [out_of_range.405](../../home/exceptions.md#jsonexceptionout_of_range405) if the JSON pointer has no parent.

## Complexity

Linear in the number of reference tokens in the `json_pointer`.

## Examples

??? example

    The example shows the usage of `pop_front`.
     
    ```cpp
    --8<-- "examples/json_pointer__pop_front.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/json_pointer__pop_front.output"
    ```

## Version history
