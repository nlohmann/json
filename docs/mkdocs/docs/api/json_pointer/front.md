# <small>nlohmann::json_pointer::</small>front

```cpp
const string_t& front() const;
```

Return the first reference token.

## Return value

First reference token.

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

## Version history
