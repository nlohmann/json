# <small>nlohmann::json_pointer::</small>empty

```cpp
bool empty() const noexcept;
```

Return whether pointer points to the root document.

## Return value

`#!cpp true` iff the JSON pointer points to the root document.

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Examples

??? example

    The example shows the result of `empty` for different JSON Pointers.
     
    ```cpp
    --8<-- "examples/json_pointer__empty.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/json_pointer__empty.output"
    ```

## Version history

Added in version 3.6.0.
