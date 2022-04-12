# <small>nlohmann::json_pointer::</small>operator/=

```cpp
// (1)
json_pointer& operator/=(const json_pointer& ptr);

// (2)
json_pointer& operator/=(string_t token);

// (3)
json_pointer& operator/=(std::size_t array_idx)
```

1. append another JSON pointer at the end of this JSON pointer
2. append an unescaped reference token at the end of this JSON pointer
3. append an array index at the end of this JSON pointer

## Parameters

`ptr` (in)
:    JSON pointer to append

`token` (in)
:    reference token to append

`array_idx` (in)
:    array index to append

## Return value

1. JSON pointer with `ptr` appended
2. JSON pointer with `token` appended without escaping `token`
3. JSON pointer with `array_idx` appended

## Complexity

1. Linear in the length of `ptr`.
2. Amortized constant.
3. Amortized constant.

## Examples

??? example

    The example shows the usage of `operator/=`.
     
    ```cpp
    --8<-- "examples/json_pointer__operator_add.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/json_pointer__operator_add.output"
    ```

## Version history

1. Added in version 3.6.0.
2. Added in version 3.6.0. Changed type of `token` to `string_t` in version 3.11.0.
3. Added in version 3.6.0.
