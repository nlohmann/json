# <small>nlohmann::basic_json::</small>get_binary

```cpp
binary_t& get_binary();

const binary_t& get_binary() const;
```

Returns a reference to the stored binary value.

## Return value

Reference to binary value.

## Exception safety

Strong exception safety: if an exception occurs, the original value stays intact.

## Exceptions

Throws [`type_error.302`](../../home/exceptions.md#jsonexceptiontype_error302) if the value is not binary

## Complexity

Constant.

## Examples

??? example

    The following code shows how to query a binary value.
     
    ```cpp
    --8<-- "examples/get_binary.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/get_binary.output"
    ```

## Version history

- Added in version 3.8.0.
