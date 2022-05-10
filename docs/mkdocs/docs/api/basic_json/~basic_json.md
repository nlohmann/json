# <small>nlohmann::basic_json::</small>~basic_json

```cpp
~basic_json() noexcept;
```

Destroys the JSON value and frees all allocated memory.

## Exception safety

No-throw guarantee: this member function never throws exceptions.

## Complexity

Linear.

## Examples

??? example

    The following code shows an example for the destructor.
     
    ```cpp
    --8<-- "examples/~basic_json.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/~basic_json.output"
    ```

## Version history

- Added in version 1.0.0.
