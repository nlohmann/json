# <small>nlohmann::json_pointer::</small>push_front

```cpp
void push_front(const string_t& token);

void push_front(string_t&& token);
```

Append an unescaped token at the start of the reference pointer.

## Parameters

`token` (in)
:   token to add

## Complexity

Linear in the number of reference tokens in the `json_pointer`.

## Examples

??? example

    The example shows the result of `push_front` for different JSON Pointers.
     
    ```cpp
    --8<-- "examples/json_pointer__push_front.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/json_pointer__push_front.output"
    ```

## Version history
