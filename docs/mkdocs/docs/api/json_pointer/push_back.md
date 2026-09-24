# <small>nlohmann::json_pointer::</small>push_back

```cpp
void push_back(const string_t& token);

void push_back(string_t&& token);
```

Append an unescaped token at the end of the reference pointer.

## Parameters

`token` (in)
:   token to add

## Complexity

Amortized constant.

## Examples

??? example

    The example shows the result of `push_back` for different JSON Pointers.
     
    ```cpp
    --8<-- "examples/json_pointer__push_back.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/json_pointer__push_back.output"
    ```

## Version history

- Added in version 3.6.0.
- Changed type of `token` to `string_t` in version 3.11.0.
