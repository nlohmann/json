# <small>nlohmann::json_pointer::</small>push_back

```cpp
void push_back(const string_t& token);

void push_back(string_t&& token);
```

Append an unescaped token at the end of the reference pointer.

## Parameters

`token` (in)
:   token to add

## Exception safety

Strong exception safety: if an exception occurs, the original value stays intact.

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

## See also

- [back](back.md) return last reference token
- [pop_back](pop_back.md) remove the last reference token
- [operator/=](operator_slasheq.md) append to the end of the JSON pointer
- [operator/](operator_slash.md) create JSON Pointer by appending

## Version history

- Added in version 3.6.0.
- Changed type of `token` to `string_t` in version 3.11.0.
