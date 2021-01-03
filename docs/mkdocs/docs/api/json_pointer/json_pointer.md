# <small>nlohmann::json_pointer::</small>json_pointer

```cpp
explicit json_pointer(const string_t& s = "");
```

Create a JSON pointer according to the syntax described in
[Section 3 of RFC6901](https://tools.ietf.org/html/rfc6901#section-3).

## Parameters

`s` (in)
:    string representing the JSON pointer; if omitted, the empty string is assumed which references the whole JSON value

## Exceptions

- Throws [parse_error.107](../../home/exceptions.md#jsonexceptionparse_error107) if the given JSON pointer `s` is 
  nonempty and does not begin with a slash (`/`); see example below.
- Throws [parse_error.108](../../home/exceptions.md#jsonexceptionparse_error108) if a tilde (`~`) in the given JSON
  pointer `s` is not followed by `0` (representing `~`) or `1` (representing `/`); see example below.

## Examples

??? example

    The example shows the construction several valid JSON pointers as well as the exceptional behavior.
     
    ```cpp
    --8<-- "examples/json_pointer.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/json_pointer.output"
    ```

## Version history

- Added in version 2.0.0.
- Changed type of `s` to `string_t` in version 3.11.0.
