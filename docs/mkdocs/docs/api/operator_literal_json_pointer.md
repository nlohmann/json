# <small>nlohmann::</small>operator""_json_pointer

```cpp
json_pointer operator ""_json_pointer(const char* s, std::size_t n);
json_pointer operator ""_json_pointer(const char8_t* s, std::size_t n);  // since C++20
```

This operator implements a user-defined string literal for JSON Pointers. It can be used by adding `#!cpp _json_pointer`
to a string literal and returns a [`json_pointer`](json_pointer/index.md) object if no parse error occurred.

It is recommended to bring the operator into scope using any of the following lines:
```cpp
using nlohmann::literals::operator ""_json_pointer;
using namespace nlohmann::literals;
using namespace nlohmann::json_literals;
using namespace nlohmann::literals::json_literals;
using namespace nlohmann;
```
This is suggested to ease migration to the next major version release of the library. See
[`JSON_USE_GLOBAL_UDLS`](macros/json_use_global_udls.md#notes) for details.

## Parameters

`s` (in)
:   a string representation of a JSON Pointer

`n` (in)
:   length of string `s`

## Return value

[`json_pointer`](json_pointer/index.md) value parsed from `s`

## Exceptions

The function can throw anything that [`json_pointer::json_pointer`](json_pointer/index.md) would throw.

## Complexity

Linear.

## Examples

??? example

    The following code shows how to create JSON Pointers from string literals.
     
    ```cpp
    --8<-- "examples/operator_literal_json_pointer.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/operator_literal_json_pointer.output"
    ```

## See also

- [json_pointer](json_pointer/index.md) - type to represent JSON Pointers

## Version history

- Added in version 2.0.0.
- Moved to namespace `nlohmann::literals::json_literals` in 3.11.0.
- Added `char8_t*` overload in 3.12.1.
