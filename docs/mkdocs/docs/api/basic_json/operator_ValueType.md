# <small>nlohmann::basic_json::</small>operator ValueType

```cpp
template<typename ValueType>
JSON_EXPLICIT operator ValueType() const;
```

Implicit type conversion between the JSON value and a compatible value. The call is realized by calling
[`get()`](get.md). See [Notes](#notes) for the meaning of `JSON_EXPLICIT`.

## Template parameters

`ValueType`
:   the value type to return

## Return value

copy of the JSON value, converted to `ValueType`

## Exceptions

Depends on what `json_serializer<ValueType>` `from_json()` method throws

## Complexity

Linear in the size of the JSON value.

## Notes

!!! note "Definition of `JSON_EXPLICIT`"

    By default `JSON_EXPLICIT` is defined to the empty string, so the signature is:
    
    ```cpp
    template<typename ValueType>
    operator ValueType() const;
    ```
    
    If [`JSON_USE_IMPLICIT_CONVERSIONS`](../macros/json_use_implicit_conversions.md) is set to `0`,
    `JSON_EXPLICIT` is defined to `#!cpp explicit`:

    ```cpp
    template<typename ValueType>
    explicit operator ValueType() const;
    ```
    
    That is, implicit conversions can be switched off by defining
    [`JSON_USE_IMPLICIT_CONVERSIONS`](../macros/json_use_implicit_conversions.md) to `0`.

!!! info "Future behavior change"

    Implicit conversions will be switched off by default in the next major release of the library. That is,
    `JSON_EXPLICIT` will be set to `#!cpp explicit` by default.

    You can prepare existing code by already defining
    [`JSON_USE_IMPLICIT_CONVERSIONS`](../macros/json_use_implicit_conversions.md) to `0` and replace any implicit
    conversions with calls to [`get`](../basic_json/get.md).

## Examples

??? example

    The example below shows several conversions from JSON values to other types. There are a few things to note: (1)
    Floating-point numbers can be converted to integers, (2) A JSON array can be converted to a standard
    `std::vector<short>`, (3) A JSON object can be converted to C++ associative containers such as
    `std::unordered_map<std::string, json>`.
        
    ```cpp
    --8<-- "examples/operator__ValueType.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/operator__ValueType.output"
    ```

## Version history

- Since version 1.0.0.
- Macros `JSON_EXPLICIT`/[`JSON_USE_IMPLICIT_CONVERSIONS`](../macros/json_use_implicit_conversions.md) added
  in version 3.9.0.
