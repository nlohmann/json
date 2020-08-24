# basic_json::get_to

```cpp
template<typename ValueType>
ValueType& get_to(ValueType& v) const noexcept(
    noexcept(JSONSerializer<ValueType>::from_json(
        std::declval<const basic_json_t&>(), v)))
```

Explicit type conversion between the JSON value and a compatible value. The value is filled into the input parameter by
calling the `json_serializer<ValueType>` `from_json()` method.

The function is equivalent to executing
```cpp
ValueType v;
JSONSerializer<ValueType>::from_json(*this, v);
```

This overloads is chosen if:

- `ValueType` is not `basic_json`,
- `json_serializer<ValueType>` has a `from_json()` method of the form `void from_json(const basic_json&, ValueType&)`

## Template parameters

`ValueType`
:   the value type to return

## Return value

the input parameter, allowing chaining calls

## Exceptions

Depends on what `json_serializer<ValueType>` `from_json()` method throws

## Example

??? example

    The example below shows several conversions from JSON values to other types. There a few things to note: (1)
    Floating-point numbers can be converted to integers, (2) A JSON array can be converted to a standard
    `#!cpp std::vector<short>`, (3) A JSON object can be converted to C++ associative containers such as
    `#cpp std::unordered_map<std::string, json>`.
        
    ```cpp
    --8<-- "examples/get_to.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/get_to.output"
    ```

## Version history

- Since version 3.3.0.
