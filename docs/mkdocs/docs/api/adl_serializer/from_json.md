# <small>nlohmann::adl_serializer::</small>from_json

```cpp
// (1)
template<typename BasicJsonType, typename TargetType = ValueType>
static auto from_json(BasicJsonType && j, TargetType& val) noexcept(
    noexcept(::nlohmann::from_json(std::forward<BasicJsonType>(j), val)))
-> decltype(::nlohmann::from_json(std::forward<BasicJsonType>(j), val), void())

// (2)
template<typename BasicJsonType, typename TargetType = ValueType>
static auto from_json(BasicJsonType && j) noexcept(
noexcept(::nlohmann::from_json(std::forward<BasicJsonType>(j), detail::identity_tag<TargetType> {})))
-> decltype(::nlohmann::from_json(std::forward<BasicJsonType>(j), detail::identity_tag<TargetType> {}))
```

This function is usually called by the [`get()`](../basic_json/get.md) function of the [basic_json](../basic_json)
class (either explicitly or via the conversion operators).

1. This function is chosen for default-constructible value types.
2. This function is chosen for value types which are not default-constructible.

## Parameters

`j` (in)
:   JSON value to read from

`val` (out)
:   value to write to

## Return value

Copy of the JSON value, converted to `ValueType`

## Examples

??? example "Example: (1) Default-constructible type"

    The example below shows how a `from_json` function can be implemented for a user-defined type. This function is
    called by the `adl_serializer` when `template get<ns::person>()` is called.
        
    ```cpp
    --8<-- "examples/from_json__default_constructible.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/from_json__default_constructible.output"
    ```

??? example "Example: (2) Non-default-constructible type"

    The example below shows how a `from_json` is implemented as part of a specialization of the `adl_serializer` to
    realize the conversion of a non-default-constructible type.
        
    ```cpp
    --8<-- "examples/from_json__non_default_constructible.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/from_json__non_default_constructible.output"
    ```

## See also

- [to_json](to_json.md)

## Version history

- Added in version 2.1.0.
