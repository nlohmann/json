# <small>nlohmann::adl_serializer::</small>to_json

```cpp
template<typename BasicJsonType, typename TargetType = ValueType>
static auto to_json(BasicJsonType& j, TargetType && val) noexcept(
    noexcept(::nlohmann::to_json(j, std::forward<TargetType>(val))))
-> decltype(::nlohmann::to_json(j, std::forward<TargetType>(val)), void())
```

This function is usually called by the constructors of the [basic_json](../basic_json) class.

## Parameters

`j` (out)
:   JSON value to write to

`val` (in)
:   value to read from

!!! note

    This documentation page is a stub.

## Version history

- Added in version 2.1.0.
