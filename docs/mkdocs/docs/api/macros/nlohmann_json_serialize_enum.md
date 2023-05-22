# NLOHMANN_JSON_SERIALIZE_ENUM

```cpp
#define NLOHMANN_JSON_SERIALIZE_ENUM(type, conversion...)
```

By default, enum values are serialized to JSON as integers. In some cases this could result in undesired behavior. If an
enum is modified or re-ordered after data has been serialized to JSON, the later de-serialized JSON data may be
undefined or a different enum value than was originally intended.

The `NLOHMANN_JSON_SERIALIZE_ENUM` allows to define a user-defined serialization for every enumerator.

## Parameters

`type` (in)
:   name of the enum to serialize/deserialize

`conversion` (in)
:   a pair of an enumerator and a JSON serialization; arbitrary pairs can be given as a comma-separated list

## Default definition

The macros add two friend functions to the class which take care of the serialization and deserialization:

```cpp
template<typename BasicJsonType>
inline void to_json(BasicJsonType& j, const type& e);
template<typename BasicJsonType>
inline void from_json(const BasicJsonType& j, type& e);
```

## Notes

!!! info "Prerequisites"

    The macro must be used inside the namespace of the enum.

!!! important "Important notes"

    - When using [`template get<ENUM_TYPE>()`](../basic_json/get.md), undefined JSON values will default to the first specified
      conversion. Select this default pair carefully. See example 1 below.
    - If an enum or JSON value is specified in multiple conversions, the first matching conversion from the top of the
      list will be returned when converting to or from JSON. See example 2 below.

## Examples

??? example "Example 1: Basic usage"

    The example shows how `NLOHMANN_JSON_SERIALIZE_ENUM` can be used to serialize/deserialize both classical enums and
    C++11 enum classes:

    ```cpp hl_lines="16 17 18 19 20 21 22 29 30 31 32 33"
    --8<-- "examples/nlohmann_json_serialize_enum.cpp"
    ```

    Output:
    
    ```json
    --8<-- "examples/nlohmann_json_serialize_enum.output"
    ```

??? example "Example 2: Multiple conversions for one enumerator"

    The example shows how to use multiple conversions for a single enumerator. In the example, `Color::red` will always
    be *serialized* to `"red"`, because the first occurring conversion. The second conversion, however, offers an
    alternative *deserialization* from `"rot"` to `Color::red`.

    ```cpp hl_lines="17"
    --8<-- "examples/nlohmann_json_serialize_enum_2.cpp"
    ```

    Output:
    
    ```json
    --8<-- "examples/nlohmann_json_serialize_enum_2.output"
    ```

## See also

- [Specializing enum conversion](../../features/enum_conversion.md)
- [`JSON_DISABLE_ENUM_SERIALIZATION`](json_disable_enum_serialization.md)

## Version history

Added in version 3.4.0.
