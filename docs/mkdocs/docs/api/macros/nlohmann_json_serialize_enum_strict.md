# NLOHMANN_JSON_SERIALIZE_ENUM_STRICT

```cpp
#define NLOHMANN_JSON_SERIALIZE_ENUM_STRICT(type, conversion...)
```

By default, enum values are serialized to JSON as integers. In some cases, this could result in undesired behavior. If
an enum is modified or re-ordered after data has been serialized to JSON, the later deserialized JSON data may be
undefined or a different enum value than was originally intended.

`NLOHMANN_JSON_SERIALIZE_ENUM_STRICT` allows to define a user-defined serialization for every enumerator that
throws an exception on undefined input.

## Parameters

`type` (in)
:   name of the enum to serialize/deserialize

`conversion` (in)
:   a pair of an enumerator and a JSON serialization; arbitrary pairs can be given as a comma-separated list

## Default definition

The macro adds two functions to the namespace which take care of the serialization and deserialization:

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

    - When using [`get<ENUM_TYPE>()`](../basic_json/get.md), undefined JSON values will throw an exception.
    - If an enum or JSON value is specified in multiple conversions, the first matching conversion from the top of the
      list will be returned when converting to or from JSON. See example 2 below.

## Examples

??? example "Example 1: Basic usage"

    The example shows how `NLOHMANN_JSON_SERIALIZE_ENUM_STRICT` can be used to serialize/deserialize both classical enums and
    C++11 enum classes:

    ```cpp hl_lines="16 17 18 19 20 21 22 29 30 31 32 33"
    --8<-- "examples/nlohmann_json_serialize_enum_strict.cpp"
    ```

    Output:
    
    ```json
    --8<-- "examples/nlohmann_json_serialize_enum_strict.output"
    ```

??? example "Example 2: Multiple conversions for one enumerator"

    The example shows how to use multiple conversions for a single enumerator. In the example, `Color::red` will always
    be *serialized* to `"red"`, because the first occurring conversion. The second conversion, however, offers an
    alternative *deserialization* from `"rot"` to `Color::red`.

    ```cpp hl_lines="17"
    --8<-- "examples/nlohmann_json_serialize_enum_strict_2.cpp"
    ```

    Output:
    
    ```json
    --8<-- "examples/nlohmann_json_serialize_enum_strict_2.output"
    ```

??? example "Example 3: exceptions on invalid serialization"
    
    The example shows how an invalid serialization causes an exception to be thrown. In the example,
    Color::unknown is not defined in the mapping used to call `NLOHMANN_JSON_SERIALIZE_ENUM_STRICT`
    so causes an exception when used to serialize. Similarly, "what" does not refer to an enum
    value so also causes an exception when deserialization is attempted.

    ```cpp hl_lines="14 32 33 43 44 45"
    --8<-- "examples/nlohmann_json_serialize_enum_strict_err.cpp"
    ```

    Output:
    ```json
    --8<-- "examples/nlohmann_json_serialize_enum_strict_err.output"
    ```

## See also

- [Specializing enum conversion](../../features/enum_conversion.md)
- [`NLOHMANN_JSON_SERIALIZE_ENUM`](./nlohmann_json_serialize_enum.md)
- [`JSON_DISABLE_ENUM_SERIALIZATION`](json_disable_enum_serialization.md)

## Version history

Added in version 3.12.0.
