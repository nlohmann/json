<h1>NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_NAMES, NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT_WITH_NAMES,
    NLOHMANN_DEFINE_TYPE_INTRUSIVE_ONLY_SERIALIZE_WITH_NAMES, NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_NAMES,
    NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT_WITH_NAMES, NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE_WITH_NAMES,
    NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE_WITH_NAMES, NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE_WITH_DEFAULT_WITH_NAMES,
    NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE_ONLY_SERIALIZE_WITH_NAMES, NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_WITH_NAMES,
    NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_WITH_DEFAULT_WITH_NAMES, NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE_WITH_NAMES</h1>

```cpp
#define NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_NAMES(type, "json_member_name", member...)
#define NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT_WITH_NAMES(type, "json_member_name", member...)
#define NLOHMANN_DEFINE_TYPE_INTRUSIVE_ONLY_SERIALIZE_WITH_NAMES(type, "json_member_name", member...)
#define NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_NAMES(type, "json_member_name", member...)
#define NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT_WITH_NAMES(type, "json_member_name", member...)
#define NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE_WITH_NAMES(type, "json_member_name", member...)
#define NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE_WITH_NAMES(type, base_type, "json_member_name", member...)
#define NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE_WITH_DEFAULT_WITH_NAMES(type, base_type, "json_member_name", member...)
#define NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE_ONLY_SERIALIZE_WITH_NAMES(type, base_type, "json_member_name", member...)
#define NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_WITH_NAMES(type, base_type, "json_member_name", member...)
#define NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_WITH_DEFAULT_WITH_NAMES(type, base_type, "json_member_name", member...)
#define NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE_WITH_NAMES(type, base_type, "json_member_name", member...)
```

These macros can be used in case you want to use the custom names for the member variables in the resulting JSON.
They behave exactly as their non-`WITH_NAMES` counterparts, but require an additional parameter for each member variable
which will be used in JSON. Both serialization and deserialization will only use the custom names for JSON, the names of
the member variables themselves will be ignored.

Using the named conversion macros will halve the maximum number of member variables from 63 to 31.

For further information please refer to the corresponding macros without `WITH_NAMES`.

## Parameters

`type` (in)
:   name of the type (class, struct) to serialize/deserialize

`base_type` (in)
:   name of the base type (class, struct) `type` is derived from (used only in `DEFINE_DERIVED_TYPE` macros)

`json_member_name` (in)
:   the string that will be used as the name for the next value

`member` (in)
:   name of the member variable to serialize/deserialize

## Examples

??? example "Example (1): NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_NAMES"

    Consider the following complete example:

    ```cpp hl_lines="16"
    --8<-- "examples/nlohmann_define_type_non_intrusive_with_names_macro.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/nlohmann_define_type_non_intrusive_with_names_macro.output"
    ```

    Notes:

    - `ns::person` is default-constructible. This is a requirement for using the macro.
    - `ns::person` has only public member variables. This makes `NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_NAMES` applicable.
    - The macro `NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_NAMES` is used _outside_ the class, but _inside_ its namespace `ns`.
    - A missing key "age" in the deserialization yields an exception. To fall back to the default value,
      `NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT_WITH_NAMES` can be used.

    The macro is equivalent to:

    ```cpp hl_lines="16 17 18 19 20 21 22 23 24 25 26 27 28"
    --8<-- "examples/nlohmann_define_type_non_intrusive_with_names_explicit.cpp"
    ```

## Version history

1. Added in version 3.11.x.
