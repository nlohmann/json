# NLOHMANN_DEFINE_TYPE_INTRUSIVE, NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT, NLOHMANN_DEFINE_TYPE_INTRUSIVE_ONLY_SERIALIZE

```cpp
#define NLOHMANN_DEFINE_TYPE_INTRUSIVE(type, member...)              // (1)
#define NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(type, member...) // (2)
#define NLOHMANN_DEFINE_TYPE_INTRUSIVE_ONLY_SERIALIZE(type, member...) // (3)
```

These macros can be used to simplify the serialization/deserialization of types if you want to use a JSON object as
serialization and want to use the member variable names as object keys in that object. The macro is to be defined
**inside** the class/struct to create code for. Unlike
[`NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE`](nlohmann_define_type_non_intrusive.md), it can access private members. The first
parameter is the name of the class/struct, and all remaining parameters name the members.

1. Will use [`at`](../basic_json/at.md) during deserialization and will throw
  [`out_of_range.403`](../../home/exceptions.md#jsonexceptionout_of_range403) if a key is missing in the JSON object.
2. Will use [`value`](../basic_json/value.md) during deserialization and fall back to the default value for the
   respective type of the member variable if a key in the JSON object is missing. The generated `from_json()` function
   default constructs an object and uses its values as the defaults when calling the `value` function.
3. Only defines the serialization. Useful in cases when the type does not have a default constructor and only serialization is required.

Summary:

| Need access to private members                                   | Need only de-serialization                                       | Allow missing values when de-serializing                         | macro                                                 |
|------------------------------------------------------------------|------------------------------------------------------------------|------------------------------------------------------------------|-------------------------------------------------------|
| <div style="color: green;">:octicons-check-circle-fill-24:</div> | <div style="color: red;">:octicons-x-circle-fill-24:</div>       | <div style="color: red;">:octicons-x-circle-fill-24:</div>       | **NLOHMANN_DEFINE_TYPE_INTRUSIVE**                    |
| <div style="color: green;">:octicons-check-circle-fill-24:</div> | <div style="color: red;">:octicons-x-circle-fill-24:</div>       | <div style="color: green;">:octicons-check-circle-fill-24:</div> | **NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT**       |
| <div style="color: green;">:octicons-check-circle-fill-24:</div> | <div style="color: green;">:octicons-check-circle-fill-24:</div> | <div style="color: grey;">:octicons-skip-fill-24:</div>          | **NLOHMANN_DEFINE_TYPE_INTRUSIVE_ONLY_SERIALIZE**     |

## Parameters

`type` (in)
:   name of the type (class, struct) to serialize/deserialize

`member` (in)
:   name of the member variable to serialize/deserialize; up to 64 members can be given as a comma-separated list

## Default definition

The macros add two friend functions to the class which take care of the serialization and deserialization:

```cpp
template<typename BasicJsonType>
friend void to_json(BasicJsonType&, const type&);
template<typename BasicJsonType>
friend void from_json(const BasicJsonType&, type&); // except (3)
```

See examples below for the concrete generated code.

## Notes

!!! info "Prerequisites"

    1. The type `type` must be default constructible (except (3)). See [How can I use `get()` for non-default
       constructible/non-copyable types?][GetNonDefNonCopy] for how to overcome this limitation.
    2. The macro must be used inside the type (class/struct).

[GetNonDefNonCopy]: ../../features/arbitrary_types.md#how-can-i-use-get-for-non-default-constructiblenon-copyable-types

!!! warning "Implementation limits"

    - The current implementation is limited to at most 64 member variables. If you want to serialize/deserialize types
      with more than 64 member variables, you need to define the `to_json`/`from_json` functions manually.

## Examples

??? example "Example (1): NLOHMANN_DEFINE_TYPE_INTRUSIVE"

    Consider the following complete example:

    ```cpp hl_lines="22"
    --8<-- "examples/nlohmann_define_type_intrusive_macro.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/nlohmann_define_type_intrusive_macro.output"
    ```

    Notes:

    - `ns::person` is default-constructible. This is a requirement for using the macro.
    - `ns::person` has private member variables. This makes `NLOHMANN_DEFINE_TYPE_INTRUSIVE` applicable, but not
      `NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE`.
    - The macro `NLOHMANN_DEFINE_TYPE_INTRUSIVE` is used _inside_ the class.
    - A missing key "age" in the deserialization yields an exception. To fall back to the default value,
      `NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT` can be used.

    The macro is equivalent to:

    ```cpp hl_lines="22 23 24 25 26 27 28 29 30 31 32 33 34 35 36"
    --8<-- "examples/nlohmann_define_type_intrusive_explicit.cpp"
    ```

??? example "Example (2): NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT"

    Consider the following complete example:

    ```cpp hl_lines="22"
    --8<-- "examples/nlohmann_define_type_intrusive_with_default_macro.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/nlohmann_define_type_intrusive_with_default_macro.output"
    ```

    Notes:

    - `ns::person` is default-constructible. This is a requirement for using the macro.
    - `ns::person` has private member variables. This makes `NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT` applicable,
       but not `NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT`.
    - The macro `NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT` is used _inside_ the class.
    - A missing key "age" in the deserialization does not yield an exception. Instead, the default value `-1` is used.

    The macro is equivalent to:

    ```cpp hl_lines="22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37"
    --8<-- "examples/nlohmann_define_type_intrusive_with_default_explicit.cpp"
    ```

    Note how a default-initialized `person` object is used in the `from_json` to fill missing values.

??? example "Example (3): NLOHMANN_DEFINE_TYPE_INTRUSIVE_ONLY_SERIALIZE"
    Consider the following complete example:

    ```cpp hl_lines="22"
    --8<-- "examples/nlohmann_define_type_intrusive_only_serialize_macro.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/nlohmann_define_type_intrusive_only_serialize_macro.output"
    ```

    Notes:

    - `ns::person` is non-default-constructible. This allows this macro to be used instead of 
      `NLOHMANN_DEFINE_TYPE_INTRUSIVE` and `NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT`.
    - `ns::person` has private member variables. This makes `NLOHMANN_DEFINE_TYPE_INTRUSIVE_ONLY_SERIALIZE` applicable, but not
      `NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE`.
    - The macro `NLOHMANN_DEFINE_TYPE_INTRUSIVE_ONLY_SERIALIZE` is used _inside_ the class.

    The macro is equivalent to:

    ```cpp hl_lines="22 22 23 24 25 26 27 28"
    --8<-- "examples/nlohmann_define_type_intrusive_only_serialize_explicit.cpp"
    ```

## See also

- [NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE, NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT, 
  NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE](nlohmann_define_type_non_intrusive.md)
  for a similar macro that can be defined _outside_ the type.
- [NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE, NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE_WITH_DEFAULT,
  NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE_ONLY_SERIALIZE, NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE,
  NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_WITH_DEFAULT, 
  NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE](nlohmann_define_derived_type.md) for similar macros for
  derived types
- [Arbitrary Type Conversions](../../features/arbitrary_types.md) for an overview.

## Version history

1. Added in version 3.9.0.
2. Added in version 3.11.0.
3. Added in version 3.11.3.
