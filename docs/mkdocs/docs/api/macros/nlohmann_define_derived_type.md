<h1>NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE, NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE_WITH_DEFAULT,
    NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE_ONLY_SERIALIZE, NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE,
    NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_WITH_DEFAULT, NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE</h1>

```cpp
// (1)
#define NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE(type, base_type, member...)
// (2)
#define NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE_WITH_DEFAULT(type, base_type, member...)
// (3)
#define NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE_ONLY_SERIALIZE(type, base_type, member...)

// (4)
#define NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE(type, base_type, member...)
// (5)
#define NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_WITH_DEFAULT(type, base_type, member...)
// (6)
#define NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(type, base_type, member...)
```

These macros can be used to simplify the serialization/deserialization of derived types if you want to use a JSON
object as serialization and want to use the member variable names as object keys in that object.

- Macros 1, 2, and 3 are to be defined **inside** the class/struct to create code for.
Like [`NLOHMANN_DEFINE_TYPE_INTRUSIVE`](nlohmann_define_type_intrusive.md), they can access private members.
- Macros 4, 5, and 6 are to be defined **outside** the class/struct to create code for, but **inside** its namespace.
Like [`NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE`](nlohmann_define_type_non_intrusive.md),
they **cannot** access private members.

The first parameter is the name of the derived class/struct,
the second parameter is the name of the base class/struct and all remaining parameters name the members.
The base type **must** be already serializable/deserializable.

- Macros 1 and 4 will use [`at`](../basic_json/at.md) during deserialization and will throw
  [`out_of_range.403`](../../home/exceptions.md#jsonexceptionout_of_range403) if a key is missing in the JSON object.
- Macros 2 and 5 will use [`value`](../basic_json/value.md) during deserialization and fall back to the default value for the
   respective type of the member variable if a key in the JSON object is missing. The generated `from_json()` function
   default constructs an object and uses its values as the defaults when calling the `value` function.

Summary:

| Need access to private members                                   | Need only de-serialization                                       | Allow missing values when de-serializing                         | macro                                                         |
|------------------------------------------------------------------|------------------------------------------------------------------|------------------------------------------------------------------|---------------------------------------------------------------|
| <div style="color: green;">:octicons-check-circle-fill-24:</div> | <div style="color: red;">:octicons-x-circle-fill-24:</div>       | <div style="color: red;">:octicons-x-circle-fill-24:</div>       | **NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE**                    |
| <div style="color: green;">:octicons-check-circle-fill-24:</div> | <div style="color: red;">:octicons-x-circle-fill-24:</div>       | <div style="color: green;">:octicons-check-circle-fill-24:</div> | **NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE_WITH_DEFAULT**       |
| <div style="color: green;">:octicons-check-circle-fill-24:</div> | <div style="color: green;">:octicons-check-circle-fill-24:</div> | <div style="color: grey;">:octicons-skip-fill-24:</div>          | **NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE_ONLY_SERIALIZE**     |
| <div style="color: red;">:octicons-x-circle-fill-24:</div>       | <div style="color: red;">:octicons-x-circle-fill-24:</div>       | <div style="color: red;">:octicons-x-circle-fill-24:</div>       | **NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE**                |
| <div style="color: red;">:octicons-x-circle-fill-24:</div>       | <div style="color: red;">:octicons-x-circle-fill-24:</div>       | <div style="color: green;">:octicons-check-circle-fill-24:</div> | **NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_WITH_DEFAULT**   |
| <div style="color: red;">:octicons-x-circle-fill-24:</div>       | <div style="color: green;">:octicons-check-circle-fill-24:</div> | <div style="color: grey;">:octicons-skip-fill-24:</div>          | **NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE** |

## Parameters

`type` (in)
:   name of the type (class, struct) to serialize/deserialize

`base_type` (in)
:   name of the base type (class, struct) `type` is derived from

`member` (in)
:   name of the member variable to serialize/deserialize; up to 64 members can be given as a comma-separated list

## Default definition

Macros 1 and 2 add two friend functions to the class which take care of the serialization and deserialization:

```cpp
template<typename BasicJsonType>
friend void to_json(BasicJsonType&, const type&);
template<typename BasicJsonType>
friend void from_json(const BasicJsonType&, type&);
```

Macros 4 and 5 add two functions to the namespace which take care of the serialization and deserialization:

```cpp
template<typename BasicJsonType>
void to_json(BasicJsonType&, const type&);
template<typename BasicJsonType>
void from_json(const BasicJsonType&, type&);
```

Macros 3 and 6 add one function to the namespace, which takes care of the serialization only:

```cpp
template<typename BasicJsonType>
void to_json(BasicJsonType&, const type&);
```

In first two cases, they call the `to_json`/`from_json` functions of the base type
before serializing/deserializing the members of the derived type:

```cpp
class A { /* ... */ };
class B : public A { /* ... */ };

template<typename BasicJsonType>
void to_json(BasicJsonType& j, const B& b) {
    nlohmann::to_json(j, static_cast<const A&>(b));
    // ...
}

template<typename BasicJsonType>
void from_json(const BasicJsonType& j, B& b) {
    nlohmann::from_json(j, static_cast<A&>(b));
    // ...
}
```

In the third case, only `to_json` will be called:

```cpp
class A { /* ... */ };
class B : public A { /* ... */ };

template<typename BasicJsonType>
void to_json(BasicJsonType& j, const B& b) {
    nlohmann::to_json(j, static_cast<const A&>(b));
    // ...
}
```

## Notes

!!! info "Prerequisites"

    - Macros 1, 2, and 3 have the same prerequisites of [NLOHMANN_DEFINE_TYPE_INTRUSIVE](nlohmann_define_type_intrusive.md).
    - Macros 4, 5, and 6 have the same prerequisites of [NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE](nlohmann_define_type_non_intrusive.md).
    - Serialization/deserialization of base types must be defined.

!!! warning "Implementation limits"

    See Implementation limits for [NLOHMANN_DEFINE_TYPE_INTRUSIVE](nlohmann_define_type_intrusive.md) and
    [NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE](nlohmann_define_type_non_intrusive.md), respectively.

## Examples

??? example "NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE"

    Consider the following complete example:

    ```cpp hl_lines="28"
    --8<-- "examples/nlohmann_define_derived_type_intrusive_macro.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/nlohmann_define_derived_type_intrusive_macro.output"
    ```

    Notes:

    - `A` and `B` are default-constructible. This is a requirement for using the macro.
    - `A` has private members and is not a derived class. Hence, macro `NLOHMANN_DEFINE_TYPE_INTRUSIVE` is used.
    - As `B` is a derived class, `NLOHMANN_DEFINE_TYPE_INTRUSIVE` is not applicable, but
      `NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE` must be used.
    - The macro `NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE` is used _inside_ the class use as
      `NLOHMANN_DEFINE_TYPE_INTRUSIVE`.

## See also

- [NLOHMANN_DEFINE_TYPE_INTRUSIVE / NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT / 
  NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE_ONLY_SERIALIZE](nlohmann_define_type_intrusive.md)
  for similar macros that can be defined _inside_ a non-derived type.
- [NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE / NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT / 
  NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE](nlohmann_define_type_non_intrusive.md)
  for similar macros that can be defined _outside_ a non-derived type.
- [Arbitrary Type Conversions](../../features/arbitrary_types.md) for an overview.

## Version history

1. Added in version 3.12.0.
2. Added in version 3.12.0.
3. Added in version 3.12.0.
4. Added in version 3.12.0.
5. Added in version 3.12.0.
6. Added in version 3.12.0.
