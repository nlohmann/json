# NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE, NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE_WITH_DEFAULT

# NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE, NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_WITH_DEFAULT

```cpp
#define NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE(type, base_type, member...)                  // (1)
#define NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE_WITH_DEFAULT(type, base_type, member...)     // (2)

#define NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE(type, base_type, member...)              // (3)
#define NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_WITH_DEFAULT(type, base_type, member...) // (4)
```

These macros can be used to simplify the serialization/deserialization of derived types if you want to use a JSON
object as serialization and want to use the member variable names as object keys in that object.

- Macros 1 and 2 are to be defined **inside** the class/struct to create code for.
Like [`NLOHMANN_DEFINE_TYPE_INTRUSIVE`](nlohmann_define_type_intrusive.md), they can access private members.
- Macros 3 and 4 are to be defined **outside** the class/struct to create code for, but **inside** its namespace.
Like [`NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE`](nlohmann_define_type_non_intrusive.md),
they **cannot** access private members.


The first  parameter is the name of the derived class/struct,
the second parameter is the name of the base class/struct and all remaining parameters name the members.
The base type **must** be already serializable/deserializable.

- Macros 1 and 3 will use [`at`](../basic_json/at.md) during deserialization and will throw
  [`out_of_range.403`](../../home/exceptions.md#jsonexceptionout_of_range403) if a key is missing in the JSON object.
- Macros 2 and 4 will use [`value`](../basic_json/value.md) during deserialization and fall back to the default value for the
   respective type of the member variable if a key in the JSON object is missing. The generated `from_json()` function
   default constructs an object and uses its values as the defaults when calling the `value` function.

## Parameters

`type` (in)
:   name of the type (class, struct) to serialize/deserialize

`base_type` (in)
:   name of the base type (class, struct) `type` is derived from

`member` (in)
:   name of the member variable to serialize/deserialize; up to 64 members can be given as comma-separated list

## Default definition

Macros 1 and 2 add two friend functions to the class which take care of the serialization and deserialization:

```cpp
friend void to_json(nlohmann::json&, const type&);
friend void from_json(const nlohmann::json&, type&);
```

Macros 3 and 4 add two functions to the namespace which take care of the serialization and deserialization:

```cpp
void to_json(nlohmann::json&, const type&);
void from_json(const nlohmann::json&, type&);
```

In both cases they call the `to_json`/`from_json` functions of the base type
before serializing/deserializing the members of the derived type:

```cpp
class A { /* ... */ };
class B : public A { /* ... */ };

void to_json(nlohmann::json& j, const B& b) {
    nlohmann::to_json(j, static_cast<const A&>(b));
    // ...
}

void from_json(const nlohmann::json& j, B& b) {
    nlohmann::from_json(j, static_cast<A&>(b));
    // ...
}
```

## Notes

!!! info "Prerequisites"

    - Macros 1 and 2 have the same prerequisites of NLOHMANN_DEFINE_TYPE_INTRUSIVE. 
    - Macros 3 and 3 have the same prerequisites of NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE.
    - Serialization/deserialization of base types must be defined.

!!! warning "Implementation limits"

    - See Implementation limits for NLOHMANN_DEFINE_TYPE_INTRUSIVE and NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE.

## Examples

Example of `NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE` usage:

```cpp
class A {
  double Aa;
  double Ab;
  NLOHMANN_DEFINE_TYPE_INTRUSIVE(A, Aa, Ab)
};

class B : public A {
  int Ba;
  int Bb;
  NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE(B, A, Ba, Bb)
};
```

## See also

- [NLOHMANN_DEFINE_TYPE_INTRUSIVE / NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT](nlohmann_define_type_intrusive.md)
  for similar macros that can be defined _inside_ a non-derived type.
- [NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE / NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT](nlohmann_define_type_non_intrusive.md)
  for a similar macros that can be defined _outside_ a non-derived type.
- [Arbitrary Type Conversions](../../features/arbitrary_types.md) for an overview.

## Version history

1. Added in version 3.11.x.
