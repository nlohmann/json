# NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE, NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE_WITH_DEFAULT, NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE_ONLY_SERIALIZE, NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE, NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_WITH_DEFAULT, NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE

```
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

These macros can be used to simplify the serialization/deserialization of derived types if you want to use a JSON object as serialization and want to use the member variable names as object keys in that object.

- Macros 1, 2, and 3 are to be defined **inside** the class/struct to create code for. Like [`NLOHMANN_DEFINE_TYPE_INTRUSIVE`](https://json.nlohmann.me/api/macros/nlohmann_define_type_intrusive/index.md), they can access private members.
- Macros 4, 5, and 6 are to be defined **outside** the class/struct to create code for, but **inside** its namespace. Like [`NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE`](https://json.nlohmann.me/api/macros/nlohmann_define_type_non_intrusive/index.md), they **cannot** access private members.

The first parameter is the name of the derived class/struct, the second parameter is the name of the base class/struct and all remaining parameters name the members. The base type **must** be already serializable/deserializable.

- Macros 1 and 4 will use [`at`](https://json.nlohmann.me/api/basic_json/at/index.md) during deserialization and will throw [`out_of_range.403`](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range403) if a key is missing in the JSON object.
- Macros 2 and 5 will use [`value`](https://json.nlohmann.me/api/basic_json/value/index.md) during deserialization and fall back to the default value for the respective type of the member variable if a key in the JSON object is missing. The generated `from_json()` function default constructs an object and uses its values as the defaults when calling the `value` function.

Summary:

| Need access to private members | Need only serialization | Allow missing values when de-serializing | macro                                                         |
| ------------------------------ | ----------------------- | ---------------------------------------- | ------------------------------------------------------------- |
|                                |                         |                                          | **NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE**                    |
|                                |                         |                                          | **NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE_WITH_DEFAULT**       |
|                                |                         |                                          | **NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE_ONLY_SERIALIZE**     |
|                                |                         |                                          | **NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE**                |
|                                |                         |                                          | **NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_WITH_DEFAULT**   |
|                                |                         |                                          | **NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE** |

## Parameters

`type` (in) : name of the type (class, struct) to serialize/deserialize

`base_type` (in) : name of the base type (class, struct) `type` is derived from

`member` (in) : name of the member variable to serialize/deserialize; up to 63 members can be given as a comma-separated list

## Default definition

Macros 1 and 2 add two friend functions to the class which take care of the serialization and deserialization:

```
template<typename BasicJsonType>
friend void to_json(BasicJsonType&, const type&);
template<typename BasicJsonType>
friend void from_json(const BasicJsonType&, type&);
```

Macros 4 and 5 add two functions to the namespace which take care of the serialization and deserialization:

```
template<typename BasicJsonType>
void to_json(BasicJsonType&, const type&);
template<typename BasicJsonType>
void from_json(const BasicJsonType&, type&);
```

Macros 3 and 6 add one function to the namespace, which takes care of the serialization only:

```
template<typename BasicJsonType>
void to_json(BasicJsonType&, const type&);
```

In first two cases, they call the `to_json`/`from_json` functions of the base type before serializing/deserializing the members of the derived type:

```
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

```
class A { /* ... */ };
class B : public A { /* ... */ };

template<typename BasicJsonType>
void to_json(BasicJsonType& j, const B& b) {
    nlohmann::to_json(j, static_cast<const A&>(b));
    // ...
}
```

## Notes

Prerequisites

- Macros 1, 2, and 3 have the same prerequisites of [NLOHMANN_DEFINE_TYPE_INTRUSIVE](https://json.nlohmann.me/api/macros/nlohmann_define_type_intrusive/index.md).
- Macros 4, 5, and 6 have the same prerequisites of [NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE](https://json.nlohmann.me/api/macros/nlohmann_define_type_non_intrusive/index.md).
- Serialization/deserialization of base types must be defined.

Implementation limits

See Implementation limits for [NLOHMANN_DEFINE_TYPE_INTRUSIVE](https://json.nlohmann.me/api/macros/nlohmann_define_type_intrusive/index.md) and [NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE](https://json.nlohmann.me/api/macros/nlohmann_define_type_non_intrusive/index.md), respectively.

## Examples

NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE

Consider the following complete example:

```
#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using nlohmann::json;

class A
{
  private:
    double Aa = 0.0;
    double Ab = 0.0;

  public:
    A() = default;
    A(double a, double b) : Aa(a), Ab(b) {}
    NLOHMANN_DEFINE_TYPE_INTRUSIVE(A, Aa, Ab)
};

class B : public A
{
  private:
    int Ba = 0;
    int Bb = 0;

  public:
    B() = default;
    B(int a, int b, double aa, double ab) : A(aa, ab), Ba(a), Bb(b) {}
    NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE(B, A, Ba, Bb)
};

int main()
{
    B example(23, 42, 3.142, 1.777);
    json example_json = example;

    std::cout << std::setw(4) << example_json << std::endl;
}
```

Output:

```
{
    "Aa": 3.142,
    "Ab": 1.777,
    "Ba": 23,
    "Bb": 42
}
```

Notes:

- `A` and `B` are default-constructible. This is a requirement for using the macro.
- `A` has private members and is not a derived class. Hence, macro `NLOHMANN_DEFINE_TYPE_INTRUSIVE` is used.
- As `B` is a derived class, `NLOHMANN_DEFINE_TYPE_INTRUSIVE` is not applicable, but `NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE` must be used.
- The macro `NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE` is used *inside* the class use as `NLOHMANN_DEFINE_TYPE_INTRUSIVE`.

## See also

- [NLOHMANN_DEFINE_TYPE_INTRUSIVE / NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT / NLOHMANN_DEFINE_TYPE_INTRUSIVE_ONLY_SERIALIZE](https://json.nlohmann.me/api/macros/nlohmann_define_type_intrusive/index.md) for similar macros that can be defined *inside* a non-derived type.
- [NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE / NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT / NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE](https://json.nlohmann.me/api/macros/nlohmann_define_type_non_intrusive/index.md) for similar macros that can be defined *outside* a non-derived type.
- [Arbitrary Type Conversions](https://json.nlohmann.me/features/arbitrary_types/index.md) for an overview.

## Version history

1. Added in version 3.12.0.
1. Added in version 3.12.0.
1. Added in version 3.12.0.
1. Added in version 3.12.0.
1. Added in version 3.12.0.
1. Added in version 3.12.0.
