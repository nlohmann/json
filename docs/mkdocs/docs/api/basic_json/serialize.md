# <small>nlohmann::basic_json::</small>serialize

```cpp
template<typename T>
static basic_json serialize(const T& obj);
```

Map an arbitrary C++ object to a JSON value using reflection, without a hand-written `to_json` and without the
[`NLOHMANN_DEFINE_TYPE_*`](../macros/nlohmann_define_type_intrusive.md) macros. Each non-static data member of `obj`
becomes a key in a JSON object, keyed by the member's name unless a [`rename`](#notes) annotation overrides it.
Members recurse through the normal conversion machinery, so nested structs, containers, optionals, and types with a
custom `to_json` all serialize as they would anywhere else.

This function is only available when [`JSON_HAS_REFLECTION`](../macros/json_has_reflection.md) evaluates to `1`.

## Template parameters

`T`
:   the type to serialize. Must be a class or struct type that is not itself a `basic_json` specialization, a string, a
    container, or an optional. A plain struct with only public data members needs no annotation; a type with private or
    protected members must be annotated [`reflectable`](#notes) (or [`JSON_SERDE_ALLOW_PRIVATE`](../macros/json_has_reflection.md#notes)
    must be set).

## Parameters

`obj` (in)
:   the object to serialize

## Return value

a JSON object holding the serialized members of `obj`

## Exceptions

This function does not throw. (Member conversions it delegates to may throw if a member's own `to_json` does.)

## Complexity

Linear in the number of members, times the cost of serializing each member.

## Notes

!!! info "Annotations"

    The following annotations are applied to a data member (or, for `reflectable`, to the type) with the annotation
    syntax `#!cpp [[=nlohmann::...]]`. They affect both `serialize` and [`deserialize`](deserialize.md).

    | Annotation                             | Applies to | Effect                                                                   |
    |----------------------------------------|------------|--------------------------------------------------------------------------|
    | `#!cpp [[=nlohmann::transient]]`       | member     | the member is skipped entirely                |
    | `#!cpp [[=nlohmann::flatten]]`         | member     | a nested struct's keys are written at the parent level instead of nested |
    | `#!cpp [[=nlohmann::rename("key")]]`   | member     | the member uses `key` as its JSON key instead of its name                |
    | `#!cpp [[=nlohmann::reflectable]]`     | type       | grants the serializer access to the type's private and protected members |

!!! info "Enumerations"

    An enum member is serialized as the **name** of its enumerator (a string), not its underlying integer value. An
    enumerator formed by a cast that matches no name falls back to its integer representation.

!!! info "Optionals"

    An `std::optional` member with a value serializes as that value; an empty optional serializes as `#!json null`.

!!! warning "Relationship to the macros"

    `serialize`/`deserialize` only step in for types that have **no** `to_json`/`from_json` found by ADL and no
    `NLOHMANN_DEFINE_TYPE_*` expansion. A type that defines either keeps its hand-written behavior, so reflection never
    silently overrides an explicit conversion.

## Examples

??? example

    The example below serializes a plain struct, including a renamed key, a skipped member, and a nested struct inside a
    vector.

    ```cpp
    import std;
    import nlohmann.json;

    using nlohmann::json;

    enum class Element { FIRE, WATER, WIND };

    struct Spell { std::string name; int cost = 0; Element element = Element::FIRE; };

    struct Player {
        [[=nlohmann::rename("full_name")]] std::string name;
        int bombs = 3;
        std::vector<Spell> spells;
        [[=nlohmann::transient]] std::string password;
    };

    int main() {
        Player p = {
            .name = "Reimu",
            .bombs = 5,
            .spells = { Spell {.name = "Fantasy Seal", .cost = 50, .element = Element::WIND } },
            .password = "never persist me"
        };
        std::println("{}", json::serialize(p).dump(2));
    }
    ```

    Output:

    ```json
    {
      "full_name": "Reimu",
      "bombs": 5,
      "spells": [
        {
          "cost": 50,
          "element": "WIND",
          "name": "Fantasy Seal"
        }
      ]
    }
    ```

## See also

- [`deserialize`](deserialize.md) - the inverse: map a JSON value back into an object
- [`JSON_HAS_REFLECTION`](../macros/json_has_reflection.md) - whether this function is available
- [`NLOHMANN_DEFINE_TYPE_INTRUSIVE`](../macros/nlohmann_define_type_intrusive.md) - the macro-based alternative that
  works without reflection
- [Arbitrary Type Conversions](../../features/arbitrary_types.md) - overview of converting user types to and from JSON

## Version history

- Added in version 3.13.0.
