# <small>nlohmann::basic_json_document::</small>deserialize

```cpp
template<typename T>
T deserialize() const;
```

Map the JSON value of this document into an arbitrary C++ object using static reflection, without a hand-written `from_json` and
without the [`NLOHMANN_DEFINE_TYPE_*`](../macros/nlohmann_define_type_intrusive.md) macros. It is the inverse of
[`serialize`](../basic_json/serialize.md): each non-static data member of `T` is read from the object key that matches the member's
name (or its [`rename`](../basic_json/serialize.md#notes) annotation), and members recurse through the normal conversion machinery.
It is a shorthand for [`root().deserialize<T>()`](../basic_json_view/deserialize.md).

Unlike [`root()`](root.md), this function is also valid on a temporary document, because it returns an owned `T` and keeps no view.

This function is only available when [`JSON_HAS_REFLECTION`](../macros/json_has_reflection.md) evaluates to `1`.

## Template parameters

`T`
:   the type to deserialize into. Must be default-constructible and satisfy the same constraints as for
    [`serialize`](../basic_json/serialize.md) (a class or struct that is not a `basic_json` specialization, string, container, or
    optional). A type with private or protected members must be annotated [`reflectable`](../basic_json/serialize.md#notes).

## Return value

a `T` whose members are filled from the JSON value of the document

## Exceptions

- Throws [`deserialization_error.601`](../../home/exceptions.md#jsonexceptiondeserialization_error601) if a struct member is expected to be
  a JSON object but the key holds another type.
- Throws [`deserialization_error.602`](../../home/exceptions.md#jsonexceptiondeserialization_error602) if an enum member holds a string that
  matches no enumerator name.
- A member whose own `from_json` conversion fails propagates that conversion's exception (for example,
  [`type_error.302`](../../home/exceptions.md#jsonexceptiontype_error302) for a scalar of the wrong type).

## Complexity

Linear in the number of members, times the cost of deserializing each member.

## Notes

!!! info "Missing and null keys"

    A member whose key is absent, or present but `#!json null`, is left at its default value. This makes defaulted
    members and `std::optional` members behave naturally: a missing optional stays empty rather than being an error.

!!! info "Enumerations"

    An enum member is read from the **name** of its enumerator (a string), matching what [`serialize`](../basic_json/serialize.md)
    writes. A string that matches no enumerator throws
    [`deserialization_error.602`](../../home/exceptions.md#jsonexceptiondeserialization_error602).

!!! warning "Relationship to the macros"

    As with [`serialize`](../basic_json/serialize.md), reflection only steps in for types that have no `from_json` found by ADL and no
    `NLOHMANN_DEFINE_TYPE_*` expansion; a type that defines either keeps its hand-written behavior.

## Examples

??? example

    The example below round-trips a struct and shows that a missing key leaves the corresponding member at its default.

    ```cpp
    import std;
    import nlohmann.json;

    using nlohmann::json_document;

    struct Player {
        [[=nlohmann::rename("full_name")]] std::string name;
        int bombs = 3;
        std::optional<int> graze;
    };

    int main() {
        json_document doc = json_document::parse(R"({"full_name": "Marisa", "bombs": 2})");
        Player p = doc.deserialize<Player>();
        std::println("Name: {}, Bombs: {}, Has graze?: {}", p.name, p.bombs, p.graze.has_value());
    }
    ```

    Output:

    ```
    Name: Marisa, Bombs: 2, Has graze?: false
    ```

## See also

- [`basic_json_view::deserialize`](../basic_json_view/deserialize.md) - the operation on a view, which this function forwards to
- [`basic_json::deserialize`](../basic_json/deserialize.md) - the same operation on an owning `basic_json` value
- [`root`](root.md) - the root view of the document
- [`serialize`](../basic_json/serialize.md) - the inverse: map an object to a JSON value
- [`JSON_HAS_REFLECTION`](../macros/json_has_reflection.md) - whether this function is available
- [`deserialization_error`](../basic_json/deserialization_error.md) - the exception thrown on a failed reflection-based conversion

## Version history

- Added in version 3.13.0.
