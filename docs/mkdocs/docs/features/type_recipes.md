# Recipes for Common Types

The library converts the standard containers, strings, numbers, tuples, `std::optional`, and `std::filesystem::path`
(the last two since version 3.12.0, C++17) out of the box, and your own types once you write conversion functions or use
the macros (see [Arbitrary type conversions](arbitrary_types.md)). It deliberately does **not** convert smart pointers,
`std::variant`, `std::chrono` types, or class hierarchies, because there is more than one reasonable JSON
representation for each of them. This page shows a representation for each that you can copy and adapt.

All recipes use a specialization of [`adl_serializer`](../api/adl_serializer/index.md), which you may provide for types
you do not own, or free `to_json`/`from_json` functions in the namespace of the type. Place them where they are
visible before any code that converts the type; see
[Why isn't my `to_json` found?](arbitrary_types.md#why-isnt-my-to_json-or-from_json-found).

## Smart pointers

A `std::shared_ptr<T>` or `std::unique_ptr<T>` is written as the value it points to, or as `#!json null` for an empty
pointer, and read back by allocating a new `T`:

??? example "Example: serialize shared_ptr and unique_ptr"

    ```cpp
    --8<-- "examples/type_recipes_smart_pointers.c++14.cpp"
    ```

    Output:

    ```
    --8<-- "examples/type_recipes_smart_pointers.c++14.output"
    ```

With this, containers of smart pointers, pointers to `const`, and members of these types in your own structs convert as
usual. A pointer to a base class cannot be filled this way, because `T` would have
to be created as a derived type; see the next section.

Reading creates a new object. Two `shared_ptr`s that pointed to the same object are written twice and read back as two
separate objects.

## Class hierarchies

!!! tip "Derived classes whose type is known at compile time"

    If you only need to serialize the data members of a derived class, and the code always knows the concrete type, you do
    not need a type tag. The [`NLOHMANN_DEFINE_DERIVED_TYPE_*` macros](arbitrary_types.md#simplify-your-life-with-macros)
    (since version 3.12.0) add the members of the derived class to those of its base class. This section is for the case
    where the concrete type is only known at run time, such as a `std::unique_ptr<shape>` that holds a circle or a
    rectangle.

JSON has no notion of types, so a value in a hierarchy needs a **type tag** that says which derived class to create.
Write the tag in the object, and select the class from it when reading:

??? example "Example: serialize a class hierarchy with a type tag"

    ```cpp
    --8<-- "examples/type_recipes_class_hierarchy.c++14.cpp"
    ```

    Output:

    ```
    --8<-- "examples/type_recipes_class_hierarchy.c++14.output"
    ```

A `#!cpp std::vector<std::unique_ptr<shape>>` converts to an array of tagged objects and back, creating a `circle`
and a `rectangle`. The same works for `std::shared_ptr<shape>`. Remember the virtual destructor: without it, deleting a
derived object through the base pointer is undefined behavior.

## `std::variant`

A variant has the same problem: the alternative must be recorded. If the alternatives are your own types, write a type
tag next to their members, exactly as for a hierarchy:

??? example "Example: serialize a std::variant with a type tag"

    ```cpp
    --8<-- "examples/type_recipes_variant.c++17.cpp"
    ```

    Output:

    ```
    --8<-- "examples/type_recipes_variant.c++17.output"
    ```

In the example, the functions are found
because `geo` is the namespace of the template arguments of `#!cpp std::variant<circ, rect>`; for a variant of only
standard types (for example `#!cpp std::variant<int, std::string>`) there is no such namespace, and you need an
`adl_serializer` specialization or a wrapper type of your own.

If the alternatives are JSON-native (numbers, strings, ...), a variant such as `#!cpp std::variant<int, std::string>`
can instead be written as the plain value, and read by testing the JSON type (`is_number_integer()`, `is_string()`)
to choose the alternative.

## `std::chrono`

A duration is written as its count and read back with the same representation and period. The **unit is not part of
the JSON value**, so document it, for example in the member name (`timeout_ms`):

??? example "Example: serialize durations and system_clock time points"

    ```cpp
    --8<-- "examples/type_recipes_chrono.cpp"
    ```

    Output:

    ```
    --8<-- "examples/type_recipes_chrono.output"
    ```

A `system_clock::time_point` with millisecond precision is written as the number of milliseconds since the Unix epoch.
The time point serializer is limited to `system_clock`,
because the epoch of other clocks (for example `steady_clock`) has no meaning outside the running program.

If you prefer a text representation such as ISO 8601 (`2023-11-14T22:13:20Z`), write the string with
`#!cpp std::format("{:%FT%TZ}", t)` and read it with `std::chrono::parse` (both C++20), or with a date library, in the
same two functions.

## See also

- [Arbitrary type conversions](arbitrary_types.md) - the conversion mechanism and macros
- [Why isn't my `to_json` found?](arbitrary_types.md#why-isnt-my-to_json-or-from_json-found)
- [Converting values](conversions.md) - `get`, implicit conversions, and `std::optional`
