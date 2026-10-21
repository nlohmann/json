# <small>nlohmann::basic_json_view::</small>get_to

```cpp
template<typename T>
T& get_to(T& v) const;
```

Converts the value to `T` and stores it in `v`, in one of two ways:

- For the types that [`get<T>()`](get.md) converts directly -- arithmetic types, `#!cpp bool`,
  `#!cpp std::nullptr_t`, [`string_view_t`](index.md#member-types), `#!cpp std::basic_string`, `BasicJsonType`,
  `basic_json_view`, `#!cpp std::vector`, and `#!cpp std::map`/`#!cpp std::unordered_map` with string keys -- `v` is
  assigned: `#!cpp v = get<T>()`.
- For every other type, the subtree is built into a `BasicJsonType` value and `#!cpp materialize().get_to(v)` is
  called, i.e. `from_json()` is invoked with the existing `v`, exactly as
  [`BasicJsonType::get_to()`](../basic_json/get_to.md) does.

## Template parameters

`T`
:   the type to convert the value to

## Parameters

`v` (out)
:   the variable to store the converted value in

## Return value

`v`, allowing calls to chain

## Exception safety

- For the directly converted types: strong exception safety. If an exception is thrown, `v` is not modified.
- For every other type: as for [`BasicJsonType::get_to()`](../basic_json/get_to.md). `materialize()` throws before `v`
  is touched, but a `from_json()` that throws may leave `v` partly modified.

## Exceptions

- For the directly converted types: whatever [`get<T>()`](get.md) throws for the same value and `T`.
- For every other type: whatever [`materialize()`](materialize.md) and
  [`BasicJsonType::get_to()`](../basic_json/get_to.md) throw.

## Complexity

- For the directly converted types: whatever [`get<T>()`](get.md) has for the same `T`.
- For every other type: that of [`materialize()`](materialize.md), plus that of
  [`BasicJsonType::get_to()`](../basic_json/get_to.md).

## Notes

The difference between the two ways matters for a `from_json()` that sets only the fields present in the JSON: since
it runs on the existing `v`, the other fields of `v` keep their values, whereas assigning `get<T>()` would replace
them with those of a default-constructed `T`.

## Examples

??? example

    The example below reads several fields of a service configuration directly into existing variables, then uses
    the returned reference to fold the `#!cpp host`/`#!cpp port` pair into a single string in the same expression.

    ```cpp
    --8<-- "examples/basic_json_view__get_to.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_view__get_to.output"
    ```

## See also

- [get](get.md) - convert the value to a given type
- [`BasicJsonType::get_to`](../basic_json/get_to.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0.
