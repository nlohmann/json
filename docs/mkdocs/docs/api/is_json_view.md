# <small>nlohmann::</small>is_json_view

<small>Defined in header `<nlohmann/json_view.hpp>`</small>

```cpp
template<typename T>
struct is_json_view;
```

A type trait: `#!cpp is_json_view<T>::value` is `#!cpp true` if `T` is a [`basic_json_view`](basic_json_view/index.md)
of any `BasicJsonType` and any [`view_mode`](view_mode.md) -- [`json_view`](json_view.md),
[`json_editable_view`](json_editable_view.md), [`ordered_json_view`](ordered_json_view.md), ... -- and
`#!cpp false` otherwise, for [`basic_json`](basic_json/index.md) as well.

It is meant for constraining templates that accept views, in particular a `from_json()` that should read views
directly: [`get<T>()`](basic_json_view/get.md) on a view calls a `from_json()` with the view only if that `from_json()`
accepts views but not arbitrary types.

## Template parameters

`T`
:   the type to check (without cv-qualifiers or references)

## Notes

A view is recognized by its member type `basic_json_type` (a [`basic_json`](basic_json/index.md) specialization) and
its [`materialize()`](basic_json_view/materialize.md) returning that type, so the trait needs no declaration of the
view class.

## Examples

??? example

    The example below shows the trait, and a `from_json()` constrained to `json` values and views: `get<T>()` on a view
    reads the view directly.

    ```cpp
    --8<-- "examples/is_json_view.cpp"
    ```

    Output:

    ```
    --8<-- "examples/is_json_view.output"
    ```

## See also

- [basic_json_view](basic_json_view/index.md) - a handle to one value of a document
- [get](basic_json_view/get.md) - which conversions read the view directly
- [view_mode](view_mode.md) - read-only or editable

## Version history

Added in version 3.13.0.
