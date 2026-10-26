# <small>nlohmann::</small>view_mode

<small>Defined in header `<nlohmann/json_view.hpp>`</small>

```cpp
enum class view_mode : std::uint8_t
{
    read_only,
    editable
};
```

The second template parameter of [`basic_json_document`](basic_json_document/index.md) and
[`basic_json_view`](basic_json_view/index.md): whether a document can be changed after parsing, and whether a view is
of such a document.

`read_only`
:   the default: the document is parsed once and then only read. It carries none of the bookkeeping edits need, and
    calling [`set`](basic_json_document/set.md), [`push_back`](basic_json_document/push_back.md),
    [`insert`](basic_json_document/insert.md), or [`erase`](basic_json_document/erase.md) on it fails to compile.

`editable`
:   the document also offers [`set`](basic_json_document/set.md), [`push_back`](basic_json_document/push_back.md),
    [`insert`](basic_json_document/insert.md), and [`erase`](basic_json_document/erase.md); its views see every edit,
    see [Edits](basic_json_document/index.md#edits).

The shortcuts name both modes: [`json_document`](json_document.md) and [`json_view`](json_view.md) are read-only,
[`json_editable_document`](json_editable_document.md) and [`json_editable_view`](json_editable_view.md) are editable
(and likewise for `ordered_json`).

## Notes

The mode is a compile-time property of the document's and the view's type, not a setting of a call, and there is no conversion between the two modes: a read-only view reads a
container in place, while a view of an editable document follows the links that edits leave behind. A function that
accepts views therefore names the modes it accepts in its signature:

```cpp
// views of editable documents only
template<typename BasicJsonType>
void f(basic_json_view<BasicJsonType, view_mode::editable> v);

// views of read-only documents only
template<typename BasicJsonType>
void f(basic_json_view<BasicJsonType, view_mode::read_only> v);

// either
template<typename BasicJsonType, view_mode Mode>
void f(basic_json_view<BasicJsonType, Mode> v);
```

A function that takes a [`json_view`](json_view.md) accepts neither an [`ordered_json_view`](ordered_json_view.md)
nor a [`json_editable_view`](json_editable_view.md). Views of the two modes still compare with
[`operator==`](basic_json_view/operator_eq.md).

## Examples

??? example

    The example below shows a function template that accepts the views of both modes, and one that accepts only
    views of editable documents.

    ```cpp
    --8<-- "examples/view_mode.cpp"
    ```

    Output:

    ```
    --8<-- "examples/view_mode.output"
    ```

## See also

- [basic_json_document](basic_json_document/index.md) - a parsed JSON text
- [basic_json_view](basic_json_view/index.md) - a handle to one value of a document
- [json_editable_document](json_editable_document.md) - an editable document of `json`

## Version history

Added in version 3.13.0.
