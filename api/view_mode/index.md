# nlohmann::view_mode

Defined in header `<nlohmann/json_view.hpp>`

```
enum class view_mode : std::uint8_t
{
    read_only,
    editable
};
```

The second template parameter of [`basic_json_document`](https://json.nlohmann.me/api/basic_json_document/index.md) and [`basic_json_view`](https://json.nlohmann.me/api/basic_json_view/index.md): whether a document can be changed after parsing, and whether a view is of such a document.

`read_only` : the default: the document is parsed once and then only read. It carries none of the bookkeeping edits need, and calling [`set`](https://json.nlohmann.me/api/basic_json_document/set/index.md), [`push_back`](https://json.nlohmann.me/api/basic_json_document/push_back/index.md), [`insert`](https://json.nlohmann.me/api/basic_json_document/insert/index.md), or [`erase`](https://json.nlohmann.me/api/basic_json_document/erase/index.md) on it fails to compile.

`editable` : the document also offers [`set`](https://json.nlohmann.me/api/basic_json_document/set/index.md), [`push_back`](https://json.nlohmann.me/api/basic_json_document/push_back/index.md), [`insert`](https://json.nlohmann.me/api/basic_json_document/insert/index.md), and [`erase`](https://json.nlohmann.me/api/basic_json_document/erase/index.md); its views see every edit, see [Edits](https://json.nlohmann.me/api/basic_json_document/#edits).

The shortcuts name both modes: [`json_document`](https://json.nlohmann.me/api/json_document/index.md) and [`json_view`](https://json.nlohmann.me/api/json_view/index.md) are read-only, [`json_editable_document`](https://json.nlohmann.me/api/json_editable_document/index.md) and [`json_editable_view`](https://json.nlohmann.me/api/json_editable_view/index.md) are editable (and likewise for `ordered_json`).

## Notes

The mode is a compile-time property of the document's and the view's type, not a setting of a call. A read-only view reads a container in place, while a view of an editable document follows the links that edits leave behind. A view of a read-only document converts implicitly to a view of an editable document of the same `BasicJsonType`: a read-only document has no edits, so the converted view reads it like an editable document before its first edit (at the cost of one check per access). There is no conversion the other way, because a read-only view of an editable document would read wrong values after the next edit.

A function that takes a [`json_editable_view`](https://json.nlohmann.me/api/json_editable_view/index.md) therefore accepts the views of both modes. A function template deduces the mode from its argument instead, without conversions, so it names the modes it accepts in its signature:

```
// views of editable documents only
template<typename BasicJsonType>
void f(basic_json_view<BasicJsonType, view_mode::editable> v);

// views of read-only documents only
template<typename BasicJsonType>
void f(basic_json_view<BasicJsonType, view_mode::read_only> v);

// views of either document type
template<typename BasicJsonType, view_mode Mode>
void f(basic_json_view<BasicJsonType, Mode> v);
```

A function that takes a [`json_view`](https://json.nlohmann.me/api/json_view/index.md) accepts neither an [`ordered_json_view`](https://json.nlohmann.me/api/ordered_json_view/index.md) nor a [`json_editable_view`](https://json.nlohmann.me/api/json_editable_view/index.md). Views of the two modes compare with [`operator==`](https://json.nlohmann.me/api/basic_json_view/operator_eq/index.md).

## Examples

Example

The example below shows a function template that accepts the views of both modes, one that accepts only views of editable documents, and a function taking a `json_editable_view` that also accepts a view of a read-only document.

```
#include <iostream>
#include <nlohmann/json_view.hpp>

using nlohmann::basic_json_view;
using nlohmann::view_mode;

// accepts the views of read-only and of editable documents, of json and of ordered_json
template<typename BasicJsonType, view_mode Mode>
std::size_t count_members(basic_json_view<BasicJsonType, Mode> v)
{
    return v.is_object() ? v.size() : 0;
}

// accepts only the views of editable documents
template<typename BasicJsonType>
bool is_edited(basic_json_view<BasicJsonType, view_mode::editable> v)
{
    return v.is_string() && v.get_string() == "edited";
}

// a function (no template) taking a json_editable_view also accepts the view of a read-only document
std::size_t size_of(nlohmann::json_editable_view v)
{
    return v.size();
}

int main()
{
    const nlohmann::json_document doc = nlohmann::json_document::parse(R"({"a": 1, "b": 2})");
    nlohmann::json_editable_document edoc = nlohmann::json_editable_document::parse(R"({"a": 1})");
    edoc.set(edoc.root()["a"], "edited");

    std::cout << count_members(doc.root()) << ' ' << count_members(edoc.root()) << '\n';
    std::cout << std::boolalpha << is_edited(edoc.root()["a"]) << '\n';
    std::cout << size_of(doc.root()) << ' ' << size_of(edoc.root()) << '\n';
}
```

Output:

```
2 1
true
2 1
```

## See also

- [basic_json_document](https://json.nlohmann.me/api/basic_json_document/index.md) - a parsed JSON text
- [basic_json_view](https://json.nlohmann.me/api/basic_json_view/index.md) - a handle to one value of a document
- [json_editable_document](https://json.nlohmann.me/api/json_editable_document/index.md) - an editable document of `json`
- [(constructor)](https://json.nlohmann.me/api/basic_json_view/basic_json_view/index.md) - the conversion from a read-only to an editable view
- [Writing generic code](https://json.nlohmann.me/features/json_view/#writing-generic-code) - functions that accept views

## Version history

Added in version 3.13.0 unreleased.
