# nlohmann::is_json_view

Defined in header `<nlohmann/json_view.hpp>`

```
template<typename T>
struct is_json_view;
```

A type trait: `is_json_view<T>::value` is `true` if `T` is a [`basic_json_view`](https://json.nlohmann.me/api/basic_json_view/index.md) of any `BasicJsonType` and any [`view_mode`](https://json.nlohmann.me/api/view_mode/index.md) -- [`json_view`](https://json.nlohmann.me/api/json_view/index.md), [`json_editable_view`](https://json.nlohmann.me/api/json_editable_view/index.md), [`ordered_json_view`](https://json.nlohmann.me/api/ordered_json_view/index.md), ... -- and `false` otherwise, for [`basic_json`](https://json.nlohmann.me/api/basic_json/index.md) as well.

It is meant for constraining templates that accept views, in particular a `from_json()` that should read views directly: [`get<T>()`](https://json.nlohmann.me/api/basic_json_view/get/index.md) on a view calls a `from_json()` with the view only if that `from_json()` accepts views but not arbitrary types.

## Template parameters

`T` : the type to check (without cv-qualifiers or references)

## Notes

A view is recognized by its member type `basic_json_type` (a [`basic_json`](https://json.nlohmann.me/api/basic_json/index.md) specialization) and its [`materialize()`](https://json.nlohmann.me/api/basic_json_view/materialize/index.md) returning that type, so the trait needs no declaration of the view class.

## Examples

Example

The example below shows the trait, and a `from_json()` constrained to `json` values and views: `get<T>()` on a view reads the view directly.

```
#include <iostream>
#include <type_traits>
#include <nlohmann/json_view.hpp>

using nlohmann::json;

namespace ns
{
struct person
{
    std::string name;
    int age = 0;
};

// reads json values and views (of any document type), but nothing else
template < typename J, typename std::enable_if < nlohmann::is_json_view<J>::value || std::is_same<J, json>::value, int >::type = 0 >
void from_json(const J& j, person& p)
{
    p.name = j.at("name").template get<std::string>();
    p.age = j.at("age").template get<int>();
}
} // namespace ns

int main()
{
    std::cout << std::boolalpha
              << nlohmann::is_json_view<nlohmann::json_view>::value << ' '
              << nlohmann::is_json_view<nlohmann::ordered_json_editable_view>::value << ' '
              << nlohmann::is_json_view<json>::value << '\n';

    const nlohmann::json_document doc = nlohmann::json_document::parse(R"({"name": "Ada", "age": 36})");
    const auto p = doc.root().get<ns::person>(); // reads the view, no json value is built
    std::cout << p.name << ' ' << p.age << '\n';
}
```

Output:

```
true true false
Ada 36
```

## See also

- [basic_json_view](https://json.nlohmann.me/api/basic_json_view/index.md) - a handle to one value of a document
- [get](https://json.nlohmann.me/api/basic_json_view/get/index.md) - which conversions read the view directly
- [view_mode](https://json.nlohmann.me/api/view_mode/index.md) - read-only or editable
- [Writing generic code](https://json.nlohmann.me/features/json_view/#writing-generic-code) - functions and `from_json()` for views

## Version history

Added in version 3.13.0 unreleased.
