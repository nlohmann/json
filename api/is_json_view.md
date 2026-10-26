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

- [basic_json_view](basic_json_view/index.md) - a handle to one value of a document
- [get](basic_json_view/get.md) - which conversions read the view directly
- [view_mode](view_mode.md) - read-only or editable
- [Writing generic code](../features/json_view.md#writing-generic-code) - functions and `from_json()` for views

## Version history

Added in version 3.13.0.
