# nlohmann::basic_json_view::is_discarded

```
bool is_discarded() const noexcept;
```

Returns whether this view is invalid, i.e. does not refer to a value. This is the case for a default-constructed view (see [(constructor)](https://json.nlohmann.me/api/basic_json_view/basic_json_view/index.md)), and for [`root()`](https://json.nlohmann.me/api/basic_json_document/root/index.md) of a document that is itself [discarded](https://json.nlohmann.me/api/basic_json_document/is_discarded/index.md) — in particular, the root of a failed [`parse()`](https://json.nlohmann.me/api/basic_json_document/parse/index.md) with `allow_exceptions` set to `false`.

A discarded view is also what [`operator[]`](https://json.nlohmann.me/api/basic_json_view/operator%5B%5D/index.md) returns for a missing key, an index out of range, or a JSON pointer that cannot be resolved, and for any access on a view that is itself discarded (so a chain such as `v["a"]["b"]` is safe). [`at`](https://json.nlohmann.me/api/basic_json_view/at/index.md) throws instead.

## Return value

`true` if the view or its document is discarded, `false` otherwise.

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Notes

A `basic_json_view` is not convertible to `bool`: such a conversion would mean "refers to a value", whereas `basic_json` converts to the `bool` it holds, so the same code would silently behave differently. Test `!v.is_discarded()` explicitly.

## Examples

Example

The example below classifies several parsed documents by the type of their root value, without materializing any of them into a `BasicJsonType` value.

```
#include <iostream>
#include <nlohmann/json_view.hpp>

using nlohmann::json_document;

int main()
{
    std::cout << std::boolalpha;

    // several incoming messages, one json_document per message. type() and
    // is_*() only look at the flat index built by parse(); no nlohmann::json
    // tree exists yet, and none is built unless materialize() is called
    json_document d_null = json_document::parse("null");
    json_document d_bool = json_document::parse("true");
    json_document d_int = json_document::parse("-42");
    json_document d_unsigned = json_document::parse("42");
    json_document d_float = json_document::parse("4.2");
    json_document d_string = json_document::parse(R"("hi")");
    json_document d_array = json_document::parse("[1, 2, 3]");
    json_document d_object = json_document::parse(R"({"a": 1})");

    std::cout << d_null.root().is_null() << '\n';
    std::cout << d_bool.root().is_boolean() << '\n';
    std::cout << d_int.root().is_number() << ' ' << d_int.root().is_number_integer() << '\n';
    std::cout << d_unsigned.root().is_number_unsigned() << '\n';
    std::cout << d_float.root().is_number_float() << '\n';
    std::cout << d_string.root().is_string() << '\n';
    std::cout << d_array.root().is_array() << ' ' << d_array.root().is_structured() << '\n';
    std::cout << d_object.root().is_object() << ' ' << d_object.root().is_primitive() << '\n';

    // JSON text can never produce a binary value: is_binary() is always false
    std::cout << d_array.root().is_binary() << '\n';

    // a default-constructed view, and the root of a document that failed to
    // parse without exceptions, are both discarded
    nlohmann::json_view invalid;
    json_document failed = json_document::parse("not json", /* allow_exceptions */ false);
    std::cout << invalid.is_discarded() << '\n';
    std::cout << failed.root().is_discarded() << '\n';

    // type() returns the same value_t enumeration as basic_json::type()
    std::cout << (d_object.root().type() == nlohmann::json::value_t::object) << '\n';
}
```

Output:

```
true
true
true true
true
true
true
true true
true false
false
true
true
true
```

## See also

- [`operator[]`](https://json.nlohmann.me/api/basic_json_view/operator%5B%5D/index.md) - access specified element; yields a discarded view where an element is missing
- [`(constructor)`](https://json.nlohmann.me/api/basic_json_view/basic_json_view/index.md) - the default constructor creates a discarded view
- [`basic_json_document::is_discarded`](https://json.nlohmann.me/api/basic_json_document/is_discarded/index.md) - return whether the last parse failed
- [`BasicJsonType::is_discarded`](https://json.nlohmann.me/api/basic_json/is_discarded/index.md) - the corresponding function of `basic_json`
- [Zero-copy JSON views](https://json.nlohmann.me/features/json_view/#what-is-different) - how views differ from basic_json

## Version history

- Added in version 3.13.0 unreleased.
