# nlohmann::basic_json_view::operator!=

```
// (1)
bool operator!=(const basic_json_view& lhs, const basic_json_view& rhs);

// (2)
bool operator!=(const basic_json_view& lhs, const BasicJsonType& rhs);
bool operator!=(const BasicJsonType& lhs, const basic_json_view& rhs);
```

1. Compares two views for inequality. Returns `!(lhs == rhs)`, see [operator==](https://json.nlohmann.me/api/basic_json_view/operator_eq/index.md).
1. Compares a view and a `BasicJsonType` value for inequality, in either order. Returns `!(lhs == rhs)` (or, for the reversed order, `!(rhs == lhs)`), see [operator==](https://json.nlohmann.me/api/basic_json_view/operator_eq/index.md).

Since `operator!=` is defined as the negation of [`operator==`](https://json.nlohmann.me/api/basic_json_view/operator_eq/index.md), it follows the same rules for special cases: for instance, since a [discarded](https://json.nlohmann.me/api/basic_json_view/is_discarded/index.md) view is never equal to anything by default (see [operator=='s Notes](https://json.nlohmann.me/api/basic_json_view/operator_eq/#notes)), it is never *unequal* to anything either -- `discarded != discarded` is also `false`, exactly as for a discarded `BasicJsonType` value.

## Parameters

`lhs` (in) : first value to consider

`rhs` (in) : second value to consider

## Return value

whether the values `lhs` and `rhs` are not equal

## Exception safety

Strong exception safety: if an exception is thrown, there are no changes to either operand, or to the document(s) a view refers to.

## Exceptions

May throw `std::bad_alloc`, propagated from [`operator==`](https://json.nlohmann.me/api/basic_json_view/operator_eq/#exceptions). Unlike most other `basic_json_view` functions, `operator!=` is not `noexcept`.

## Complexity

Linear, as [`operator==`](https://json.nlohmann.me/api/basic_json_view/operator_eq/#complexity).

## Notes

See the [Notes](https://json.nlohmann.me/api/basic_json_view/operator_eq/#notes) of `operator==` -- in particular for how an object's members are compared (order matters for [`ordered_json_view`](https://json.nlohmann.me/api/ordered_json_view/index.md) but not for [`json_view`](https://json.nlohmann.me/api/json_view/index.md)) and for how discarded views compare.

No ordering comparison (`operator<`) is provided for `basic_json_view`; [`materialize()`](https://json.nlohmann.me/api/basic_json_view/materialize/index.md) is the way to get a `BasicJsonType` value that supports it.

## Examples

Example

The example below asserts, as a test would, that a received document differs from an unwanted value, and shows that -- as for [`json`](https://json.nlohmann.me/api/json/index.md)/[`ordered_json`](https://json.nlohmann.me/api/ordered_json/index.md) -- reordering an object's members is detected as a difference for an `ordered_json_view` but not for a `json_view`.

```
#include <iostream>
#include <nlohmann/json_view.hpp>

using nlohmann::json_document;
using nlohmann::ordered_json_document;
using nlohmann::json;

int main()
{
    // assert, as a test would, that a received document differs from an
    // unwanted shape -- without ever materializing it into a json value just
    // to compare
    const json_document received = json_document::parse(
                                       R"({"status": "ok", "code": 200})");
    const json unwanted = {{"status", "error"}, {"code", 500}};
    std::cout << std::boolalpha << (received.root() != unwanted) << '\n';

    // json (std::map) compares object members regardless of order ...
    const json_document a = json_document::parse(R"({"a": 1, "b": 2})");
    const json_document b = json_document::parse(R"({"b": 2, "a": 1})");
    std::cout << (a.root() != b.root()) << '\n';

    // ... but ordered_json (ordered_map) compares them in the order they
    // appear, so the very same reordering is detected as a difference
    const ordered_json_document oa = ordered_json_document::parse(R"({"a": 1, "b": 2})");
    const ordered_json_document ob = ordered_json_document::parse(R"({"b": 2, "a": 1})");
    std::cout << (oa.root() != ob.root()) << '\n';
}
```

Output:

```
true
false
true
```

## See also

- [operator==](https://json.nlohmann.me/api/basic_json_view/operator_eq/index.md) - compare for equality
- [materialize](https://json.nlohmann.me/api/basic_json_view/materialize/index.md) - build a `BasicJsonType` value, e.g. to keep comparing after the document is gone
- [`BasicJsonType::operator!=`](https://json.nlohmann.me/api/basic_json/operator_ne/index.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0 unreleased.
