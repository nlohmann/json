# nlohmann::basic_json_view::operator==

```
// (1)
bool operator==(const basic_json_view& lhs, const basic_json_view& rhs);

// (2)
bool operator==(const basic_json_view& lhs, const BasicJsonType& rhs);
bool operator==(const BasicJsonType& lhs, const basic_json_view& rhs);
```

1. Compares two views for equality: whether the values [`BasicJsonType::parse()`](https://json.nlohmann.me/api/basic_json/parse/index.md) would produce for `lhs` and `rhs` are equal, according to `BasicJsonType`'s [`operator==`](https://json.nlohmann.me/api/basic_json/operator_eq/index.md).
1. Compares a view and a `BasicJsonType` value for equality, in either order: whether the value `parse()` would produce for the view and the other operand are equal, according to `BasicJsonType`'s [`operator==`](https://json.nlohmann.me/api/basic_json/operator_eq/index.md).

Neither overload builds a `BasicJsonType` value for a view to do the comparison (see [Notes](#notes) below). Numbers compare by value across their types (`1 == 1.0`), and an object compares by its members, with duplicate keys resolved exactly as `parse()` resolves them -- the last value, at the position of the first occurrence of the key. This is not what [`operator[]`](https://json.nlohmann.me/api/basic_json_view/operator%5B%5D/index.md) and the other lookups return for a duplicate key: they find the *first* member (see [Duplicate keys](https://json.nlohmann.me/features/json_view/#duplicate-keys)).

## Parameters

`lhs` (in) : first value to consider

`rhs` (in) : second value to consider

## Return value

whether the values `lhs` and `rhs` are equal

## Exception safety

Strong exception safety: if an exception is thrown, there are no changes to either operand, or to the document(s) a view refers to.

## Exceptions

May throw `std::bad_alloc`. Unlike the other comparison and most other `basic_json_view` functions, `operator==` is not `noexcept`: resolving an object's members needs a temporary array to sort them by key (see [Complexity](#complexity) below), and that allocation can fail.

## Complexity

Linear in the size of the compared values: every number, string, array element, and object member is visited at most once, and the walk is iterative, so the nesting depth it can compare is limited by available memory only, not by the call stack (as for [`materialize()`](https://json.nlohmann.me/api/basic_json_view/materialize/index.md)). Resolving an object's members takes an additional O(n log n) in the number of members at that level, since they are sorted by key to detect and resolve duplicates before being compared. Two arrays of different [`size()`](https://json.nlohmann.me/api/basic_json_view/size/index.md) are rejected without visiting either one's elements.

## Notes

Only a single number, boolean, or `null` value is ever materialized into a `BasicJsonType`, to reuse its `operator==` -- for numbers, so that values written differently in the source text but equal in value (e.g. an integer and a floating-point literal) still compare equal, following the same rules `BasicJsonType` does for special values such as `NaN`. Constructing one of these scalars never allocates. Strings are compared directly, without allocating, either from the source text on both sides or, for overload 2, against `BasicJsonType`'s own string. Arrays and objects are never materialized at all; only their elements or members are visited, one pair at a time.

How objects are compared

For a [`json_view`](https://json.nlohmann.me/api/json_view/index.md) (`BasicJsonType::object_t` is `std::map`), members are compared by key, regardless of the order they appear in the source text. For an [`ordered_json_view`](https://json.nlohmann.me/api/ordered_json_view/index.md) (`object_t` is `ordered_map`), they are compared in the order they occur, so the very same two objects with their members reordered can compare equal as `json_view`s but not as `ordered_json_view`s. This is exactly how [`json`](https://json.nlohmann.me/api/json/index.md) and [`ordered_json`](https://json.nlohmann.me/api/ordered_json/index.md) compare, see ["Comparing different `basic_json` specializations"](https://json.nlohmann.me/api/basic_json/operator_eq/#notes).

Discarded views

A [discarded](https://json.nlohmann.me/api/basic_json_view/is_discarded/index.md) view compares the same way a discarded `BasicJsonType` value does, which is governed by [`JSON_USE_LEGACY_DISCARDED_VALUE_COMPARISON`](https://json.nlohmann.me/api/macros/json_use_legacy_discarded_value_comparison/index.md): by default, a discarded view is never equal to anything, not even another discarded view.

No ordering comparison (`operator<`) is provided for `basic_json_view`; [`materialize()`](https://json.nlohmann.me/api/basic_json_view/materialize/index.md) is the way to get a `BasicJsonType` value that supports it.

## Examples

Example

The example below checks whether a newly received configuration differs from the previous one, and whether a received document matches what a test expects -- directly on views, without ever materializing a `BasicJsonType` value for either side.

```
#include <iostream>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;
using json = nlohmann::json;

int main()
{
    // two snapshots of a polled configuration endpoint -- compare them
    // directly as views, without ever building a nlohmann::json value for
    // either one
    const json_document previous = json_document::parse(
                                       R"({"name": "cache", "port": 6379, "timeout": 30})");
    const json_document current = json_document::parse(
                                      R"({"port": 6379.0, "timeout": 30, "name": "cache"})");

    // same members, reordered, and 6379 written as a float -- operator==
    // treats them the same way BasicJsonType::operator== would
    std::cout << std::boolalpha << (previous.root() == current.root()) << '\n';

    // an actually changed value is detected the same way
    const json_document changed = json_document::parse(
                                      R"({"name": "cache", "port": 6380, "timeout": 30})");
    std::cout << (previous.root() == changed.root()) << '\n';

    // comparing a view directly against an expected json value -- handy in a
    // test, without materializing the received document at all
    const json expected = {{"name", "cache"}, {"port", 6379}, {"timeout", 30}};
    std::cout << (previous.root() == expected) << '\n';
}
```

Output:

```
true
false
true
```

## See also

- [operator!=](https://json.nlohmann.me/api/basic_json_view/operator_ne/index.md) - compare for inequality
- [materialize](https://json.nlohmann.me/api/basic_json_view/materialize/index.md) - build a `BasicJsonType` value, e.g. to keep comparing after the document is gone
- [`BasicJsonType::operator==`](https://json.nlohmann.me/api/basic_json/operator_eq/index.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0 unreleased.
