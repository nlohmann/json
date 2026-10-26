# nlohmann::basic_json_view::at

```
// (1)
basic_json_view at(string_view_t key) const;
basic_json_view at(const char* key) const;
basic_json_view at(const string_t& key) const;

// (2)
basic_json_view at(size_type idx) const;
template<typename IntegerType>
basic_json_view at(IntegerType idx) const;

// (3)
basic_json_view at(const json_pointer& ptr) const;
```

1. Returns the value of the object member with key `key` -- the first one, should the key occur more than once (see [Notes on duplicate keys](https://json.nlohmann.me/api/basic_json_view/operator%5B%5D/#notes)).
1. Returns the array element at index `idx`. The template accepts every integer type except `bool` and `std::size_t` and forwards to the `size_type` overload, as for [`operator[]`](https://json.nlohmann.me/api/basic_json_view/operator%5B%5D/index.md); a negative `idx` is out of range.
1. Returns the value a JSON pointer `ptr` refers to, starting at this value.

## Parameters

`key` (in) : object key of the element to access

`idx` (in) : index of the element to access

`ptr` (in) : JSON pointer to the element to access

## Return value

1. the value of the first member with key `key`
1. the element at index `idx`
1. the value `ptr` resolves to, starting at this value

## Exception safety

Strong guarantee: there are no changes to the view or the document it refers to.

## Exceptions

1. The function can throw the following exceptions, both with the same message as the corresponding call to [`BasicJsonType::at`](https://json.nlohmann.me/api/basic_json/at/index.md):
   - Throws [`type_error.304`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error304) if the value is not an object.
   - Throws [`out_of_range.403`](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range403) if no member has key `key`.
1. The function can throw the following exceptions, both with the same message as the corresponding call to [`BasicJsonType::at`](https://json.nlohmann.me/api/basic_json/at/index.md):
   - Throws [`type_error.304`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error304) if the value is not an array.
   - Throws [`out_of_range.401`](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range401) if `idx >= size()`.
1. The function can throw the following exceptions, all with the same message as the corresponding call to [`BasicJsonType::at`](https://json.nlohmann.me/api/basic_json/at/index.md):
   - Throws [`parse_error.106`](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error106) if an array index in `ptr` begins with `'0'`.
   - Throws [`parse_error.109`](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error109) if an array index in `ptr` is not a number.
   - Throws [`out_of_range.401`](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range401) if an array index in `ptr` is out of range.
   - Throws [`out_of_range.402`](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range402) if a reference token is `"-"` at an array -- `at` never inserts an element, so `"-"` is always invalid.
   - Throws [`out_of_range.403`](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range403) if a reference token names an object member that does not exist.
   - Throws [`out_of_range.404`](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range404) if `ptr` cannot be resolved because a reference token is used on a primitive value.

None of these exceptions carry a [`JSON_DIAGNOSTICS`](https://json.nlohmann.me/api/macros/json_diagnostics/index.md) path: the view has no `BasicJsonType` value to point at, so the exception is created without one, even if `BasicJsonType` was built with `JSON_DIAGNOSTICS` enabled.

## Complexity

1. Linear in the number of members: as for [`ordered_json`](https://json.nlohmann.me/api/ordered_json/index.md), members are compared one after another, in document order, stopping at the first match. Each comparison first checks the key's length -- already known from the index, without reading the key bytes -- before comparing its content. Objects with 128 or more members get a hash index of their keys while parsing, so that a lookup in them takes constant time on average.
1. Linear in `idx`: elements are skipped one at a time from the first one, since they are not a fixed size in the index (unlike `BasicJsonType`'s array, which is random-access). Constant if no element of the array is an array or object, since the elements are then adjacent in the index.
1. Linear in the number of reference tokens of `ptr` and, for each token, in the number of members of the object at that level (as 1.) or the index into the array (as 2.).

## Notes

Duplicate keys: the first member wins

If the source text repeats a key, this resolves to the *first* member with it, not to the last one that [`materialize()`](https://json.nlohmann.me/api/basic_json_view/materialize/index.md) and `parse()` keep. See the [Notes on duplicate keys](https://json.nlohmann.me/api/basic_json_view/operator%5B%5D/#notes) of `operator[]` and [Duplicate keys](https://json.nlohmann.me/features/json_view/#duplicate-keys) for the reasons and for how to get the last value.

Unlike [`operator[]`](https://json.nlohmann.me/api/basic_json_view/operator%5B%5D/index.md), which returns a [discarded](https://json.nlohmann.me/api/basic_json_view/is_discarded/index.md) view for a missing key or an out-of-range index, `at` always throws -- exactly as `BasicJsonType::at` does, and with the same messages, so existing error handling written against `BasicJsonType::at` keeps working unchanged when switched to a view. This also holds for overload 3: unlike [`operator[]`](https://json.nlohmann.me/api/basic_json_view/operator%5B%5D/index.md) with a JSON pointer, which returns a discarded view for a missing key or an out-of-range index, `at` throws for those too (`out_of_range.403`/`out_of_range.401`).

## Examples

Example: (1)/(2) access specified element with bounds checking

The example below reads required fields out of a service configuration with `at`, and shows that the exceptions it throws -- for a wrong type and for a missing key -- carry the same messages [`BasicJsonType::at`](https://json.nlohmann.me/api/basic_json/at/index.md) would produce for the same JSON text.

```
#include <iostream>
#include <nlohmann/json_view.hpp>

using nlohmann::json_document;
using nlohmann::json_view;

int main()
{
    // required fields of a service configuration -- at() reports a missing
    // or wrong-typed field with the very same exception basic_json::at()
    // would throw for the equivalent nlohmann::json value, so error
    // handling written against basic_json::at() keeps working unchanged
    json_document config = json_document::parse(R"({"name": "cache", "port": "6379"})");
    const json_view service = config.root();

    std::cout << service.at("port").materialize().dump() << '\n';

    try
    {
        // "port" is a string, not an array
        static_cast<void>(service.at("port").at(0));
    }
    catch (const nlohmann::json::type_error& e)
    {
        std::cout << e.what() << '\n';
    }

    try
    {
        static_cast<void>(service.at("timeout"));
    }
    catch (const nlohmann::json::out_of_range& e)
    {
        std::cout << e.what() << '\n';
    }
}
```

Output:

```
"6379"
[json.exception.type_error.304] cannot use at() with string
[json.exception.out_of_range.403] key 'timeout' not found
```

Example: (3) access specified element via JSON pointer with bounds checking

The example below shows that `at` with a JSON pointer throws exactly the exceptions, with exactly the messages, that [`BasicJsonType::at`](https://json.nlohmann.me/api/basic_json/at/index.md) throws for the same pointer and the same document.

```
#include <iostream>
#include <nlohmann/json_view.hpp>

using nlohmann::json_document;
using json_pointer = nlohmann::json::json_pointer;

int main()
{
    json_document doc = json_document::parse(R"({"region": "eu", "servers": ["eu-1", "eu-2"]})");
    const auto root = doc.root();

    std::cout << root.at(json_pointer("/servers/1")).materialize().dump() << '\n';

    // at() throws for every resolution failure -- with the very same
    // message json::at(ptr) would throw for the same pointer and the same
    // document
    try
    {
        static_cast<void>(root.at(json_pointer("/servers/5")));
    }
    catch (const nlohmann::json::out_of_range& e)
    {
        std::cout << e.what() << '\n';
    }

    try
    {
        static_cast<void>(root.at(json_pointer("/missing")));
    }
    catch (const nlohmann::json::out_of_range& e)
    {
        std::cout << e.what() << '\n';
    }
}
```

Output:

```
"eu-2"
[json.exception.out_of_range.401] array index 5 is out of range
[json.exception.out_of_range.403] key 'missing' not found
```

## See also

- [operator[]](https://json.nlohmann.me/api/basic_json_view/operator%5B%5D/index.md) - access specified element (returns a discarded view instead of throwing)
- [front](https://json.nlohmann.me/api/basic_json_view/front/index.md), [back](https://json.nlohmann.me/api/basic_json_view/back/index.md) - access the first or last element
- [`BasicJsonType::at`](https://json.nlohmann.me/api/basic_json/at/index.md) - the corresponding function of `basic_json`
- [`json_pointer`](https://json.nlohmann.me/api/json_pointer/index.md) - JSON pointer type used by overload 3

## Version history

- Added in version 3.13.0 unreleased.
