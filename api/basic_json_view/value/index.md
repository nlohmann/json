# nlohmann::basic_json_view::value

```
// (1)
template<typename T>
T value(string_view_t key, const T& default_value) const;
string_t value(string_view_t key, const char* default_value) const;

// (2)
template<typename T>
T value(const json_pointer& ptr, const T& default_value) const;
string_t value(const json_pointer& ptr, const char* default_value) const;
```

1. Returns the value of the object member with key `key` -- the first one, should the key occur more than once (see [Notes on duplicate keys](https://json.nlohmann.me/api/basic_json_view/operator%5B%5D/#notes)) -- converted to `T`, or `default_value` if there is no such member.
1. Returns the value a JSON pointer `ptr` refers to, starting at this value, converted to `T`, or `default_value` if `ptr` cannot be resolved.

Both overloads have a dedicated `const char*` overload, so `v.value(key, "default")` (and the JSON pointer equivalent) deduce `string_t`, not `const char*`, for their return type and for the comparison used to pick between `key` and `default_value`.

## Template parameters

`T` : the type to convert the found value to; also the type of `default_value`

## Parameters

`key` (in) : object key of the element to access

`ptr` (in) : JSON pointer to the element to access

`default_value` (in) : the value to return if `key`/`ptr` resolves to no value

## Return value

1. the first member with key `key`, converted to `T`, or `default_value`
1. the value `ptr` resolves to, converted to `T`, or `default_value`

## Exception safety

Strong guarantee: there are no changes to the view or the document it refers to.

## Exceptions

1. Throws [`type_error.306`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error306) if the value is not an object -- the same exception, with the same message, that [`BasicJsonType::value`](https://json.nlohmann.me/api/basic_json/value/index.md) throws for the same call. If a member with key `key` is found, throws whatever converting it to `T` throws (typically [`type_error.302`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error302), with the same message [`BasicJsonType::value`](https://json.nlohmann.me/api/basic_json/value/index.md) throws for the same mismatch); a missing member never throws.
1. Throws [`type_error.306`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error306) if this value -- not the value `ptr` resolves to -- is neither an object nor an array. Throws [`parse_error.106`](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error106) or [`parse_error.109`](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error109) if `ptr` contains a malformed array index. If `ptr` resolves to a value, throws whatever converting it to `T` throws. Every other way `ptr` can fail to resolve -- a missing key, an out-of-range or "`-`" array index, an unresolvable token on a primitive -- yields `default_value` instead of throwing, exactly as [`BasicJsonType::value`](https://json.nlohmann.me/api/basic_json/value/index.md) catches `out_of_range` and returns `default_value`.

None of these exceptions carry a [`JSON_DIAGNOSTICS`](https://json.nlohmann.me/api/macros/json_diagnostics/index.md) path: the view has no `BasicJsonType` value to point at, so the exception is created without one, even if `BasicJsonType` was built with `JSON_DIAGNOSTICS` enabled.

## Complexity

1. Linear in the number of members: as for [`operator[]`](https://json.nlohmann.me/api/basic_json_view/operator%5B%5D/#complexity), members are compared one after another, in document order, stopping at the first match. Plus the complexity of converting the found member to `T` (see [`get`](https://json.nlohmann.me/api/basic_json_view/get/index.md)). Objects with 128 or more members get a hash index of their keys while parsing, so that a lookup in them takes constant time on average.
1. Linear in the number of reference tokens of `ptr` and, for each token, in the number of members of the object at that level or the index into the array -- as for the [`operator[]`](https://json.nlohmann.me/api/basic_json_view/operator%5B%5D/#complexity) and [`at`](https://json.nlohmann.me/api/basic_json_view/at/#complexity) overloads that take a JSON pointer. Plus the complexity of converting the resolved value to `T`.

## Notes

Duplicate keys: the first member wins

If the source text repeats a key, this resolves to the *first* member with it, not to the last one that [`materialize()`](https://json.nlohmann.me/api/basic_json_view/materialize/index.md) and `parse()` keep. See the [Notes on duplicate keys](https://json.nlohmann.me/api/basic_json_view/operator%5B%5D/#notes) of `operator[]` and [Duplicate keys](https://json.nlohmann.me/features/json_view/#duplicate-keys) for the reasons and for how to get the last value.

Differences to `at` and `operator[]`

Unlike [`at`](https://json.nlohmann.me/api/basic_json_view/at/index.md), this function does not throw if `key`/`ptr` resolves to no value. Unlike [`operator[]`](https://json.nlohmann.me/api/basic_json_view/operator%5B%5D/index.md), it never returns a [discarded](https://json.nlohmann.me/api/basic_json_view/is_discarded/index.md) view -- it always returns a `T` -- and it is available on any view, since it never needs to insert a missing element the way the non-const `BasicJsonType::operator[]` would.

Which values can be asked

As for [`BasicJsonType::value`](https://json.nlohmann.me/api/basic_json/value/index.md), the key overload (1) requires an object, and the JSON pointer overload (2) an object or an array.

## Examples

Example: (1) access specified object element with default value

The example below reads a couple of optional configuration fields with a default, so that a missing key never needs a `try`/`catch` of its own.

```
#include <iostream>
#include <nlohmann/json_view.hpp>
#include <string>

using json_document = nlohmann::json_document;
using json_view = nlohmann::json_view;

int main()
{
    json_document doc = json_document::parse(R"({"server": {"host": "localhost"}})");
    const json_view server = doc.root()["server"];

    // "port" is missing -- value() returns the default instead of
    // throwing, so optional configuration fields never need their own
    // try/catch
    std::cout << server.value("host", std::string("0.0.0.0")) << '\n';
    std::cout << server.value("port", 8080) << '\n';

    // a present but wrong-typed default still throws -- value() only
    // replaces "not found", not "wrong type", exactly as basic_json::value
    try
    {
        static_cast<void>(server.value("host", 0));
    }
    catch (const nlohmann::json::type_error& e)
    {
        std::cout << e.what() << '\n';
    }
}
```

Output:

```
localhost
8080
[json.exception.type_error.302] type must be number, but is string
```

Example: (2) access specified element via JSON pointer with default value

The example below reads an optional, nested configuration value with a default, given as a JSON pointer.

```
#include <iostream>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;
using json_view = nlohmann::json_view;
using json_pointer = nlohmann::json::json_pointer;

int main()
{
    json_document doc = json_document::parse(R"({"server": {"host": "localhost", "limits": {"connections": 100}}})");
    const json_view config = doc.root();

    // a nested, optional setting read with a default -- no exception, even
    // though "timeout" is missing several levels down
    std::cout << config.value(json_pointer("/server/limits/connections"), 10) << '\n';
    std::cout << config.value(json_pointer("/server/limits/timeout"), 30) << '\n';

    // an out-of-range array index also falls back to the default
    json_document list_doc = json_document::parse(R"({"servers": ["a", "b"]})");
    std::cout << list_doc.root().value(json_pointer("/servers/5"), std::string("none")) << '\n';
}
```

Output:

```
100
30
none
```

## See also

- [at](https://json.nlohmann.me/api/basic_json_view/at/index.md) - access specified element with bounds checking (throws instead of returning a default value)
- [operator[]](https://json.nlohmann.me/api/basic_json_view/operator%5B%5D/index.md) - access specified element (returns a discarded view instead of a default value)
- [`BasicJsonType::value`](https://json.nlohmann.me/api/basic_json/value/index.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0 unreleased.
