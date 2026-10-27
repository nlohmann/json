# nlohmann::basic_json_view::operator[]

```
// (1)
basic_json_view operator[](string_view_t key) const;
basic_json_view operator[](const char* key) const;
basic_json_view operator[](const string_t& key) const;

// (2)
basic_json_view operator[](size_type idx) const;
template<typename IntegerType>
basic_json_view operator[](IntegerType idx) const;

// (3)
basic_json_view operator[](const json_pointer& ptr) const;
```

1. Returns the value of the object member with key `key` — the first one, should the key occur more than once (see the [Notes](#notes) below) — or a [discarded](https://json.nlohmann.me/api/basic_json_view/is_discarded/index.md) view if there is no such member.
1. Returns the array element at index `idx`, or a [discarded](https://json.nlohmann.me/api/basic_json_view/is_discarded/index.md) view if `idx` is out of range. The template accepts every integer type except `bool` and `std::size_t` (`int`, `unsigned`, `long`, `std::int64_t`, ...) and forwards to the `size_type` overload, so that an integer argument is not ambiguous between that overload and 1; a negative `idx` is out of range.
1. Returns the value a JSON pointer `ptr` refers to, starting at this value, or a [discarded](https://json.nlohmann.me/api/basic_json_view/is_discarded/index.md) view wherever resolving it further is not possible without inserting into or extending the document (see [Return value](#return-value) and [Exceptions](#exceptions) below).

## Parameters

`key` (in) : object key of the element to access

`idx` (in) : index of the element to access

`ptr` (in) : JSON pointer to the element to access

## Return value

1. the value of the first member with key `key`, or a discarded view if no member has this key (or if this view is [discarded](https://json.nlohmann.me/api/basic_json_view/is_discarded/index.md))
1. the element at index `idx`, or a discarded view if `idx >= size()` or `idx` is negative (or if this view is [discarded](https://json.nlohmann.me/api/basic_json_view/is_discarded/index.md))
1. the value `ptr` resolves to, starting at this value, or a discarded view (also if this view is [discarded](https://json.nlohmann.me/api/basic_json_view/is_discarded/index.md)) for exactly the reference tokens where the **const** overload of [`BasicJsonType::operator[]`](https://json.nlohmann.me/api/basic_json/operator%5B%5D/index.md) invokes undefined behavior for the same pointer and the same document: an object member that does not exist, or an array index that is out of range

## Exception safety

Strong guarantee: there are no changes to the view or the document it refers to.

## Exceptions

1. Throws [`type_error.305`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error305) if the value is not an object and not [discarded](https://json.nlohmann.me/api/basic_json_view/is_discarded/index.md) — the same exception, with the same message, that the **const** overload of [`BasicJsonType::operator[]`](https://json.nlohmann.me/api/basic_json/operator%5B%5D/index.md) throws for a string argument on a non-object value.
1. Throws [`type_error.305`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error305) if the value is not an array and not [discarded](https://json.nlohmann.me/api/basic_json_view/is_discarded/index.md) — the same exception, with the same message, that the **const** overload of [`BasicJsonType::operator[]`](https://json.nlohmann.me/api/basic_json/operator%5B%5D/index.md) throws for a numeric argument on a non-array value.
1. Throws the same exceptions, with the same messages, that the **const** overload of [`BasicJsonType::operator[]`](https://json.nlohmann.me/api/basic_json/operator%5B%5D/index.md) throws for the same pointer and the same document:
   - [`out_of_range.402`](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range402) if a reference token is `"-"` at an array.
   - [`out_of_range.404`](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range404) if a reference token cannot be resolved because it is used on a primitive value.
   - [`parse_error.106`](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error106) if an array index in `ptr` begins with `'0'`.
   - [`parse_error.109`](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error109) if an array index in `ptr` is not a number.

None of these exceptions carry a [`JSON_DIAGNOSTICS`](https://json.nlohmann.me/api/macros/json_diagnostics/index.md) path: the view has no `BasicJsonType` value to point at, so the exception is created without one, even if `BasicJsonType` was built with `JSON_DIAGNOSTICS` enabled.

## Complexity

1. Linear in the number of members: as for [`ordered_json`](https://json.nlohmann.me/api/ordered_json/index.md), members are compared one after another, in document order, stopping at the first match. Each comparison first checks the key's length — already known from the index, without reading the key bytes — before comparing its content, so a key of a different length than `key` is rejected without touching the source text. Objects with 128 or more members get a hash index of their keys while parsing, so that a lookup in them takes constant time on average.
1. Linear in `idx`: elements are skipped one at a time from the first one, since they are not a fixed size in the index (unlike `BasicJsonType`'s array, which is random-access). Constant if no element of the array is an array or object, since the elements are then adjacent in the index.
1. Linear in the number of reference tokens of `ptr` and, for each token, in the number of members of the object at that level (as 1.) or the index into the array (as 2.).

## Notes

Unlike `BasicJsonType::operator[]`, which is undefined behavior (guarded by a [runtime assertion](https://json.nlohmann.me/features/assertions/index.md)) for a missing key on a **const** value, this operator returns a safe, testable result for a missing key or an index out of range: a [discarded](https://json.nlohmann.me/api/basic_json_view/is_discarded/index.md) view, which is tested with [`is_discarded`](https://json.nlohmann.me/api/basic_json_view/is_discarded/index.md). There is also no non-const overload that inserts a missing key or extends an array — a view never modifies the document.

Chained access

`operator[]` on a [discarded](https://json.nlohmann.me/api/basic_json_view/is_discarded/index.md) view returns a discarded view and does not throw, so a chain like `v["a"]["b"][0]` is safe even if `"a"` or `"b"` is missing: the first missing step makes the whole result discarded, which is tested once at the end. Type errors on values that are *not* discarded still throw: a key on an array or a primitive, or an index on an object or a primitive, is `type_error.305` as for `BasicJsonType`. [`at`](https://json.nlohmann.me/api/basic_json_view/at/index.md) still throws for a discarded view, as it does for a missing key.

Duplicate keys: the first member wins

If the source text has an object with a duplicate key, `operator[]` (and [`at`](https://json.nlohmann.me/api/basic_json_view/at/index.md), [`find`](https://json.nlohmann.me/api/basic_json_view/find/index.md), [`contains`](https://json.nlohmann.me/api/basic_json_view/contains/index.md), [`value`](https://json.nlohmann.me/api/basic_json_view/value/index.md), and JSON pointer resolution) all resolve to the *first* member with that key, because a lookup can stop as soon as it finds a match. This is different from [`materialize()`](https://json.nlohmann.me/api/basic_json_view/materialize/index.md) (and [`BasicJsonType::parse()`](https://json.nlohmann.me/api/basic_json/parse/index.md)), which replay every member in order and so keep the *last* value for a repeated key, so `v["a"]` and `v.materialize()["a"]` can differ. To get the value `parse()` would give, use [`materialize()`](https://json.nlohmann.me/api/basic_json_view/materialize/index.md) or iterate the members with [`items()`](https://json.nlohmann.me/api/basic_json_view/items/index.md) and keep the last match. The key hash index of a larger object (128 members or more) leads to the first member of a key as well. [`begin()`](https://json.nlohmann.me/api/basic_json_view/begin/index.md)/[`end()`](https://json.nlohmann.me/api/basic_json_view/end/index.md) and [`items()`](https://json.nlohmann.me/api/basic_json_view/items/index.md) iterate over *all* members, including duplicates, in document order. See [Duplicate keys](https://json.nlohmann.me/features/json_view/#duplicate-keys) and [`size()`](https://json.nlohmann.me/api/basic_json_view/size/#notes).

JSON pointer resolution

Overload 3 walks `ptr` one reference token at a time, starting at this value, the same way [`at`](https://json.nlohmann.me/api/basic_json_view/at/index.md) and [`contains`](https://json.nlohmann.me/api/basic_json_view/contains/index.md) do. It only ever returns a discarded view where the **const** overload of `BasicJsonType::operator[]` would be undefined behavior for the same pointer — a missing object member or an out-of-range array index — and still throws for every other way `ptr` can fail to resolve. See [`at`](https://json.nlohmann.me/api/basic_json_view/at/#exceptions) for the checked version, which throws in every case instead, and [`contains`](https://json.nlohmann.me/api/basic_json_view/contains/index.md) for a version that never throws.

## Examples

Example: (1)/(2) access specified element

The example below reads a couple of fields out of a batch of user records without ever materializing a full `BasicJsonType` value for the batch. `operator[]` is used both to look up an optional object member and to index into an array — in both cases, a missing value comes back as a discarded view that can be tested with a plain `if`, instead of relying on undefined behavior.

```
#include <iostream>
#include <nlohmann/json_view.hpp>

using nlohmann::json_document;

int main()
{
    // two user records from a large API response; only the fields that are
    // actually read are ever touched, and no nlohmann::json tree is built
    // for the batch
    json_document batch = json_document::parse(R"(
      [
        {"name": "Alice", "email": "alice@example.com", "tags": ["admin", "ops"]},
        {"name": "Bob", "tags": []}
      ]
    )");

    const auto users = batch.root();
    for (std::size_t i = 0; i < users.size(); ++i)
    {
        const auto user = users[i];
        std::cout << user["name"].materialize().dump();

        // operator[] on a missing object key gives a discarded view -- test
        // it with is_discarded(). The const overload of json::operator[]
        // would instead be undefined behavior (guarded by an assertion) for
        // a missing key
        const auto email = user["email"];
        if (!email.is_discarded())
        {
            std::cout << " <" << email.materialize().dump() << ">";
        }

        // the same holds for an array index past the end: a discarded view,
        // not undefined behavior
        const auto first_tag = user["tags"][0];
        if (!first_tag.is_discarded())
        {
            std::cout << " #" << first_tag.materialize().dump();
        }

        std::cout << '\n';
    }
}
```

Output:

```
"Alice" <"alice@example.com"> #"admin"
"Bob"
```

Example: (3) access specified element via JSON pointer

The example below reaches straight into one deeply nested field of a large document with a single JSON pointer, without ever building a tree for the rest of it, and shows the discarded-view and throwing outcomes of a pointer that cannot be fully resolved.

```
#include <iostream>
#include <nlohmann/json_view.hpp>

using nlohmann::json_document;
using json_pointer = nlohmann::json::json_pointer;

int main()
{
    // a larger document; operator[] with a JSON pointer reaches straight to
    // one deeply nested field, without ever building a tree for the rest
    json_document doc = json_document::parse(R"(
      {
        "region": {
          "servers": [
            {"name": "eu-1", "metrics": {"cpu": 0.42}},
            {"name": "eu-2", "metrics": {"cpu": 0.71}}
          ]
        }
      }
    )");

    const auto root = doc.root();
    std::cout << root[json_pointer("/region/servers/1/metrics/cpu")].materialize().dump() << '\n';

    // a missing key or an out-of-range index along the path gives a
    // discarded view, exactly where const json::operator[] would be
    // undefined behavior for the same pointer
    const auto missing = root[json_pointer("/region/servers/5/metrics/cpu")];
    if (!missing.is_discarded())
    {
        std::cout << missing.materialize().dump() << '\n';
    }
    else
    {
        std::cout << "no such server\n";
    }

    // indexing into a primitive still throws, as basic_json::operator[]
    // does for the same pointer
    try
    {
        static_cast<void>(root[json_pointer("/region/servers/0/name/x")]);
    }
    catch (const nlohmann::json::out_of_range& e)
    {
        std::cout << e.what() << '\n';
    }
}
```

Output:

```
0.71
no such server
[json.exception.out_of_range.404] unresolved reference token 'x'
```

## See also

- [`at`](https://json.nlohmann.me/api/basic_json_view/at/index.md) - access specified element with bounds checking (throws instead of returning a discarded view)
- [`front`](https://json.nlohmann.me/api/basic_json_view/front/index.md), [`back`](https://json.nlohmann.me/api/basic_json_view/back/index.md) - access the first or last element
- [`find`](https://json.nlohmann.me/api/basic_json_view/find/index.md), [`contains`](https://json.nlohmann.me/api/basic_json_view/contains/index.md) - look up a member without throwing
- [`BasicJsonType::operator[]`](https://json.nlohmann.me/api/basic_json/operator%5B%5D/index.md) - the corresponding function of `basic_json`
- [`json_pointer`](https://json.nlohmann.me/api/json_pointer/index.md) - JSON pointer type used by overload 3

## Version history

- Added in version 3.13.0 unreleased.
