# nlohmann::basic_json_document::insert

```
template<typename I, typename V>
view_type insert(view_type array, I idx, V&& value);
```

Only an **editable** document (`view_mode::editable`, e.g. [`json_editable_document`](https://json.nlohmann.me/api/json_editable_document/index.md)) has `insert`; calling it on a read-only `basic_json_document` fails to compile (`static_assert`).

Inserts `value` into `array` as a new element before position `idx`, which must not be past the end (`idx <= array.size()`; `idx == array.size()` appends, like [`push_back`](https://json.nlohmann.me/api/basic_json_document/push_back/index.md)). Unlike [`push_back`](https://json.nlohmann.me/api/basic_json_document/push_back/index.md), a [null](https://json.nlohmann.me/api/basic_json_view/is_null/index.md) `array` does *not* first become an empty array: `array` must already be an array.

`value` is accepted three ways: a [`basic_json_view`](https://json.nlohmann.me/api/basic_json_view/index.md) of *any* document -- read-only or editable, and it does not have to be `array`'s own document -- which is copied so that nothing is shared with the source document afterward; a `BasicJsonType` value; or anything `BasicJsonType` can be constructed from (numbers, strings, `bool`, `nullptr`, containers, ...).

## Template parameters

`I` : an integral type other than `bool`, deduced (overloads taking a `bool` or a non-integral type for `idx` do not participate in overload resolution).

`V` : the type of `value`, deduced; see above for what is accepted.

## Parameters

`array` (in) : the array to insert into

`idx` (in) : the position to insert `value` before; a negative value throws (see [Exceptions](#exceptions))

`value` (in) : the value to insert

## Return value

a view of the new element, now holding `value`

## Exception safety

Basic exception safety: `value` is fully encoded -- including the checks below -- into storage owned by the document before anything already reachable from [`root()`](https://json.nlohmann.me/api/basic_json_document/root/index.md) is touched, so a failure while encoding `value` (an invalid argument, or `std::bad_alloc`) leaves the document completely unchanged, other than memory allocated for the encoding that is not reclaimed. A failure of a later allocation -- while `array` switches from its parsed layout to a growable block, or while that block grows, see [Notes](#notes) -- can still leave `array` already switched to that layout even though `value` itself was not inserted.

## Exceptions

Throws [`type_error.309`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error309) if `array` is not an array -- the same message [`BasicJsonType::insert`](https://json.nlohmann.me/api/basic_json/insert/index.md) throws for the same type; a null `array` throws this too (see above). Throws [`out_of_range.401`](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range401) if `idx` is negative, or if `idx > array.size()`. Throws [`invalid_iterator.202`](https://json.nlohmann.me/home/exceptions/#jsonexceptioninvalid_iterator202) ("view does not belong to this document") if `array` is a [discarded](https://json.nlohmann.me/api/basic_json_view/is_discarded/index.md) view or a view of a *different* document. Throws [`type_error.302`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error302) if `value` is a [discarded](https://json.nlohmann.me/api/basic_json_view/is_discarded/index.md) view or a [discarded](https://json.nlohmann.me/api/basic_json/is_discarded/index.md) `BasicJsonType` value, and [`type_error.319`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error319) if `value` is (or contains) a binary value -- `BasicJsonType` can hold one, but a `json_document` cannot. Throws [`type_error.316`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error316) if `value` is (or contains) a string that is not valid UTF-8, with the same message [`BasicJsonType::dump()`](https://json.nlohmann.me/api/basic_json/dump/index.md) gives for that string.

## Complexity

Linear in the number of elements of `array` at or after `idx` (they move one slot over), plus time linear in the size of `value` to encode it into the document's storage (constant for a scalar, linear in the number of nested values for an array or object): like [`push_back`](https://json.nlohmann.me/api/basic_json_document/push_back/index.md), the elements of `array` move to a growable block of links the first time it is inserted into (or [`set`](https://json.nlohmann.me/api/basic_json_document/set/index.md)/[`push_back`](https://json.nlohmann.me/api/basic_json_document/push_back/index.md) on), and that block grows in amortized constant time; inserting before the end within that block still shifts every later element.

## Notes

Like [`set`](https://json.nlohmann.me/api/basic_json_document/set/index.md) on a member or an element, `insert` never moves an existing *element's value* -- only where `array`'s *links* to its elements live -- so a view of an existing element of `array` stays valid across an `insert`, and keeps referring to the same element even though its index shifts. Any iterator already taken over `array` is invalidated, since it was walking the old layout. See [Edits](https://json.nlohmann.me/api/basic_json_document/#edits) for what stays valid across an edit in general.

## Examples

Example

The example below inserts a step into the middle of a deployment plan, without touching the steps that come after it, and shows that a view taken before the insert keeps referring to the same element even though its index shifts -- something a plain `json`/`ordered_json` array, or its `std::vector`-based storage, has no equivalent for.

```
#include <iostream>
#include <nlohmann/json_view.hpp>

using nlohmann::json;
using nlohmann::json_editable_document;
using nlohmann::json_editable_view;

int main()
{
    // a deployment plan -- "budget" is written with a trailing zero that has
    // no effect on its value
    const std::string text = R"({
  "release": "2026.09",
  "steps": ["build", "test", "deploy"],
  "budget": 19.90
})";

    json_editable_document doc = json_editable_document::parse(text);

    const std::size_t deploy_index = 2;
    const auto deploy = doc.root()["steps"][deploy_index];  // held across the insert

    doc.insert(doc.root()["steps"], deploy_index, "smoke-test"); // insert before "deploy"

    // the held view still refers to "deploy", even though its index moved
    // from 2 to 3, and nothing else in the document was touched
    std::cout << deploy.dump() << '\n';
    std::cout << doc.root().dump(2, ' ', false, json_editable_view::number_format::source) << "\n\n";

    // the same edit on a plain json value: an index held from before the
    // insert now refers to whatever moved into that slot, and dump()
    // rewrites "budget" to its shortest form even though it was never
    // touched
    json plain = json::parse(text);
    plain["steps"].insert(plain["steps"].begin() + static_cast<std::ptrdiff_t>(deploy_index), "smoke-test");
    std::cout << plain["steps"][deploy_index].dump() << '\n';
    std::cout << plain.dump(2) << '\n';
}
```

Output:

```
"deploy"
{
  "release": "2026.09",
  "steps": [
    "build",
    "test",
    "smoke-test",
    "deploy"
  ],
  "budget": 19.90
}

"smoke-test"
{
  "budget": 19.9,
  "release": "2026.09",
  "steps": [
    "build",
    "test",
    "smoke-test",
    "deploy"
  ]
}
```

## See also

- [push_back](https://json.nlohmann.me/api/basic_json_document/push_back/index.md) - append to an array
- [erase](https://json.nlohmann.me/api/basic_json_document/erase/index.md) - remove an object member, an array element, or the value a JSON pointer refers to
- [set](https://json.nlohmann.me/api/basic_json_document/set/index.md) - replace a value, or set an object member, an array element, or the value a JSON pointer refers to
- [`BasicJsonType::insert`](https://json.nlohmann.me/api/basic_json/insert/index.md) - the corresponding function of `basic_json`
- [Edits](https://json.nlohmann.me/api/basic_json_document/#edits) - what an edit guarantees, for every overload

## Version history

- Added in version 3.13.0 unreleased.
