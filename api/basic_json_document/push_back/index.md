# nlohmann::basic_json_document::push_back

```
template<typename V>
view_type push_back(view_type array, V&& value);
```

Appends `value` as a new last element of `array`. A [null](https://json.nlohmann.me/api/basic_json_view/is_null/index.md) `array` first becomes an empty array, the same way [`set`](https://json.nlohmann.me/api/basic_json_document/set/index.md) turns a null `object` into an empty object.

`value` is accepted three ways: a [`basic_json_view`](https://json.nlohmann.me/api/basic_json_view/index.md) of *any* document -- read-only or editable, and it does not have to be `array`'s own document -- which is copied so that nothing is shared with the source document afterward; a `BasicJsonType` value; or anything `BasicJsonType` can be constructed from (numbers, strings, `bool`, `nullptr`, containers, ...).

Only an **editable** document (`Editable == true`, e.g. [`json_editable_document`](https://json.nlohmann.me/api/json_editable_document/index.md)) has `push_back`; calling it on a read-only `basic_json_document` fails to compile (`static_assert`).

## Template parameters

`V` : the type of `value`, deduced; see above for what is accepted.

## Parameters

`array` (in) : the array (or null value) to append to

`value` (in) : the value to append

## Return value

a view of the new last element of `array`, now holding `value`

## Exception safety

Basic exception safety: `value` is fully encoded -- including the checks below -- into storage owned by the document before anything already reachable from [`root()`](https://json.nlohmann.me/api/basic_json_document/root/index.md) is touched, so a failure while encoding `value` (an invalid argument, or `std::bad_alloc`) leaves the document completely unchanged, other than memory allocated for the encoding that is not reclaimed. A failure of a later allocation -- while `array` switches from its parsed layout to a growable block, or while that block grows, see [Notes](#notes) -- can still leave a partial effect, such as a null `array` argument already turned into an empty array even though `value` itself was not appended.

## Exceptions

Throws [`type_error.308`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error308) if `array` is neither an array nor null -- the same message [`BasicJsonType::push_back`](https://json.nlohmann.me/api/basic_json/push_back/index.md) throws for the same type. Throws [`invalid_iterator.202`](https://json.nlohmann.me/home/exceptions/#jsonexceptioninvalid_iterator202) ("view does not belong to this document") if `array` is a [discarded](https://json.nlohmann.me/api/basic_json_view/is_discarded/index.md) view or a view of a *different* document. Throws [`type_error.302`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error302) if `value` is a [discarded](https://json.nlohmann.me/api/basic_json_view/is_discarded/index.md) view or a [discarded](https://json.nlohmann.me/api/basic_json/is_discarded/index.md) `BasicJsonType` value, and [`type_error.319`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error319) if `value` is (or contains) a binary value -- `BasicJsonType` can hold one, but a `json_document` cannot. Throws [`type_error.316`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error316) if `value` is (or contains) a string that is not valid UTF-8, with the same message [`BasicJsonType::dump()`](https://json.nlohmann.me/api/basic_json/dump/index.md) gives for that string.

## Complexity

Amortized constant, plus time linear in the size of `value` to encode it into the document's storage (constant for a scalar, linear in the number of nested values for an array or object): the elements of `array` move to a growable block of links the first time it is appended to (or [`set`](https://json.nlohmann.me/api/basic_json_document/set/index.md) on), and that block itself grows -- doubling its capacity, so the cost of growing it amortizes to constant per element -- only once it runs out of room. See [Notes](#notes).

## Notes

Like [`set`](https://json.nlohmann.me/api/basic_json_document/set/index.md) on a member or an element, `push_back` never moves an existing element itself -- only where `array`'s *links* to its elements live -- so a view of an existing element of `array` stays valid across a `push_back`, but any iterator already taken over `array` is invalidated, since it was walking the old layout. See [Edits](https://json.nlohmann.me/api/basic_json_document/#edits) for what stays valid across an edit in general.

## Examples

Example

The example below appends records to an array one at a time, as they might arrive from a stream of events, without ever building a `BasicJsonType` value for the array or for the records already in it, and shows that a view taken from an earlier `push_back` still refers to the same element once later ones have run.

```
#include <iostream>
#include <nlohmann/json_view.hpp>

using json = nlohmann::json;
using json_editable_document = nlohmann::json_editable_document;

int main()
{
    // "events" starts out null -- the first push_back() turns it into an
    // array, exactly like set() turns a null object member into an object
    json_editable_document doc = json_editable_document::parse(R"({"source": "sensor-1", "events": null})");

    const auto first = doc.push_back(doc.root()["events"], json{{"type", "start"}, {"t", 0}});
    for (int t = 1; t <= 3; ++t)
    {
        doc.push_back(doc.root()["events"], json{{"type", "tick"}, {"t", t}});
    }

    // push_back() never moves an existing element: a view taken from an
    // earlier call still refers to the same element after later ones
    std::cout << first.dump() << '\n';
    std::cout << doc.root()["events"].size() << '\n';
    std::cout << doc.root().dump(2) << '\n';
}
```

Output:

```
{"t":0,"type":"start"}
4
{
  "source": "sensor-1",
  "events": [
    {
      "t": 0,
      "type": "start"
    },
    {
      "t": 1,
      "type": "tick"
    },
    {
      "t": 2,
      "type": "tick"
    },
    {
      "t": 3,
      "type": "tick"
    }
  ]
}
```

## See also

- [set](https://json.nlohmann.me/api/basic_json_document/set/index.md) - replace a value, or set an object member, an array element, or the value a JSON pointer refers to
- [insert](https://json.nlohmann.me/api/basic_json_document/insert/index.md) - insert an element into an array before a given position
- [erase](https://json.nlohmann.me/api/basic_json_document/erase/index.md) - remove an object member, an array element, or the value a JSON pointer refers to
- [root](https://json.nlohmann.me/api/basic_json_document/root/index.md) - the view of the root value
- [`BasicJsonType::push_back`](https://json.nlohmann.me/api/basic_json/push_back/index.md) - the corresponding function of `basic_json`
- [Edits](https://json.nlohmann.me/api/basic_json_document/#edits) - what an edit guarantees, for every overload

## Version history

- Added in version 3.13.0 unreleased.
