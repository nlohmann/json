# nlohmann::basic_json_view::contains

```
// (1)
bool contains(string_view_t key) const;
bool contains(const char* key) const;
bool contains(const string_t& key) const;

// (2)
bool contains(const json_pointer& ptr) const;
```

1. Checks whether the value is an object with a member with key `key`.
1. Checks whether a JSON pointer `ptr` can be resolved, starting at this value.

## Parameters

`key` (in) : key value to check its existence

`ptr` (in) : JSON pointer to check its existence

## Return value

1. `true` if the value is an object and has a member with key `key`, `false` otherwise
1. `true` if `ptr` can be resolved to a value starting at this view, `false` otherwise

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

1. Linear in the number of members: as for [`ordered_json`](https://json.nlohmann.me/api/ordered_json/index.md), members are compared one after another, in document order, stopping at the first match. Each comparison first checks the key's length -- already known from the index, without reading the key bytes -- before comparing its content. Objects with 128 or more members get a hash index of their keys while parsing, so that a lookup in them takes constant time on average.
1. Linear in the number of reference tokens of `ptr` and, for each token, in the number of members of the object at that level or the index into the array -- as for [`operator[]`](https://json.nlohmann.me/api/basic_json_view/operator%5B%5D/#complexity) and [`at`](https://json.nlohmann.me/api/basic_json_view/at/#complexity) with a JSON pointer.

## Notes

Duplicate keys: the first member wins

If the source text repeats a key, this resolves to the *first* member with it, not to the last one that [`materialize()`](https://json.nlohmann.me/api/basic_json_view/materialize/index.md) and `parse()` keep. See the [Notes on duplicate keys](https://json.nlohmann.me/api/basic_json_view/operator%5B%5D/#notes) of `operator[]` and [Duplicate keys](https://json.nlohmann.me/features/json_view/#duplicate-keys) for the reasons and for how to get the last value.

Overload 1 always returns `false` when the value is not an object -- including a [discarded](https://json.nlohmann.me/api/basic_json_view/is_discarded/index.md) view.

Postconditions

If `v.contains(key)` returns `true`, then `v[key]` is not [discarded](https://json.nlohmann.me/api/basic_json_view/is_discarded/index.md) and `v.at(key)` does not throw. If `v.contains(ptr)` returns `true`, then `v[ptr]` is not discarded and `v.at(ptr)` does not throw.

Overload 2 never throws

Unlike [`BasicJsonType::contains(const json_pointer&)`](https://json.nlohmann.me/api/basic_json/contains/index.md), which can throw for certain malformed pointers (for instance an empty array-index reference token), overload 2 never throws: a missing key, an out-of-range or malformed array index, a `"-"` index, or a reference token used on a primitive all simply make it return `false`.

## Examples

Example: (1) check with key

The example below counts how many of a batch of records carry an optional `retry_of` field, using `contains()` to check without ever materializing a single record of the batch.

```
#include <iostream>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;

int main()
{
    // count how many of many incoming records carry an optional "retry_of"
    // field -- contains() only walks the flat index, so scanning a large
    // batch like this never builds a single nlohmann::json value
    json_document batch = json_document::parse(R"(
      [
        {"id": 1},
        {"id": 2, "retry_of": 1},
        {"id": 3},
        {"id": 4, "retry_of": 3}
      ]
    )");

    const auto records = batch.root();
    std::size_t retries = 0;
    for (std::size_t i = 0; i < records.size(); ++i)
    {
        if (records[i].contains("retry_of"))
        {
            ++retries;
        }
    }
    std::cout << retries << " of " << records.size() << " records are retries\n";
}
```

Output:

```
2 of 4 records are retries
```

Example: (2) check with JSON pointer

The example below checks an optional, nested field with a JSON pointer, and shows two pointers that `contains()` resolves to `false` without throwing.

```
#include <iostream>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;
using json_pointer = nlohmann::json::json_pointer;

int main()
{
    // "retry_of" is only present on some records, nested a level down
    // inside "meta"
    json_document batch = json_document::parse(R"(
      [
        {"id": 1, "meta": {}},
        {"id": 2, "meta": {"retry_of": 1}}
      ]
    )");

    const auto records = batch.root();
    const json_pointer retry_of("/meta/retry_of");
    for (std::size_t i = 0; i < records.size(); ++i)
    {
        const auto record = records[i];
        if (record.contains(retry_of))
        {
            std::cout << "record " << i << " is a retry of " << record[retry_of].get<int>() << '\n';
        }
        else
        {
            std::cout << "record " << i << " is original\n";
        }
    }

    // contains() with a JSON pointer never throws -- not even for a
    // pointer that indexes into a primitive ("/0/id/x") or uses a
    // malformed array index ("/01"), either of which would need a
    // try/catch with json::contains(ptr)
    std::cout << std::boolalpha << records.contains(json_pointer("/0/id/x")) << '\n';
    std::cout << std::boolalpha << records.contains(json_pointer("/01")) << '\n';
}
```

Output:

```
record 0 is original
record 1 is a retry of 1
false
false
```

## See also

- [find](https://json.nlohmann.me/api/basic_json_view/find/index.md) - find a value in an object
- [count](https://json.nlohmann.me/api/basic_json_view/count/index.md) - returns the number of occurrences of a key
- [at](https://json.nlohmann.me/api/basic_json_view/at/index.md), [operator[]](https://json.nlohmann.me/api/basic_json_view/operator%5B%5D/index.md) - resolve a JSON pointer and throw, or return a discarded view
- [`BasicJsonType::contains`](https://json.nlohmann.me/api/basic_json/contains/index.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0 unreleased.
