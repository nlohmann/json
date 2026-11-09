# Editing a document

A [`json_document`](https://json.nlohmann.me/api/json_document/index.md)/[`json_view`](https://json.nlohmann.me/api/json_view/index.md) lets you look at a parsed text without copying it, but not change it. [`basic_json_document<BasicJsonType, view_mode::editable>`](https://json.nlohmann.me/api/basic_json_document/index.md) — more conveniently spelled [`json_editable_document`](https://json.nlohmann.me/api/json_editable_document/index.md) or [`ordered_json_editable_document`](https://json.nlohmann.me/api/ordered_json_editable_document/index.md) — also lets you [`set`](https://json.nlohmann.me/api/basic_json_document/set/index.md) a value, [`push_back`](https://json.nlohmann.me/api/basic_json_document/push_back/index.md) onto or [`insert`](https://json.nlohmann.me/api/basic_json_document/insert/index.md) into an array, and [`erase`](https://json.nlohmann.me/api/basic_json_document/erase/index.md) an object member or an array element, still without ever building a `basic_json` tree for parts you do not touch.

The [mode](https://json.nlohmann.me/api/view_mode/index.md) defaults to `view_mode::read_only`, so `json_document`/`ordered_json_document` are unaffected — they carry none of the bookkeeping edits need, and calling `set`/`push_back`/`insert`/`erase` on one is a compile error, not a runtime one.

## Why: editing without reformatting

A price like `19.90` is exactly the kind of value that makes editing a `json` or `ordered_json` value in place lossy. Say you parse a configuration file, patch one field, and write it back:

- **`json`** re-sorts every key on the way in (`object_t` is a `std::map`) and rewrites every number to its shortest round-trip form on the way out — a one-field patch turns into a diff that reorders the whole file and rewrites `19.90` to `19.9`.
- **`ordered_json`** keeps the key order, but still rewrites every number the same way: parsing has already reduced it to a `double`/`int64_t`, and there is no way back to how it was spelled in the source text.

The patch of the example below (set `"host"`, add `"retries"`) written back by each of them:

`json`

keys sorted, numbers rewritten

```
{"host":"db2",
 "name":"cache",
 "port":6379,
 "price":19.9,
 "retries":3}
```

`ordered_json`

key order kept, numbers rewritten

```
{"name":"cache",
 "host":"db2",
 "port":6379,
 "price":19.9,
 "retries":3}
```

`json_editable_document`

order and spelling kept

```
{"name":"cache",
 "host":"db2",
 "port":6379,
 "price":19.90,
 "retries":3}
```

An editable document keeps both. [`dump()`](https://json.nlohmann.me/api/basic_json_view/dump/index.md) of an edited document writes members in document order — a member [`set`](https://json.nlohmann.me/api/basic_json_document/set/index.md) added goes at the end, exactly where it was inserted, and an [`erase`](https://json.nlohmann.me/api/basic_json_document/erase/index.md)d member simply leaves a gap: everything around it keeps its place — and [`number_format::source`](https://json.nlohmann.me/api/basic_json_view/number_format/index.md) keeps the exact spelling of every number an edit did not itself touch; a number an edit *did* touch is written the way [`BasicJsonType::dump()`](https://json.nlohmann.me/api/basic_json/dump/index.md) would write it, since there is no source spelling for a brand new value. See [Writing a view back](https://json.nlohmann.me/features/json_view/reading/#writing-a-view-back).

Example: patch a configuration, keeping member order and number spellings

```
#include <iostream>
#include <nlohmann/json_view.hpp>

using nlohmann::json;
using nlohmann::json_editable_document;
using nlohmann::json_editable_view;

int main()
{
    // a configuration file, as it might be read from disk
    const std::string text = R"({"name": "cache", "host": "db1", "port": 6379, "price": 19.90})";
    std::cout << text << "\n\n";

    // patch two fields -- "price" is never touched
    json_editable_document doc = json_editable_document::parse(text);
    doc.set(doc.root(), "host", "db2");
    doc.set(doc.root(), "retries", 3);

    // member order (the new member at the end) and the untouched number's
    // exact spelling survive
    std::cout << doc.root().dump(-1, ' ', false, json_editable_view::number_format::source) << '\n';

    // the same patch on a plain json value: keys are sorted (object_t is a
    // std::map), and "price" is rewritten even though the patch never
    // touched it
    json plain = json::parse(text);
    plain["host"] = "db2";
    plain["retries"] = 3;
    std::cout << plain.dump() << '\n';
}
```

Output:

```
{"name": "cache", "host": "db1", "port": 6379, "price": 19.90}

{"name":"cache","host":"db2","port":6379,"price":19.90,"retries":3}
{"host":"db2","name":"cache","port":6379,"price":19.9,"retries":3}
```

## What stays valid, and what an edit costs

The source text itself is **never written**, and the parsed index never moves — a value keeps the node it was parsed into for as long as it is not itself replaced. So every [view](https://json.nlohmann.me/api/basic_json_view/index.md) taken before an edit, including a previously obtained [`root()`](https://json.nlohmann.me/api/basic_json_document/root/index.md), stays valid and, if it still refers to the edited value, sees the edit; a view of a value a later edit drops or replaces just keeps showing what it last held. New values go to storage the document allocates and owns on demand. The one thing an edit does invalidate is the **iterators** taken over an edited array or object: the first time an element is added to it, inserted into it, erased from it, or replaced by a value that spans a different number of nodes, its elements move from the parsed, fixed layout to a growable block of links so that [`push_back`](https://json.nlohmann.me/api/basic_json_document/push_back/index.md) can later grow it in amortized constant time — existing elements are not touched, but an iterator that was walking the old layout no longer matches. A string obtained with [`get_string()`](https://json.nlohmann.me/api/basic_json_view/get_string/index.md) is unaffected either way and stays valid across further edits. See [`basic_json_document`'s Edits](https://json.nlohmann.me/api/basic_json_document/#edits) for the details, and [`set`'s Exception safety](https://json.nlohmann.me/api/basic_json_document/set/#exception-safety) for what an edit guarantees if it throws (the *basic* guarantee, not the strong one `dump()` and the read-only functions provide). How edits are kept in the index is described in the [architecture overview](https://json.nlohmann.me/home/architecture/#node-index-of-json-views).

Step through the edits of a small document (the node fields follow the [architecture overview](https://json.nlohmann.me/home/architecture/#node-index-of-json-views)):

Step 1 of 5. After parsing: nine nodes in the parsed index, no owned storage yet.

Step 2 of 5. `doc.set(doc.root(), "port", 6380)` overwrites the node of the integer in place; no member is added or removed, so the object keeps its parsed layout.

Step 3 of 5. `doc.erase(doc.root()["tags"], 0)`: the array is edited for the first time, so its elements move to a block of links in owned storage. The node of `"eu"` stays in the index, but nothing refers to it any more; iterators over the array taken before are invalid.

Step 4 of 5. `doc.push_back(doc.root()["tags"], "new")`: the new string gets its own node, its text goes to the buffer of edited text, and a link to it is appended to the block of the array.

Step 5 of 5. `doc.set(doc.root(), "retries", 3)`: a new member, so the object moves to a block too: copies of its keys, links to the values it already had, then the new key and a link to the new integer.

The node index and the owned storage of the document after each of five edits. Use *Back*, *Next*, or the numbered buttons to switch between the steps; without JavaScript all steps are shown one below the other.

## See also

- [Zero-copy JSON views](https://json.nlohmann.me/features/json_view/index.md) - overview
- [`json_editable_document`](https://json.nlohmann.me/api/json_editable_document/index.md) - and [`ordered_json_editable_document`](https://json.nlohmann.me/api/ordered_json_editable_document/index.md) - the documents that can be edited in place
- [`basic_json_document`'s Edits](https://json.nlohmann.me/api/basic_json_document/#edits) - the rules of edits in detail
- [Differences from `basic_json`](https://json.nlohmann.me/features/json_view/differences/#exception-context) - source positions after edits

## Version history

- Added in version 3.13.0 unreleased.
