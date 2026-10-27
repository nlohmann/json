# nlohmann::basic_json_view::dump

```
string_t dump(const int indent = -1,
              const char indent_char = ' ',
              const bool ensure_ascii = false,
              const number_format numbers = number_format::shortest) const;
```

Serializes this value (and its subtree) directly from the flat index, without ever building a `BasicJsonType` value first. With the default `numbers == number_format::shortest`, the result is the same string [`BasicJsonType::dump`](https://json.nlohmann.me/api/basic_json/dump/index.md) would produce for the value [`BasicJsonType::parse()`](https://json.nlohmann.me/api/basic_json/parse/index.md) builds from the same source text, called with the same `indent`, `indent_char`, and `ensure_ascii` — except that members of an object appear in document order rather than sorted by key, and *every* occurrence of a repeated key is written rather than only the last one (see [Notes on duplicate keys](https://json.nlohmann.me/api/basic_json_view/operator%5B%5D/#notes)). For a `json_view` (whose `BasicJsonType` is not ordered), this means `dump()` can print an object's members in a different order than [`materialize()`](https://json.nlohmann.me/api/basic_json_view/materialize/index.md)`.dump()` of the same subtree.

## Parameters

`indent` (in) : If `indent` is nonnegative, array elements and object members are pretty-printed with that indent level. An indent level of `0` only inserts newlines. `-1` (the default) selects the most compact representation.

`indent_char` (in) : The character used for indentation if `indent` is greater than `0`. The default is (space).

`ensure_ascii` (in) : If `ensure_ascii` is `true`, all non-ASCII characters in the output are escaped with `\uXXXX` sequences, and the result consists of ASCII characters only.

`numbers` (in) : how to write numbers, see [`number_format`](https://json.nlohmann.me/api/basic_json_view/number_format/index.md): `shortest` (the default) writes them the way [`BasicJsonType::dump`](https://json.nlohmann.me/api/basic_json/dump/index.md) would; `source` copies every number exactly as it appears in the source text.

## Return value

string containing the serialization of this value, or `"<discarded>"` if the view is [discarded](https://json.nlohmann.me/api/basic_json_view/is_discarded/index.md).

## Exception safety

Strong exception safety: if an exception is thrown, there are no changes to the view or the document it refers to.

## Exceptions

May throw `std::bad_alloc` if allocating the output string fails. Unlike [`BasicJsonType::dump`](https://json.nlohmann.me/api/basic_json/dump/index.md), there is no `error_handler` parameter and no [`type_error.316`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error316): the view only ever holds text the parser already validated as UTF-8, so there is nothing to replace or ignore.

## Complexity

Linear in the size of the output text.

## Notes

The walk over the subtree is iterative, so the nesting depth it can write is limited by available memory only, not by the call stack — as for [`materialize()`](https://json.nlohmann.me/api/basic_json_view/materialize/index.md).

Strings are escaped by the same rules as [`BasicJsonType::dump`](https://json.nlohmann.me/api/basic_json/dump/index.md).

With `numbers == number_format::shortest`, floats are written with the library's shortest round-trip conversion, exactly as [`BasicJsonType::dump`](https://json.nlohmann.me/api/basic_json/dump/index.md) would (e.g. `1.5`, `100.0`, `1e+100`), and integers are copied from the source text — already canonical in JSON, so this matches their shortest form too — except that `-0` is written as `0`, the way [`BasicJsonType::parse()`](https://json.nlohmann.me/api/basic_json/parse/index.md) reads it.

`number_format::source` copies every number exactly as written in the source text instead, with no exception for `-0` — `1.50`, `1E2`, `-0.0`, `-0`, or all digits of an integer literal with more digits than any number type holds (such a literal is itself classified as a float, see [What is different](https://json.nlohmann.me/features/json_view/#what-is-different)) — something `BasicJsonType` cannot do, since parsing already reduces every number to its parsed value.

## Examples

Example

The example below forwards a single record out of a larger batch, and re-serializes a configuration file, both without ever building a `BasicJsonType` value for the surrounding array or for the parts of it that were not needed. It also shows that [`materialize()`](https://json.nlohmann.me/api/basic_json_view/materialize/index.md)`.dump()` of the configuration sorts its keys, where `dump()` on the view keeps the order they appear in the source text.

```
#include <iostream>
#include <nlohmann/json_view.hpp>

using nlohmann::json_document;
using nlohmann::json_view;

int main()
{
    // a large batch of sensor readings -- forward just the one that changed,
    // without ever building a basic_json value for the batch or for the
    // readings that are not needed
    const json_document batch = json_document::parse(R"(
      [{"id": 1, "temp": 21.5}, {"id": 2, "temp": 87.3}, {"id": 3, "temp": 21.7}]
    )");
    const json_view readings = batch.root();
    std::cout << readings[1].dump() << '\n';

    // a configuration file -- dump() on the view keeps the member order of
    // the source text; a json value's object_t is std::map, so
    // materialize().dump() of the very same view sorts the keys instead
    const json_document config = json_document::parse(
                                     R"({"name": "cache", "host": "db1", "port": 6379, "timeout": 30})");
    std::cout << config.root().dump(2) << "\n\n";
    std::cout << config.root().materialize().dump(2) << '\n';
}
```

Output:

```
{"id":2,"temp":87.3}
{
  "name": "cache",
  "host": "db1",
  "port": 6379,
  "timeout": 30
}

{
  "host": "db1",
  "name": "cache",
  "port": 6379,
  "timeout": 30
}
```

## See also

- [`number_format`](https://json.nlohmann.me/api/basic_json_view/number_format/index.md) - how `dump()` writes numbers
- [`operator<<`](https://json.nlohmann.me/api/basic_json_view/operator_ltlt/index.md) - serialize this value to a stream
- [`materialize`](https://json.nlohmann.me/api/basic_json_view/materialize/index.md) - build a `BasicJsonType` value, e.g. to use `BasicJsonType::dump`'s `error_handler`
- [`BasicJsonType::dump`](https://json.nlohmann.me/api/basic_json/dump/index.md) - the corresponding function of `basic_json`
- [Zero-copy JSON views](https://json.nlohmann.me/features/json_view/#writing-a-view-back) - writing a view back without building a tree

## Version history

- Added in version 3.13.0 unreleased.
