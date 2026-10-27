# nlohmann::basic_json_view::operator\<<

```
std::ostream& operator<<(std::ostream& o, const basic_json_view& v);
```

Not available when [`JSON_NO_IO`](https://json.nlohmann.me/api/macros/json_no_io/index.md) is defined.

Serializes the given view `v` to the output stream `o`, using [`dump`](https://json.nlohmann.me/api/basic_json_view/dump/index.md) — exactly as `operator<<(std::ostream&, const basic_json&)` does for a `basic_json` value.

- The indentation of the output can be controlled with the member variable `width` of the output stream `o`. For instance, using the manipulator `std::setw(4)` on `o` sets the indentation level to `4`, and the serialization result is the same as calling `v.dump(4)`. A `width` of `0` or less (the default) selects the most compact representation, as `v.dump(-1)` does.
- The indentation character can be controlled with the member variable `fill` of the output stream `o`. For instance, the manipulator `std::setfill('\t')` sets indentation to use a tab character rather than the default space character.
- As for `basic_json`, `o`'s `width` is reset to `0` after this call, whether or not it was greater than `0` before.

Numbers are always written as `v.dump()` writes them by default, i.e. as with [`number_format::shortest`](https://json.nlohmann.me/api/basic_json_view/number_format/index.md); there is no way to select `number_format::source` through the stream.

## Parameters

`o` (in, out) : stream to write to

`v` (in) : view to serialize

## Return value

the stream `o`

## Exceptions

May throw `std::bad_alloc`, propagated from [`dump`](https://json.nlohmann.me/api/basic_json_view/dump/#exceptions). Unlike `operator<<(std::ostream&, const basic_json&)`, there is no UTF-8 decoding step that could throw [`type_error.316`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error316), and no `error_handler` to choose between — see the [Exceptions](https://json.nlohmann.me/api/basic_json_view/dump/#exceptions) of `dump`.

## Complexity

Linear, as [`dump`](https://json.nlohmann.me/api/basic_json_view/dump/#complexity).

## Examples

Example

The example below writes one record out of a larger batch straight to a log stream — compact for a one-line entry, and pretty-printed with `std::setw`/`std::setfill` for a readable dump — without ever building a `BasicJsonType` value for the record, or for the rest of the batch.

```
#include <iostream>
#include <iomanip>
#include <nlohmann/json_view.hpp>

using nlohmann::json_document;
using nlohmann::json_view;

int main()
{
    // one order out of a large incoming batch -- write it straight to a log
    // stream without ever building a basic_json value for it, or for the
    // rest of the batch
    const json_document doc = json_document::parse(R"(
      [{"id": 1, "item": "cable"}, {"id": 2, "item": "adapter"}]
    )");
    const json_view orders = doc.root();

    // compact, for a one-line log entry
    std::cout << orders[1] << '\n';

    // std::setw sets the indentation level, exactly as for basic_json
    std::cout << std::setw(2) << orders[1] << "\n\n";

    // std::setfill changes the indentation character
    std::cout << std::setw(1) << std::setfill('\t') << orders[1] << '\n';
}
```

Output:

```
{"id":2,"item":"adapter"}
{
  "id": 2,
  "item": "adapter"
}

{
    "id": 2,
    "item": "adapter"
}
```

## See also

- [`dump`](https://json.nlohmann.me/api/basic_json_view/dump/index.md) - serialize to a JSON-formatted string
- [`operator<<(std::ostream&)`](https://json.nlohmann.me/api/operator_ltlt/index.md) - the corresponding operator for `basic_json`
- [`JSON_NO_IO`](https://json.nlohmann.me/api/macros/json_no_io/index.md) - switch off functions relying on certain C++ I/O headers
- [Zero-copy JSON views](https://json.nlohmann.me/features/json_view/#writing-a-view-back) - writing a view back without building a tree

## Version history

- Added in version 3.13.0 unreleased.
