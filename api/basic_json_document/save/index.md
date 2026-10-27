# nlohmann::basic_json_document::save

```
std::vector<std::uint8_t> save() const;
```

Writes the document as an *image*: a byte buffer that [`load`](https://json.nlohmann.me/api/basic_json_document/load/index.md) reads back without parsing. The image holds the node index, the source text (plus, for an edited document, the number tokens edits wrote), and the decoded strings (plus the strings edits wrote) — everything [`root()`](https://json.nlohmann.me/api/basic_json_document/root/index.md) needs, with nothing left to parse.

An edited document is written in its *current* state, with its values in document order, the way the library's own parser would have produced them for that JSON text: a member [`set`](https://json.nlohmann.me/api/basic_json_document/set/index.md) added goes at the end, an [`erase`](https://json.nlohmann.me/api/basic_json_document/erase/index.md)d member leaves no trace, and a float that is not finite (NaN or positive/negative infinity) becomes null, the same substitution [`dump()`](https://json.nlohmann.me/api/basic_json_view/dump/index.md) makes. The same document always saves to the same bytes — also across `BasicJsonType` and the [`view_mode`](https://json.nlohmann.me/api/view_mode/index.md), since the image reflects document order and values only, not which specialization produced them.

## Return value

The image, as a `std::vector<std::uint8_t>`. Pass it, or a pointer to its data together with its size, to [`load`](https://json.nlohmann.me/api/basic_json_document/load/index.md) to read the document back.

## Exception safety

Strong guarantee: `save()` does not modify `*this` (it is `const`), so if it throws, the document is left exactly as it was, and the partially built image is discarded with the exception.

## Exceptions

Throws [`type_error.320`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error320) if the document is [discarded](https://json.nlohmann.me/api/basic_json_document/is_discarded/index.md) — a default-constructed document, or one a failed [`parse()`](https://json.nlohmann.me/api/basic_json_document/parse/index.md)/ [`read()`](https://json.nlohmann.me/api/basic_json_document/read/index.md) with `allow_exceptions == false` left discarded.

Throws [`out_of_range.416`](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range416) if the node count, the text, or the decoded strings of the image would individually reach 4 GiB — the same 32-bit offsets [`parse()`](https://json.nlohmann.me/api/basic_json_document/parse/#exceptions) and, for edits, [`set`](https://json.nlohmann.me/api/basic_json_document/set/index.md)/[`push_back`](https://json.nlohmann.me/api/basic_json_document/push_back/index.md) are already limited to.

Example messages

```
[json.exception.type_error.320] cannot save a discarded json_document
```

```
[json.exception.out_of_range.416] images of 4 GiB or more are not supported by json_document
```

## Complexity

Linear in the size of the document: the number of nodes, plus the length of the text and the decoded strings that end up in the image.

## Notes

**Format.** The image begins with a 64-byte header (the magic bytes `"NJVI"`, a version number, the node count, and the sizes of the text and the decoded strings, all little-endian), followed by the nodes ([16 bytes each](https://json.nlohmann.me/home/architecture/#node-index-of-json-views)), the text and a `'\0'`, and the decoded strings and a `'\0'`. [`load`](https://json.nlohmann.me/api/basic_json_document/load/index.md) checks the header, and the sizes it describes, before reading anything else — see [`load`'s Exceptions](https://json.nlohmann.me/api/basic_json_document/load/#exceptions).

Experimental

The image format is versioned but not yet stable: it may change in an incompatible way before it is declared stable. Use images to cache a document within one build of the library, or to hand one to another process running the *same* build on the *same* (little-endian) machine — not as a long-term storage format. Keep the original JSON text if you need to read a saved document back with a future library version.

**Little-endian targets only.** The image is written as raw little-endian bytes, with no byte-swapping. On a big-endian target, `save()` and [`load`](https://json.nlohmann.me/api/basic_json_document/load/index.md) do not exist: a call fails to compile rather than produce bytes a big-endian reader could not interpret correctly.

## Examples

Caching a parsed document as an image

The example below saves a parsed configuration as an image — the way a service might cache one to answer later requests without parsing the text again — and confirms that loading it back gives exactly the same result as parsing did, and that saving is deterministic.

```
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>
#include <nlohmann/json_view.hpp>

using nlohmann::json_document;

int main()
{
    std::cout << std::boolalpha;

    // a configuration a service parses once and then caches as an image, so
    // that later requests can load() it instead of parsing the text again
    const std::string text = R"({"name": "cache", "host": "db1", "port": 6379, "replicas": ["db2", "db3"]})";
    const json_document config = json_document::parse(text);

    // save() turns the parsed document into a byte buffer: a 64-byte header,
    // the node index, the source text, and the decoded strings
    const std::vector<std::uint8_t> image = config.save();
    std::cout << image.size() << '\n';

    // the same document always saves to the same bytes
    std::cout << (image == json_document::parse(text).save()) << '\n';

    // loading the image back needs no parsing, yet dumps exactly what
    // parsing the text produced
    const json_document reloaded = json_document::load(image);
    std::cout << (reloaded.root().dump() == config.root().dump()) << '\n';
}
```

Output:

```
316
true
true
```

## See also

- [`load`](https://json.nlohmann.me/api/basic_json_document/load/index.md) - read an image written by `save()`
- [`owns_source`](https://json.nlohmann.me/api/basic_json_document/owns_source/index.md) - return whether the document holds its own copy of the text
- [`basic_json_view::dump`](https://json.nlohmann.me/api/basic_json_view/dump/index.md) - serialize the document to JSON text instead of an image
- [Images](https://json.nlohmann.me/features/json_view/#images) - why and when to use images

## Version history

- Added in version 3.13.0 unreleased.
