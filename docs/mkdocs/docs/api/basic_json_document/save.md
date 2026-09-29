# <small>nlohmann::basic_json_document::</small>save

```cpp
std::vector<std::uint8_t> save() const;
```

Writes the document as an *image*: a byte buffer that [`load`](load.md) reads back without parsing. The image holds
the node index, the source text (plus, for an edited document, the number tokens edits wrote), and the decoded
strings (plus the strings edits wrote) -- everything [`root()`](root.md) needs, with nothing left to parse.

An edited document is written in its *current* state, with its values in document order, the way the library's own
parser would have produced them for that JSON text: a member [`set`](set.md) added goes at the end, an
[`erase`](erase.md)d member leaves no trace, and a float that is not finite (NaN or positive/negative infinity)
becomes null, the same substitution [`dump()`](../basic_json_view/dump.md) makes. The same document always saves to
the same bytes -- also across `BasicJsonType` and `#!cpp Editable`, since the image reflects document order and
values only, not which specialization produced them.

## Return value

The image, as a `#!cpp std::vector<std::uint8_t>`. Pass it, or a pointer to its data together with its size, to
[`load`](load.md) to read the document back.

## Exception safety

Strong guarantee: `save()` does not modify `#!cpp *this` (it is `#!cpp const`), so if it throws, the document is left
exactly as it was, and the partially built image is discarded with the exception.

## Exceptions

Throws [`type_error.320`](../../home/exceptions.md#jsonexceptiontype_error320) if the document is
[discarded](is_discarded.md) -- a default-constructed document, or one a failed [`parse()`](parse.md)/
[`read()`](read.md) with `allow_exceptions == false` left discarded.

On a big-endian target, throws `type_error.320` with a different message instead: the image format is little-endian
only (see [Notes](#notes)).

Throws [`out_of_range.416`](../../home/exceptions.md#jsonexceptionout_of_range416) if the node count, the text, or
the decoded strings of the image would individually reach 4 GiB -- the same 32-bit offsets
[`parse()`](parse.md#exceptions) and, for edits, [`set`](set.md)/[`push_back`](push_back.md) are already limited to.

!!! failure "Example messages"

    ```
    [json.exception.type_error.320] cannot save a discarded json_document
    ```
    ```
    [json.exception.type_error.320] json_document images need a little-endian target
    ```
    ```
    [json.exception.out_of_range.416] images of 4 GiB or more are not supported by json_document
    ```

## Complexity

Linear in the size of the document: the number of nodes, plus the length of the text and the decoded strings that end
up in the image.

## Notes

**Format.** The image begins with a 64-byte header (the magic bytes `#!cpp "NJVI"`, a version number, the node count,
and the sizes of the text and the decoded strings, all little-endian), followed by the nodes
([16 bytes each](../../home/architecture.md#node-index-of-json-views)), the text and a `#!cpp '\0'`, and the decoded
strings and a `#!cpp '\0'`. [`load`](load.md) checks the header, and the sizes it describes, before reading anything
else -- see [`load`'s Exceptions](load.md#exceptions).

!!! warning "Experimental"

    The image format is versioned but not yet stable: it may change in an incompatible way before it is declared
    stable. Use images to cache a document within one build of the library, or to hand one to another process running
    the *same* build on the *same* (little-endian) machine -- not as a long-term storage format. Keep the original
    JSON text if you need to read a saved document back with a future library version.

**Little-endian only.** The image is written as raw little-endian bytes, with no byte-swapping. `save()` (and
[`load`](load.md)) throw `type_error.320` on a big-endian target rather than silently produce bytes a big-endian
reader could not interpret correctly.

## Examples

??? example "Caching a parsed document as an image"

    The example below saves a parsed configuration as an image -- the way a service might cache one to answer later
    requests without parsing the text again -- and confirms that loading it back gives exactly the same result as
    parsing did, and that saving is deterministic.

    ```cpp
    --8<-- "examples/basic_json_document__save.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_document__save.output"
    ```

## See also

- [load](load.md) - read an image written by `save()`
- [owns_source](owns_source.md) - return whether the document holds its own copy of the text
- [`basic_json_view::dump`](../basic_json_view/dump.md) - serialize the document to JSON text instead of an image
- [Images](../../features/json_view.md#images) - why and when to use images

## Version history

- Added in version 3.13.0.
