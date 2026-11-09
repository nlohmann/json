# Images

[`save()`](../../api/basic_json_document/save.md) writes a document as an *image*: a byte buffer that
[`load()`](../../api/basic_json_document/load.md) reads back into a document without parsing — no lexing, no building
the node index, nothing but copying the nodes and pointing the text and the decoded strings at the image. Where
[`parse_copy()`](../../api/basic_json_document/parse_copy.md) still has to scan the whole input,
[`load()`](../../api/basic_json_document/load.md) turns that scan into a copy of the node index alone.

## Why

A document that is parsed once and then read many times — a configuration loaded at startup, a template rendered on
every request, a large reference dataset a worker process needs in memory — pays for parsing once but can amortize
[`save()`](../../api/basic_json_document/save.md)'s cost across every later load. That makes images useful for a
cache: save a document the first time it is parsed (to a file, a shared-memory segment, an in-process cache), and
[`load()`](../../api/basic_json_document/load.md) it on every later use instead of parsing the source text again.
They are just as useful for handing a parsed document to another process (or a forked worker) running the same build
of the library, since [`load()`](../../api/basic_json_document/load.md) turns the transfer into a copy of the node
index plus pointers into the received bytes, not a re-parse.

## Choosing a check

[`load()`](../../api/basic_json_document/load.md) takes an
[`image_check`](../../api/basic_json_document/load.md#image_check) that trades validation against speed:

- `image_check::full` (the default) checks everything the parser itself guarantees, so a checked image is exactly as
  safe to read and serialize as a freshly parsed document — the right choice whenever the image did not come straight
  from this process's own [`save()`](../../api/basic_json_document/save.md), such as a file or a network peer.
- `image_check::bounds` only checks structure and bounds — cheaper, since it skips scanning the text and the decoded
  strings — and fits a cache the process trusts, one it wrote and reads back itself.
- `image_check::none` skips validation entirely, for an image trusted as much as the process's own memory.

See [`load()`'s Notes](../../api/basic_json_document/load.md#notes) for exactly what each level does and does not
guarantee.

??? example "Example: cache a parsed configuration as an image"

    ```cpp
    --8<-- "examples/basic_json_document__save.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_document__save.output"
    ```

!!! warning "Experimental"

    The image format is versioned but not yet stable, and may change in an incompatible way before it is declared
    stable. It is little-endian only (on big-endian targets, `save()` and `load()` do not exist), and tied to the
    library build that wrote it — use it to cache a document or to hand one to another process running the *same*
    build, not as a long-term storage format; keep the original JSON text if a saved document needs to be readable by
    a future library version.

## Credits

The idea of a document you can read without parsing comes from zero-copy formats such as
[FlatBuffers](https://github.com/google/flatbuffers) and [YaFF](https://github.com/yandex/yaff); the check
[`load()`](../../api/basic_json_document/load.md) runs follows the idea of FlatBuffers' Verifier. No code is taken from
either.

## See also

- [Zero-copy JSON views](index.md) - overview
- [`save()`](../../api/basic_json_document/save.md) - write a document as an image
- [`load()`](../../api/basic_json_document/load.md) - read an image back into a document

## Version history

- Added in version 3.13.0.
