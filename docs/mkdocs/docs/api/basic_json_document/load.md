# <small>nlohmann::basic_json_document::</small>load

```cpp
// (1)
static basic_json_document load(const std::uint8_t* image, std::size_t size,
                                 const image_check check = image_check::full);

// (2)
static basic_json_document load(const std::vector<std::uint8_t>& image,
                                 const image_check check = image_check::full);

// (3)
static basic_json_document load(std::vector<std::uint8_t>&& image,
                                 const image_check check = image_check::full);
```

1. Reads an image [`save()`](save.md) wrote, from a pointer and a byte count. The image is **borrowed**: `image`
   must stay alive and unchanged for as long as the returned document, and any view taken from it, is used.
2. Reads an image from a `#!cpp std::vector`. Also **borrowed** -- equivalent to overload 1 called with
   `#!cpp image.data()` and `#!cpp image.size()`.
3. Reads an image, keeping the vector instead of copying it: `image` is moved into the document (no copy), which
   then owns it for as long as it needs the text and the decoded strings. [`owns_source()`](owns_source.md) is
   `#!cpp true` afterward.

In every overload, the node index is copied into storage the document itself owns -- so that it is properly aligned,
and, for an [editable](index.md#edits) document, can be edited -- while the text and the decoded strings stay in
`image`. The hash indexes [large objects](../../features/json_view.md) use for lookup are rebuilt, exactly as after
parsing.

## Parameters

`image` (in)
:   the image [`save()`](save.md) wrote (overloads 1 and 2), or one to take ownership of (overload 3)

`size` (in)
:   the number of bytes at `image` (overload 1)

`check` (in)
:   how thoroughly to validate `image` before trusting it; see [`image_check`](#image_check) below (optional,
    `#!cpp image_check::full` by default)

## Return value

The document read from the image.

## Exception safety

Overloads 1 and 2 give the strong guarantee: `image` is only read, never written, so a thrown exception leaves the
caller's buffer untouched.

Overload 3 moves `image` into the document *before* validating it, so that a good image is kept without a copy. If
loading then fails, the partially built document -- and the vector now inside it -- is discarded along with the
exception, and `image` itself is left **empty**, not restored to what was passed in. Move a copy in instead, or
validate with overload 2 first, if the original vector must survive a failed load.

## Exceptions

On a big-endian target, throws [`type_error.320`](../../home/exceptions.md#jsonexceptiontype_error320) -- the same
exception [`save()`](save.md#exceptions) throws there, since the image format is little-endian only.

Otherwise throws [`parse_error.116`](../../home/exceptions.md#jsonexceptionparse_error116) if `image` is not one
`save()` could have written, or fails the requested `check`:

| message               | when                                                                                                |
|------------------------|------------------------------------------------------------------------------------------------------|
| `too short`            | `image` is `#!cpp nullptr`, or `size` is smaller than the 64-byte header                             |
| `unknown format`       | the header's magic bytes or version do not match, or a reserved header field is not zero             |
| `sizes out of range`   | the node count, text size, or decoded-string size the header describes does not fit `size`, or the `#!cpp '\0'` after the text or after the decoded strings is missing |
| `the check failed`     | `check` is not `#!cpp image_check::none`, and the image fails it -- see [`image_check`](#image_check) |

!!! failure "Example messages"

    ```
    [json.exception.parse_error.116] parse error: invalid json_document image: too short
    ```
    ```
    [json.exception.parse_error.116] parse error: invalid json_document image: unknown format
    ```
    ```
    [json.exception.parse_error.116] parse error: invalid json_document image: sizes out of range
    ```
    ```
    [json.exception.parse_error.116] parse error: invalid json_document image: the check failed
    ```

## Complexity

Linear in the number of nodes, which are always copied into the document. With `#!cpp check == image_check::full`,
additionally linear in the combined length of the text and the decoded strings; `#!cpp image_check::bounds` and
`#!cpp image_check::none` do not read them.

## Notes

**The `image_check` modes.**

```cpp
using image_check = detail::view::image_check;

enum class image_check
{
    full,
    bounds,
    none
};
```

How thoroughly `load()` validates `image` before trusting it.

| value    | checks                                                                                                    | guarantees |
|----------|--------------------------------------------------------------------------------------------------------------|------------|
| `full`   | everything the parser itself guarantees: structure and bounds; that every string is valid UTF-8 (and, for a string still in the source text, that it contains no quote, backslash, or control character); and that every number token is well-formed and matches the value stored for it | reading and serializing a checked image is safe and always produces valid JSON, exactly as for a parsed document |
| `bounds` | structure and bounds only -- that every offset and count in the node index stays inside the image            | reading and serializing stay memory-safe, but a crafted image can hold strings that are not valid UTF-8 or that serialize to invalid JSON ([`dump()`](../basic_json_view/dump.md) writes them unchanged or throws [`type_error.316`](../../home/exceptions.md#jsonexceptiontype_error316)), and numbers whose values differ from their text |
| `none`   | nothing                                                                                                       | images from a trusted source only -- reading a damaged image is undefined behavior |

`full` is the default and the right choice for an image from anything you do not fully control -- a file, a cache
shared with other processes, a peer on the network. `bounds` skips scanning the text and the decoded strings, so it
fits a cache your own process just wrote and reads straight back, where damage would mean a bug or a hardware fault
rather than adversarial input; it still cannot crash or read out of bounds. `none` skips validation entirely and
should only be used for an image you trust as much as your own memory.

**Lifetime.** Overloads 1 and 2 borrow `image`: it must stay alive and byte-for-byte unchanged for as long as the
returned document, and any [view](../basic_json_view/index.md) taken from it, is used -- exactly like a document
[`parse()`](parse.md) borrowed its input for. Overload 3 avoids this by keeping the vector itself; see
[`owns_source`](owns_source.md).

!!! warning "Experimental"

    The image format is versioned but not yet stable, and may change in an incompatible way before it is declared
    stable; `load()` already rejects an image written by a different format version with `parse_error.116`
    ("unknown format"). Use images to cache a document within one build of the library, or to hand one to another
    process running the *same* build on the *same* (little-endian) machine -- not as a long-term storage format.

**What `image_check::bounds` does not guarantee.** A bounds-checked image can never make `load()`,
[`root()`](root.md), element access, or [`materialize()`](../basic_json_view/materialize.md) read outside the image,
so those stay safe on a damaged one. It does *not* guarantee that the image describes valid JSON: a string
that a `full` check would have rejected can make [`dump()`](../basic_json_view/dump.md) write invalid UTF-8 or invalid
JSON, or throw `type_error.316`, and a number can read back with a value that does not match how it is spelled.
Reserve `bounds` for images you already trust to be well-formed, and use it only to skip the extra scan.

## Examples

??? example "Caching a document, ownership, and a rejected image"

    The example below saves a parsed document as an image, checks that `load()` reproduces the original
    [`dump()`](../basic_json_view/dump.md) without parsing, and shows the difference between
    `load(std::move(image))` (owned) and `load(image)` (borrowed). It then damages one byte of the image and shows
    `image_check::full` rejecting it with `parse_error.116`, while `image_check::bounds` -- meant for a cache the
    process already trusts -- still reads it without going out of bounds.

    ```cpp
    --8<-- "examples/basic_json_document__load.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_document__load.output"
    ```

## See also

- [save](save.md) - write the document as an image
- [owns_source](owns_source.md) - return whether the document holds its own copy of the text
- [parse](parse.md) - deserialize from JSON text instead of an image
- [Images](../../features/json_view.md#images) - why and when to use images

## Version history

- Added in version 3.13.0.
