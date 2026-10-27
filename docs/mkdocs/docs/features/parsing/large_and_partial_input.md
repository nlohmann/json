# Large, Streamed, and Partial Input

[`parse`](../../api/basic_json/parse.md) reads exactly one complete JSON value and builds it in memory. It cannot be
paused and resumed, and it does not hand back a half-parsed value when the input ends early. This page shows what to do
when the input does not fit that model: it arrives in pieces, it contains several values, or it is too large to hold
as a `json` value.

```mermaid
flowchart TD
    A["my input is..."] --> B{"several JSON values in one stream?"}
    B -->|"yes"| C["read them one at a time"]
    A --> D{"arriving in chunks (socket, pipe)?"}
    D -->|"yes"| E["frame the messages, or buffer until complete"]
    A --> F{"too large to keep in memory?"}
    F -->|"yes"| G["discard parts with a callback, or use SAX"]
    A --> H{"only a small part is needed?"}
    H -->|"yes"| I["stop early with SAX, or read through a view"]
```

<p class="nj-caption" markdown>Questions about the input and the approach this page describes for each; an input can match more than one question.</p>

## Several values in one stream

For newline-delimited input, read line by line and parse each line, as described in [JSON Lines](json_lines.md). For
values that are simply concatenated, [`operator>>`](../../api/operator_gtgt.md) reads one value and leaves the stream
positioned after it. Check for the end of the stream before each read, because a read at the end throws:

??? example "Example: read concatenated values"

    ```cpp
    --8<-- "examples/partial_input_concatenated.cpp"
    ```

    Output:

    ```
    --8<-- "examples/partial_input_concatenated.output"
    ```

The same works for binary formats. [`from_cbor`](../../api/basic_json/from_cbor.md) and its relatives accept
`#!cpp strict = false` to stop after the first value and leave the rest of the stream untouched; `tellg()` then reports
how many bytes the value took:

??? example "Example: read one CBOR value and find out how many bytes it used"

    ```cpp
    --8<-- "examples/partial_input_cbor.cpp"
    ```

    Output:

    ```
    --8<-- "examples/partial_input_cbor.output"
    ```

## Input arriving in chunks

A socket, pipe, or HTTP body hands over data in pieces of arbitrary size, and a piece can end in the middle of a
number, a string, or an object. The parser does not keep state between calls, so there are two ways to deal with this.

**Frame the messages.** The most robust approach is a protocol that says where a value ends: one value per line
([JSON Lines](json_lines.md)), a length prefix, or a delimiter. Collect the bytes of one message and parse them when
the frame is complete. Prefer this whenever you control the protocol.

**Buffer until the value is complete.** If the data has no framing, append every chunk to a buffer and try to parse
it. A parse error at the very end of the buffer means that the input ended prematurely, while an error anywhere else is
a real syntax error. The member `byte` of the [`parse_error`](../../home/exceptions.md#jsonexceptionparse_error101)
exception is one past the buffer size in the first case:

??? example "Example: buffer chunks until the value is complete"

    ```cpp
    --8<-- "examples/partial_input_buffering.cpp"
    ```

    Output:

    ```
    --8<-- "examples/partial_input_buffering.output"
    ```

The example feeds a document in five chunks. The first four are reported as incomplete, and a syntax error is reported as
such, not as missing data.

The chunks of the example, and the bytes each attempt parses again:

<div class="nj-fig-wrap" markdown>
--8<-- "images/chunk_buffering.svg"
</div>

<p class="nj-caption" markdown>Each row is one parse attempt on the growing buffer: an error at the byte after the end of the buffer means the value is incomplete, an error before the end is a real syntax error. The last line adds up the bytes parsed over all attempts.</p>

!!! warning "Limits of buffering"

    - The buffer must contain exactly one value. Data that belongs to the next value is a syntax error. Use framing if
      values follow each other without a separator.
    - A number at the end of the buffer is a complete value, even if more digits are still to come (`12` may be the
      start of `123`). Buffering cannot detect this; use framing for top-level numbers.
    - Every attempt parses the buffer from the beginning, so the total work grows quadratically with the size of the
      value. Limit the size of the buffer for input you do not trust (see [untrusted input](untrusted_input.md)).

## Input too large for memory

The input does not have to become one huge `json` value. The two tools below process it piece by piece.

How the memory use develops while a large array of records is parsed (illustrative, not a measurement):

<div class="nj-fig-wrap" markdown>
--8<-- "images/memory_over_time.svg"
</div>

<p class="nj-caption" markdown>Memory use over the number of records parsed: `parse()` keeps the whole tree, `json_document` the text plus its index, a discarding callback one record at a time, and SAX only what the handler keeps.</p>

### Handle and discard elements with a callback

A [parser callback](parser_callbacks.md) is called for every finished value. If it returns `#!cpp false`, the value is
discarded and its memory is released at once. For a file that consists of one huge array (or one huge object) of
records, handle each record at depth 1 and discard it:

??? example "Example: handle and discard each record of a large array"

    ```cpp
    --8<-- "examples/partial_input_discard_records.cpp"
    ```

    Output:

    ```
    --8<-- "examples/partial_input_discard_records.output"
    ```

Only one record is in memory at any time. The same recipe, with more detail, is in the
[parser callbacks](parser_callbacks.md#recipe-streaming-a-large-homogeneous-array) page. To skip entire members you do not
need, discard them when their key is read; see the [example](parser_callbacks.md) for `parse_event_t::key`.

### Extract a few values and stop with SAX

With the [SAX interface](sax_interface.md), no value is built at all, and **returning `#!cpp false` from any handler
function stops the parser**. [`sax_parse`](../../api/basic_json/sax_parse.md) then returns `#!cpp false`, and the rest
of the input is not read. The example finds the first `id` in a document without parsing the remainder:

??? example "Example: stop parsing as soon as a value is found"

    ```cpp
    --8<-- "examples/partial_input_sax_stop.cpp"
    ```

    Output:

    ```
    --8<-- "examples/partial_input_sax_stop.output"
    ```

Note that `sax_parse` returns `#!cpp false` both when a handler stopped the parse and when the input is invalid, so
record the reason in the handler (here: `id`) if you need to tell the two apart.

### Read parts of a large document with a view

If the whole text is available and you only need to read some of it, a [`json_document`](../json_view.md) from
`<nlohmann/json_view.hpp>` (added in version 3.13.0) avoids the `basic_json` tree altogether: it keeps the text, builds a flat index of the values,
and gives read-only [views](../../api/basic_json_view/index.md) of the parts you look at. Only what you
[`materialize()`](../../api/basic_json_view/materialize.md) becomes a `basic_json` value. See
[Zero-copy JSON views](../json_view.md) for details and for the lifetime rules.

## See also

- [Parsing](index.md) - overview of the parsing functions
- [JSON Lines](json_lines.md) - newline-delimited JSON
- [Parser callbacks](parser_callbacks.md) - discard values while parsing
- [SAX interface](sax_interface.md) - event-based parsing
- [Zero-copy JSON views](../json_view.md) - read parts of a large document without building a tree
- [Untrusted input](untrusted_input.md) - limits for input you do not control
- [`operator>>`](../../api/operator_gtgt.md) - deserialize from stream
- [`parse`](../../api/basic_json/parse.md) - deserialize from a compatible input
- [`sax_parse`](../../api/basic_json/sax_parse.md) - generate SAX events
- [`JSON_PRECISE_STREAM_POSITION`](../../api/macros/json_precise_stream_position.md) - leave the stream positioned right after a parsed number
- [`JSON_DISABLE_STREAM_BULK_SCAN`](../../api/macros/json_disable_stream_bulk_scan.md) - read a `std::istream` one character at a time
