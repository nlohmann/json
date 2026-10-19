# JSON_DISABLE_STREAM_BULK_SCAN

```cpp
#define JSON_DISABLE_STREAM_BULK_SCAN /* value */
```

When defined to `1`, parsing from a `#!cpp std::istream` reads the input one character at a time through the stream
buffer, as in version 3.12.0 and earlier, instead of scanning the characters that the stream buffer already holds in
bulk.

The macro is an escape hatch for stream buffers that do not follow the usual contract of `std::basic_streambuf` (see
the requirements on the stream buffer in the notes below). It does not change any result: values, exceptions, and the
position of the stream after parsing are the same either way. Only the speed differs.

## Default definition

The default value is `0`: streams are scanned in bulk.

```cpp
#define JSON_DISABLE_STREAM_BULK_SCAN 0
```

## Notes

!!! note "How streams are scanned"

    A `std::streambuf` keeps the part of the input it has read but not yet handed out in its *get area*, the range
    from `gptr()` to `egptr()`. A `std::filebuf`, for instance, reads the file in blocks of a few kilobytes into its get
    area, and a `std::stringbuf` exposes its whole string as one get area.

    When parsing from a `std::istream`, the parser scans this get area directly, with the same fast paths that it uses
    for a `std::string`: runs of ordinary string characters, numbers, and indentation are recognized several bytes at a
    time instead of being requested from the stream buffer one character at a time. When the parser reaches the end of
    the get area, it asks the stream buffer for the next character as before, which makes the stream buffer refill its
    get area.

    The parser only reads characters that it would also have read one at a time, and it advances the stream buffer
    exactly over the characters it consumes. Nothing is read ahead, buffered elsewhere, or put back. Therefore, the
    stream is left exactly where it was left before:

    - [`operator>>`](../operator_gtgt.md) and [`sax_parse`](../basic_json/sax_parse.md) with `strict = false` can still
      read several values from one stream, and the stream can still be used with other `std::istream` functions after a
      value has been read.
    - With [`JSON_PRECISE_STREAM_POSITION`](json_precise_stream_position.md), the stream is still positioned right after
      a parsed number.
    - Exception messages, including the line, the column, and the last read token, are unchanged.

!!! note "Performance"

    Parsing from a `std::ifstream` or `std::istringstream` is typically 1.5 to 2 times as fast as before, and reading
    many small values from one stream with `operator>>` 1.4 to 4 times as fast. Parsing from a stream is then within
    about 10 to 20 % of first reading the whole file into a `std::string` and parsing that.

    A stream buffer without a get area (one that only overrides `underflow()` and `uflow()` and hands out every
    character from there) offers nothing to scan in bulk, so it is read one character at a time as before.

!!! note "Requirements on the stream buffer"

    The bulk scan relies on the following behavior, which every stream buffer of the standard library and every stream
    buffer that keeps its input in its get area has:

    - When `sgetc()` returns a character while `gptr() < egptr()`, that character is `*gptr()`; when `sbumpc()` returns
      one, it was at `gptr()` before the call.
    - Characters in the get area are not changed while they are in the get area.
    - `underflow()` or `uflow()` either sets up a get area that holds the returned character at `gptr()` (or at
      `gptr() - 1` after `uflow()`), or leaves the get area empty.

    A stream buffer that returns characters from `uflow()` while leaving unrelated characters in its get area, or that
    changes the characters in its get area in place, does not meet these requirements. Define the macro to `1` for
    such stream buffers.

!!! note "ABI compatibility"

    The value of this macro is encoded in the [namespace](../../features/namespace.md) (tag `_dsbs`), resulting in
    distinct symbol names. Translation units compiled with and without it can therefore be linked into the same program
    without One Definition Rule (ODR) violations, but they cannot exchange instances of library types.

!!! note "Other inputs"

    Strings, string views, vectors, arrays, and pointer or iterator ranges over contiguous memory are scanned in bulk
    anyway. Reading from a `#!cpp FILE*` is not affected by this macro; see
    [`JSON_DISABLE_UNLOCKED_FILE_IO`](json_disable_unlocked_file_io.md) for that input.

## Examples

??? example "Example: reading values from a stream (default)"

    The stream is scanned in bulk, and the values are read one after the other:

    ```cpp
    #include <iostream>
    #include <sstream>
    #include <nlohmann/json.hpp>

    using json = nlohmann::json;

    int main()
    {
        std::istringstream input(R"({"id": 1} {"id": 2} 42 rest)");
        json j1, j2, j3;
        input >> j1 >> j2 >> j3;  // {"id":1}, {"id":2}, 42

        std::string word;
        input >> word;            // "rest"
    }
    ```

??? example "Example: reading one character at a time (macro defined to 1)"

    With the macro, the same program reads the stream one character at a time, with the same results:

    ```cpp
    #define JSON_DISABLE_STREAM_BULK_SCAN 1
    #include <iostream>
    #include <sstream>
    #include <nlohmann/json.hpp>

    using json = nlohmann::json;

    int main()
    {
        std::istringstream input(R"({"id": 1} {"id": 2} 42 rest)");
        json j1, j2, j3;
        input >> j1 >> j2 >> j3;  // {"id":1}, {"id":2}, 42

        std::string word;
        input >> word;            // "rest"
    }
    ```

## See also

- [**parse**](../basic_json/parse.md) - deserialize from a compatible input
- [**operator>>**](../operator_gtgt.md) - deserialize from stream
- [**sax_parse**](../basic_json/sax_parse.md) - generate SAX events
- [**JSON_PRECISE_STREAM_POSITION**](json_precise_stream_position.md) - leave an input stream positioned right after a
  parsed number
- [**JSON_DISABLE_UNLOCKED_FILE_IO**](json_disable_unlocked_file_io.md) - read a `FILE*` with the locking stdio
  functions
- [Parsing: input sources and performance](../../features/parsing/index.md#input-sources-and-performance)

## Version history

- Added in version 3.13.0.
