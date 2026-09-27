# Error Recovery

By default, parsing stops at the first error. With the [SAX interface](sax_interface.md), you can instead ask the
parser to *recover*: to repair the error and continue, so that you get as much as possible out of malformed input, for
instance a file that was cut off, JSON edited by hand, or the output of a language model.

## Recovering from errors

The SAX parser's [`parse_error`](../../api/json_sax/parse_error.md) function is called for every error. Its return value
decides what happens next:

- `#!cpp false` stops parsing. This is what the SAX parsers of the library do, so [`parse`](../../api/basic_json/parse.md)
  and [`accept`](../../api/basic_json/accept.md) never recover.
- `#!cpp true` repairs the error and continues parsing.

When recovering, the SAX parser still receives well-formed events: every `start_object` or `start_array` is followed by
the matching `end_object` or `end_array`, and every `key` is followed by exactly one value. A SAX parser that creates a
JSON value, such as the one in the example below, therefore gets a complete value. Parsing always ends, and
[`sax_parse`](../../api/basic_json/sax_parse.md) returns `#!cpp false` for input that is not valid JSON, even if every
error was repaired. Each token is reported at most once, and the SAX parser can stop at any error by returning
`#!cpp false`.

!!! example

    The example below derives a SAX parser from the library's parser for `json` values (`json_sax_dom_parser`),
    and recovers from all errors.

    ```cpp
    --8<-- "examples/sax_parse__error_recovery.cpp"
    ```
    
    Output:
    
    ```
    --8<-- "examples/sax_parse__error_recovery.output"
    ```

## How errors are repaired

Each error is repaired with the smallest local edit: a missing separator is inserted, a stray token is removed, what can
be read of a broken string or number is kept, and a value that cannot be read at all becomes `#!json null`.

| Mistake                   | Repair                                                                         | Example                                  | Result                     |
|---------------------------|--------------------------------------------------------------------------------|------------------------------------------|----------------------------|
| missing `,` or `:`        | inserted                                                                       | `#!json [1 2]`, `#!json {"a" 1}`         | `[1,2]`, `{"a":1}`         |
| missing value             | `#!json null` for an object key or between commas in an array                  | `#!json {"a":}`, `#!json [1,,2]`         | `{"a":null}`, `[1,null,2]` |
| trailing comma            | removed                                                                        | `#!json [1,2,]`                          | `[1,2]`                    |
| broken string             | invalid escapes and bytes are replaced (see below); a line break ends the string | `#!json ["a\qb"]`                        | `["aqb"]`                  |
| broken number             | the longest valid beginning is kept                                            | `#!json [1., 2e+]`                       | `[1,2]`                    |
| unreadable value          | `#!json null`                                                                  | `#!json [1, NaN, tru]`                   | `[1,null,null]`            |
| number too large          | passed as infinity, together with its text                                     | `#!json [1e999]`                         | infinity (see below)       |
| stray `:`                 | removed                                                                        | `#!json ["a":1]`                         | `["a",1]`                  |
| member without a key      | skipped up to the next `,` or `}`                                              | `#!json {1:2, "b":3}`                    | `{"b":3}`                  |
| wrong closing bracket     | closes the innermost array or object                                           | `#!json {"a":[1,2}, "b":3}`              | `{"a":[1,2],"b":3}`        |
| input ends too early      | all open arrays and objects are closed                                         | `#!json {"a":[1,2`                       | `{"a":[1,2]}`              |
| text before the value     | skipped                                                                        | `#!json )]}'{"a":1}`                     | `{"a":1}`                  |

In a string, an unknown escape like `\q` stands for the escaped character (`q`), as in JavaScript. An invalid `\u`
escape, a lone surrogate, and ill-formed UTF-8 are each replaced by U+FFFD (REPLACEMENT CHARACTER), and control
characters are kept. A string without its closing quote ends at the next line break or at the end of the input.

The input after the top-level value is not repaired: as without recovery, it is reported as an error, and parsing stops.

## Binary formats

The binary formats ([BJData](../binary_formats/bjdata.md), [BON8](../binary_formats/bon8.md),
[BSON](../binary_formats/bson.md), [CBOR](../binary_formats/cbor.md), [MessagePack](../binary_formats/messagepack.md),
and [UBJSON](../binary_formats/ubjson.md)) cannot be repaired: a value's size is stored before its content, and every
byte is a valid type marker, so after an error there is no way to tell where the next value begins. Parsing therefore
always stops at the first error. If `parse_error` returns `#!cpp true`, the value read so far is completed before
parsing stops: a key that waits for its value gets `#!json null`, and all open arrays and objects are closed. This keeps
everything before the error of an input that was cut off.

## Limitations

- A repair is a guess. For example, `#!json {"a" "b": 1}` could be meant as `#!json {"a": "b"}` or as
  `#!json {"a": null, "b": 1}`; it is repaired to the former. Treat recovered values as a best effort, and check the
  reported errors.
- A closing bracket always closes the innermost array or object. If a bracket is missing rather than wrong, the
  repair differs from the intention: `#!json {"a": {"b": [1, 2}, "c": 3}` is repaired to
  `#!json {"a": {"b": [1, 2], "c": 3}}`, although `#!json {"a": {"b": [1, 2]}, "c": 3}` may have been meant.
- Keys without quotes, and strings in single quotes, are not supported; such members are skipped.
- A number that is too large for `number_float_t` is passed as positive or negative infinity. The SAX parser's
  `number_float` also gets the number's text, but a JSON value cannot store it, and
  [`dump`](../../api/basic_json/dump.md) serializes infinity as `#!json null`.
- When parsing is not strict (see [`sax_parse`](../../api/basic_json/sax_parse.md)), a repair may read parts of the
  input after the value, for instance of the next value in a stream of concatenated values.

## See also

- [SAX interface](sax_interface.md) - implement a custom SAX handler
- [`parse_error`](../../api/json_sax/parse_error.md) - the SAX event for parse errors
- [`sax_parse`](../../api/basic_json/sax_parse.md) - generate SAX events
- [parsing and exceptions](parse_exceptions.md) - control error handling
