# JSON Variants

This library reads and writes JSON as defined by [RFC 8259](https://tools.ietf.org/html/rfc8259) and
[ECMA-404](https://ecma-international.org/publications-and-standards/standards/ecma-404/). Many other formats are
built around JSON: some relax its syntax (for example, to allow comments), some put several JSON values into one
stream, some restrict it further, and some give certain JSON values a special meaning. This page lists the common
ones and how much of each the library supports.

## Overview

| Variant                                                          | Kind                       | Support                                                                                                   |
|------------------------------------------------------------------|----------------------------|-----------------------------------------------------------------------------------------------------------|
| [JSON](https://tools.ietf.org/html/rfc8259) (RFC 8259, ECMA-404) | the standard               | :white_check_mark: default                                                                                |
| [JSONC](https://jsonc.org)                                       | relaxed syntax             | :white_check_mark: with `ignore_comments` (and `ignore_trailing_commas` where trailing commas are wanted) |
| [JWCC](https://nigeltao.github.io/blog/2021/json-with-commas-comments.html) / [HuJSON](https://github.com/tailscale/hujson) | relaxed syntax             | :white_check_mark: with `ignore_comments` and `ignore_trailing_commas`                                    |
| [JSON5](https://spec.json5.org)                                  | relaxed syntax             | :warning: comments and trailing commas only                                                               |
| [Hjson](https://hjson.github.io), [HOCON](https://github.com/lightbend/config/blob/main/HOCON.md), [UCL](https://github.com/vstakhov/libucl), SJSON | configuration languages    | :x: only input that is JSON plus `//`/`/* */` comments and trailing commas                                |
| [YAML](https://yaml.org), [Amazon Ion](https://amazon-ion.github.io/ion-docs/) | other languages            | :x: see [converters](#other-languages-and-converters)                                                     |
| [JSON Lines](https://jsonlines.org), [NDJSON](https://github.com/ndjson/ndjson-spec) | several values             | :white_check_mark: line by line, see [JSON Lines](json_lines.md)                                          |
| concatenated JSON                                                | several values             | :white_check_mark: with `operator>>`, see [Large, streamed, and partial input](large_and_partial_input.md#several-values-in-one-stream) |
| [JSON text sequences](https://www.rfc-editor.org/rfc/rfc7464) (RFC 7464) | several values             | :warning: split the input yourself, see [below](#json-text-sequences-rfc-7464)                            |
| [I-JSON](https://www.rfc-editor.org/rfc/rfc7493) (RFC 7493)      | restricted profile         | :warning: most rules are enforced, see [below](#i-json-rfc-7493)                                          |
| [JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785) (RFC 8785) | restricted output          | :x: `dump()` output is close, but not canonical                                                           |
| `NaN`, `Infinity` (JavaScript, Python)                           | number extension           | :x: rejected by the parser, written as `null`                                                             |
| [JSON Schema](https://json-schema.org), [JSON-LD](https://json-ld.org), [GeoJSON](https://www.rfc-editor.org/rfc/rfc7946), [MongoDB Extended JSON](https://www.mongodb.com/docs/manual/reference/mongodb-extended-json/) | conventions on top of JSON | :white_check_mark: parsed as plain JSON; interpreting them is up to you                                   |

Whatever was parsed, [`dump`](../../api/basic_json/dump.md) always writes standard JSON: no comments, no trailing
commas, and no `NaN` or `Infinity`.

## Standard JSON

By default, [`parse`](../../api/basic_json/parse.md) accepts exactly the JSON grammar of RFC 8259, including values
other than objects and arrays at the top level (such as `#!json 42` or `#!json "text"`). A UTF-8 byte order mark at the
very start of the input is skipped; anywhere else it is a parse error.

## Relaxed syntax

### JSONC and JWCC

**JSONC** ("JSON with comments", used, for example, by Visual Studio Code's `settings.json` and `devcontainer.json`)
adds `//` and `/* */` comments to JSON. Block comments do not nest. The [JSONC specification](https://jsonc.org) lets
parsers decide whether they accept trailing commas. **JWCC** ("JSON with commas and comments") adds the same comments
and always allows a single trailing comma in arrays and objects; [HuJSON](https://github.com/tailscale/hujson) is
Tailscale's implementation of it.

Both are fully supported by passing `ignore_comments` and `ignore_trailing_commas` to `parse`:

```cpp
json j = json::parse(input,
                     /* callback */ nullptr,
                     /* allow_exceptions */ true,
                     /* ignore_comments */ true,
                     /* ignore_trailing_commas */ true);
```

Comments are treated as whitespace and are not kept, so they are lost when the value is written again. This also holds
for a [`json_document`](../../api/basic_json_document/index.md): [`dump()`](../../api/basic_json_view/dump.md) of its
root view writes the same text as `dump()` of the parsed `json` value, even though the document keeps the source text
with the comments. See
[Comments](../comments.md) and [Trailing commas](../trailing_commas.md) for the details. The .NET options
`JsonCommentHandling.Skip` and `AllowTrailingCommas` accept the same syntax.

### JSON5

[JSON5](https://spec.json5.org) is a superset of JSON that follows the syntax of ECMAScript 5 object literals. Besides
comments and trailing commas, it allows unquoted keys, single-quoted strings, line continuations in strings, more
escape sequences (`\v`, `\0`, `\xHH`, ...), hexadecimal numbers, a leading `+`, a leading or trailing decimal point, and
`Infinity` and `NaN`. With the two options above, the library accepts JSON5 documents that only use comments and
trailing commas; using any of the other extensions is a parse error.

### Configuration languages

[Hjson](https://hjson.github.io), [HOCON](https://github.com/lightbend/config/blob/main/HOCON.md),
[UCL](https://github.com/vstakhov/libucl), and SJSON (from the Bitsquid/Stingray game engine) are configuration
languages that accept JSON but go much further: `#` comments, unquoted keys and values, `=` instead of `:`, optional
commas and braces, multiline strings, and, in HOCON and UCL, includes and variable substitutions. The library does not
support these extensions. A `#` comment in particular is always a parse error, even with `ignore_comments`.

### Other languages and converters

[YAML](https://yaml.org) and the text format of [Amazon Ion](https://amazon-ion.github.io/ion-docs/) are separate
languages with their own data models, and the library does not read them. The [Ecosystem](../../community/ecosystem.md)
page lists projects that convert YAML or XML to and from `nlohmann::json`.

## Several values in one input

`parse` reads exactly one value and reports anything after it as an error. Several common formats combine many values
into one input:

- **[JSON Lines](https://jsonlines.org)** and **[NDJSON](https://github.com/ndjson/ndjson-spec)** put one value on each
  line. Read them line by line, as shown on the [JSON Lines](json_lines.md) page. The two formats differ in one detail:
  JSON Lines does not allow empty lines, while NDJSON parsers may skip them. Passing an empty line to `parse` is an
  error, so skip empty lines yourself if you read NDJSON.
- **Concatenated JSON** puts values directly after each other, optionally separated by whitespace. Read them with
  [`operator>>`](../../api/operator_gtgt.md), as shown in
  [Large, streamed, and partial input](large_and_partial_input.md#several-values-in-one-stream).

### JSON text sequences (RFC 7464)

A [JSON text sequence](https://www.rfc-editor.org/rfc/rfc7464) (media type `application/json-seq`) starts every value
with the ASCII record separator (RS, `0x1E`) and ends it with a line feed. The library does not read the record
separator, but splitting the input at it is enough. The RFC asks parsers to skip a truncated or invalid value and
continue with the next one, which parsing without exceptions does:

```cpp
std::string record;
while (std::getline(input, record, '\x1e'))
{
    // the input starts with RS, and several RS in a row are allowed
    if (record.find_first_not_of(" \t\r\n") == std::string::npos)
    {
        continue;
    }

    json j = json::parse(record, nullptr, /* allow_exceptions */ false);
    if (j.is_discarded())
    {
        continue; // truncated or invalid value
    }

    // use j
}
```

To write a sequence, write `'\x1e'`, then `j.dump()`, then `'\n'` for every value.

## Restricted profiles

### I-JSON (RFC 7493)

[I-JSON](https://www.rfc-editor.org/rfc/rfc7493) ("Internet JSON") is a subset of JSON meant for interoperable
protocols. The table shows how the library handles each of its rules:

| I-JSON rule                                                     | Library behavior                                                                              |
|-----------------------------------------------------------------|-----------------------------------------------------------------------------------------------|
| text must be UTF-8                                              | enforced: invalid UTF-8 is a parse error                                                      |
| no surrogate code points in strings, also not as `\u` escapes   | enforced: a lone surrogate such as `"\ud800"` is a parse error                                |
| no noncharacters (such as U+FFFF) in strings                    | not enforced: they are accepted                                                               |
| no duplicate object keys                                        | not enforced: they are accepted; `parse` keeps the last value, while lookups in a [`json_view`](../json_view/differences.md#duplicate-keys) return the first; see the [recipe for rejecting duplicate keys](parser_callbacks.md#recipe-rejecting-duplicate-object-keys) |
| numbers should fit into an IEEE 754 double                      | numbers that overflow a double, such as `1E400`, throw [`out_of_range.406`](../../home/exceptions.md#jsonexceptionout_of_range406); integers are kept exactly up to 64 bits, larger ones are stored as doubles, see [number handling](../types/number_handling.md) |
| top-level values should be objects or arrays                    | not enforced: any value is accepted at the top level                                          |

### JSON Canonicalization Scheme (RFC 8785)

The [JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785) (JCS) defines one exact text for each value,
so that it can be hashed or signed. `dump()` without indentation comes close, as it writes no whitespace and, with the
default [`std::map`](../types/index.md#objects), sorts the object keys. It is not canonical, though:

- JCS formats numbers like ECMAScript, so `#!json 1.0` is written as `1` and `#!json 0.000001` as `0.000001`, while
  `dump()` writes `1.0` and `1e-06`.
- JCS sorts keys by their UTF-16 code units, while `std::map` sorts them by their UTF-8 bytes. The two orders differ
  for keys that contain characters above U+FFFF.

## Non-finite numbers

`NaN`, `Infinity`, and `-Infinity` are not part of JSON, but some libraries write them, among them Python's `json`
module, which does so by default (use `allow_nan=False` there to get standard JSON). This library rejects them as
parse errors, and it writes the non-finite values that a `basic_json` value can hold as `#!json null`. See
[NaN handling](../types/number_handling.md#nan-handling).

## Conventions on top of JSON

Formats such as [JSON Schema](https://json-schema.org), [JSON-LD](https://json-ld.org),
[GeoJSON](https://www.rfc-editor.org/rfc/rfc7946), and
[MongoDB Extended JSON](https://www.mongodb.com/docs/manual/reference/mongodb-extended-json/) are standard JSON with
agreed meanings for certain keys or values, such as `{"$numberLong": "42"}` or a `"$comment"` key. The library parses
and writes them like any other JSON; what the values mean is up to your code. For schema validation, see the
[Ecosystem](../../community/ecosystem.md#schema-validation) page.

A few other standards built on JSON are supported directly: [JSON Pointer](../json_pointer.md),
[JSON Patch](../json_patch.md), and [JSON Merge Patch](../merge_patch.md).

For compact binary encodings of the JSON data model, such as CBOR or MessagePack, see
[Binary formats](../binary_formats/index.md).

## See also

- [Parsing](index.md) - overview of the parsing functions
- [Comments](../comments.md) - ignore `//` and `/* */` comments while parsing
- [Trailing Commas](../trailing_commas.md) - accept trailing commas in arrays and objects
- [JSON Lines](json_lines.md) - parse newline-delimited JSON
- [Large, Streamed, and Partial Input](large_and_partial_input.md) - chunked, concatenated, and very large input
- [Number handling](../types/number_handling.md) - how numbers are parsed, stored, and written
- [Binary formats](../binary_formats/index.md) - binary encodings of the JSON data model
- [Ecosystem](../../community/ecosystem.md) - projects that build on this library, including format converters
