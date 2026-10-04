# Parsing Untrusted Input

This page is for applications that parse JSON -- or one of the supported [binary formats](../binary_formats/index.md)
(BJData, BON8, BSON, CBOR, MessagePack, UBJSON) -- from a source they do not fully control, such as a network
connection, an uploaded file, or another process. It summarizes what the library already does for such input and what
remains the caller's responsibility, linking to the pages that cover each aspect in detail rather than repeating them.

For the project's threat model and the countermeasures behind these behaviors, see the
[assurance case](../../community/assurance_case.md); to report a vulnerability, see the
[security policy](../../community/security_policy.md).

## Errors without exceptions

By default, [`parse()`](../../api/basic_json/parse.md) throws a
[`parse_error`](../../home/exceptions.md#jsonexceptionparse_error101) (for instance `parse_error.101` for a syntax
error) when the input is not valid. If your environment cannot use exceptions for untrusted input, the library offers
several alternatives; see [Parsing and exceptions](parse_exceptions.md) for the full comparison:

- Pass `#!cpp false` as the third argument to `parse()` to get a discarded value
  (checked with [`is_discarded()`](../../api/basic_json/is_discarded.md)) instead of a thrown exception, with no
  diagnostic information.
- Use [`accept()`](../../api/basic_json/accept.md) to only check whether the input is valid JSON, without building a
  value.
- Implement the [SAX interface](sax_interface.md) and override `parse_error()` to react to an error yourself, with the
  byte position and the exception that would otherwise have been thrown; see the
  [example](parse_exceptions.md#user-defined-sax-interface) that overrides it to print instead of throw.

If exceptions are unavailable entirely (`-fno-exceptions`, or [`JSON_NOEXCEPTION`](../../api/macros/json_noexception.md)
defined), every `#!cpp throw` in the library becomes a call to `std::abort()` -- there is no way to recover from a
parse error of untrusted input in that configuration; see
[Switch off exceptions](../../home/exceptions.md#switch-off-exceptions) for the details and for overriding this with
`JSON_THROW_USER`.

## Nesting depth

The JSON parser and the binary readers are iterative: they keep the containers they are currently inside of on a
heap-allocated stack instead of calling themselves once per nesting level, so the native call stack does not grow with
the nesting depth of the input. A deeply nested document is therefore bounded by available memory, not by the call
stack, however deeply it is nested.

!!! warning "No built-in depth limit while parsing"

    Neither the parser nor the binary readers impose a limit on how deep the input may nest. An attacker can still
    exhaust memory (though not the call stack) with a sufficiently deep document. If you need to reject over-deep
    untrusted input outright, track the depth yourself, either with a
    [parser callback](parser_callbacks.md#recipe-max-nesting-depth-via-a-callback) for the JSON parser, or by counting
    `start_object`/`start_array` and `end_object`/`end_array` calls in a
    [SAX handler](sax_interface.md) (for the JSON parser or a binary format alike) and throwing once your limit is
    exceeded.

Once a value has been parsed, operations that walk it recursively -- serializing it with
[`dump`](../../api/basic_json/dump.md), hashing it, copying it, comparing two values with `#!cpp ==`, `#!cpp <`, or (in
C++20) `#!cpp <=>`, merging with [`update`](../../api/basic_json/update.md), and applying a
[`merge_patch`](../../api/basic_json/merge_patch.md) -- descend at most 128 levels on the call stack and continue
below that with an explicit stack instead, so none of them can exhaust the stack either, however deeply the value is
nested. Destroying a value (its destructor) never recurses at all, regardless of nesting depth, for the same reason.

!!! note "Not every operation is bounded yet"

    [`diff`](../../api/basic_json/diff.md), [`flatten`](../../api/basic_json/flatten.md), and the binary writers
    (`to_cbor`, `to_msgpack`, ...) still recurse once per nesting level; this is called out as work in progress in the
    [assurance case](../../community/assurance_case.md#secure-design). A value deep enough to matter for these
    operations would typically first have to survive parsing without hitting a self-imposed depth limit, as described
    above.

## Input size

The library does not limit the overall size of a JSON text; a value nested or wide enough will use memory
proportional to the input. If you parse untrusted input of unbounded size, check the size of the file or stream
yourself before -- or while -- handing it to `parse()`.

For the binary formats, an announced size is never trusted outright:

- Reading a string or binary value copies the input in bounded 4096-byte chunks and grows the result as bytes are
  actually consumed, rather than allocating the announced length up front -- a truncated input runs out of bytes
  (reported as a parse error) instead of triggering an oversized allocation.
- When an array announces its number of elements and the array container supports `reserve()` (as `#!cpp std::vector`,
  the default, does), the library reserves storage for at most 16384 of them upfront, regardless of how large the
  announced count is; further elements still grow the container normally as they are read.
- An announced array or object size that exceeds what the target container could ever hold (its `max_size()`) is
  rejected immediately as [`out_of_range.408`](../../home/exceptions.md#jsonexceptionout_of_range408), without
  attempting to allocate anything.

## Strings

Invalid UTF-8 is rejected while parsing, not just while serializing:

- In JSON text, an ill-formed UTF-8 byte in a string is a
  [`parse_error.101`](../../home/exceptions.md#jsonexceptionparse_error101) ("invalid string: ill-formed UTF-8 byte").
- In a binary format, a string that is not valid UTF-8 is a
  [`parse_error.113`](../../home/exceptions.md#jsonexceptionparse_error113).

A `#!cpp '\0'` (NUL) byte *inside* a quoted JSON string is always rejected (it must be escaped as `\u0000`). A NUL byte
*outside* of a string is different: by default it is silently treated as the end of the input, so trailing bytes after
it -- including further, otherwise well-formed JSON -- are silently ignored rather than rejected. Since untrusted input
that happens to embed a NUL is a way to make part of it disappear without a parse error, see the
[FAQ entry](../../home/faq.md#nul-bytes-in-the-input) and consider defining
[`JSON_STRICT_NUL_HANDLING`](../../api/macros/json_strict_nul_handling.md) to `1` to reject a NUL byte like any other
unexpected byte instead.

Parsing is not the only place invalid UTF-8 matters: a string that reached a `#!cpp json` value some other way (for
example, constructed by application code, or, before JSON_STRICT_NUL_HANDLING existed, read from a binary format that
does not validate strings) still has to round-trip back to JSON text. By default,
[`dump()`](../../api/basic_json/dump.md) throws [`type_error.316`](../../home/exceptions.md#jsonexceptiontype_error316)
if the string is not valid UTF-8; passing
[`error_handler_t::replace`](../../api/basic_json/error_handler_t.md) or `error_handler_t::ignore` avoids the exception
instead of crashing an application that forgot to catch it. See
[Handling invalid UTF-8](../serialization.md#handling-invalid-utf-8) for the options and an example.

## Duplicate object keys

The JSON specification leaves the handling of repeated keys in an object up to the implementation, and this library
does too: as described in [`object_t`](../../api/basic_json/object_t.md#behavior), it is unspecified which of the
values for a repeated key ends up in the parsed object. If your application must reject duplicate keys instead of
silently resolving them one way or another, see the
[parser callback recipe for rejecting duplicate keys](parser_callbacks.md#recipe-rejecting-duplicate-object-keys).

## Numbers

A number whose value cannot be represented -- for instance `1E1000`, which overflows `double` -- is rejected while
parsing as [`out_of_range.406`](../../home/exceptions.md#jsonexceptionout_of_range406) rather than silently becoming
infinity. An integer that is syntactically valid but does not fit the 64-bit integer types is not rejected; it is
instead stored as a `double`, which may lose precision for very large values. See
[number limits](../types/number_handling.md#number-limits) for the exact ranges and an example.

## Comments and trailing commas

Both [comments](../comments.md) and [trailing commas](../trailing_commas.md) are rejected by default, matching the
JSON specification; they must be explicitly enabled per call with the `ignore_comments` and `ignore_trailing_commas`
parameters of [`parse()`](../../api/basic_json/parse.md) or [`accept()`](../../api/basic_json/accept.md). Do not
enable either for input whose conformance you cannot otherwise control, since interoperability with strictly
conforming JSON consumers is exactly what the default rejects.

## Checklist

- Wrap parsing in a `#!cpp try`/`#!cpp catch` block, or use `allow_exceptions=false`/`accept()` if your environment
  cannot use exceptions; never let `JSON_NOEXCEPTION`'s `abort()` be the first time you think about error handling.
- If the input's nesting depth matters to you, enforce your own limit with a
  [parser callback](parser_callbacks.md#recipe-max-nesting-depth-via-a-callback) or a
  [SAX handler](sax_interface.md); the library bounds the call stack but not memory use.
- Bound the size of the input itself before parsing, independent of the library's own bounded allocations for binary
  format lengths.
- Decide up front how you want a string with invalid UTF-8 -- from any source, not only parsing -- to be serialized
  (`strict`, `replace`, or `ignore`), rather than discovering it from an uncaught `type_error.316`.
- If a stray NUL byte silently truncating trailing input is a problem for your input format, define
  `JSON_STRICT_NUL_HANDLING`.
- Decide whether duplicate object keys should be an error for your application, and add a callback if so.
- Do not enable `ignore_comments` or `ignore_trailing_commas` for input that must be strictly conforming JSON.

For the broader design rationale and how it is tested (fuzzing, sanitizers, static analysis), see the
[assurance case](../../community/assurance_case.md) and [quality assurance](../../community/quality_assurance.md). To
report a security issue in the library itself, follow the [security policy](../../community/security_policy.md).

## See also

- [Parsing](index.md) - overview of the parsing functions
- [Parsing and exceptions](parse_exceptions.md) - error handling without exceptions
- [Parser callbacks](parser_callbacks.md) - depth limits, duplicate-key rejection, and streaming recipes
- [SAX interface](sax_interface.md) - implement a custom handler with access to parse errors and positions
- [Serialization](../serialization.md) - handling invalid UTF-8 when dumping
- [Number handling](../types/number_handling.md) - number ranges and overflow behavior
- [Assurance case](../../community/assurance_case.md) - the library's threat model and countermeasures
- [Security policy](../../community/security_policy.md) - how to report a vulnerability
