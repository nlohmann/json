# Assurance case

This page argues why the library meets its security requirements. It describes the threats the library faces, where the
trust boundaries lie, and how the library's design and the [quality assurance](quality_assurance.md) counter these
threats. To report a vulnerability, see the [security policy](security_policy.md).

## Threat model

The library parses, stores, and serializes JSON values in memory. It does not open network connections, does not open
files (it only reads from streams or `std::FILE*` handles that the caller has already opened), does not read environment
variables, and does not implement cryptography or handle credentials.

The primary threat is therefore **untrusted input**: JSON text or binary data (BJData, BSON, CBOR, MessagePack, UBJSON)
that an attacker controls, passed to [`parse`](../api/basic_json/parse.md), [`accept`](../api/basic_json/accept.md),
[`sax_parse`](../api/basic_json/sax_parse.md), or one of the `from_*` functions such as
[`from_cbor`](../api/basic_json/from_cbor.md). Such input may try to

- make the library read or write out of bounds (malformed lengths, truncated input, invalid UTF-8),
- trigger undefined behavior (integer overflow in sizes or numbers, invalid casts),
- exhaust memory (huge announced sizes), or
- exhaust the call stack (deeply nested arrays and objects).

## Trust boundaries

- **Untrusted:** all serialized input read by the parser, the SAX interface, and the binary readers. The library must
  handle every possible input by either producing a value or throwing a [`parse_error`](../home/exceptions.md#parse-errors)
  (or returning `false` when exceptions are disabled for the call).
- **Trusted:** the C++ code that calls the library. Calling a function with violated preconditions, for instance
  accessing an array with [`operator[]`](../api/basic_json/operator%5B%5D.md) out of range, is a programming error and
  not a security boundary. Such preconditions are checked with [runtime assertions](../features/assertions.md) in debug
  builds; functions such as [`at`](../api/basic_json/at.md) offer checked access with exceptions.

## Secure design

- **Strict parsing.** The parser accepts exactly the JSON grammar of [RFC 8259](https://datatracker.ietf.org/doc/html/rfc8259).
  Extensions such as [comments](../features/comments.md) and [trailing commas](../features/trailing_commas.md) must be
  enabled explicitly. Invalid UTF-8 is rejected.
- **Errors are reported, not ignored.** Malformed input results in a [`parse_error`](../home/exceptions.md#parse-errors)
  with the byte position of the error. Binary readers do not trust announced sizes: strings and binary values grow
  only as bytes are actually read, arrays reserve at most a fixed number of elements up front, and sizes that no
  container can hold are rejected.
- **Memory is owned by values.** Each `basic_json` value owns its content, and there is no manual memory management in
  user code. The destructor does not recurse, so destroying a deeply nested value does not exhaust the stack.
- **Bounded recursion.** The JSON parser and the binary readers keep their state in explicit stacks instead of
  recursing per nesting level. Operations that walk a value, such as [`dump`](../api/basic_json/dump.md), copying,
  hashing, and [`merge_patch`](../api/basic_json/merge_patch.md), recurse only up to a fixed depth and continue with an
  explicit stack below it. Some operations, such as comparison, [`diff`](../api/basic_json/diff.md),
  [`flatten`](../api/basic_json/flatten.md), and the binary writers, still recurse once per nesting level; work on them
  is in progress. Applications that process untrusted input can limit its nesting depth with a
  [parser callback](../features/parsing/parser_callbacks.md).
- **Invariants are checked.** The class invariant (for instance, that the pointer for the stored type is never null) is
  checked with runtime assertions throughout the test suite.

## Common weaknesses

The following table maps the relevant classes of the [Common Weakness Enumeration](https://cwe.mitre.org) to the
measures that counter them. The measures are described in detail in [Quality assurance](quality_assurance.md).

| Weakness                                                                  | Countermeasures                                                                                  |
|---------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| Out-of-bounds read/write ([CWE-125](https://cwe.mitre.org/data/definitions/125.html), [CWE-787](https://cwe.mitre.org/data/definitions/787.html)) | bounds checks on all reads from the input; AddressSanitizer and Valgrind on the test suite; OSS-Fuzz      |
| Integer overflow ([CWE-190](https://cwe.mitre.org/data/definitions/190.html)) | UndefinedBehaviorSanitizer with integer overflow detection; Clang-Tidy; Cppcheck                 |
| Use after free, double free ([CWE-416](https://cwe.mitre.org/data/definitions/416.html), [CWE-415](https://cwe.mitre.org/data/definitions/415.html)) | ownership of all memory by values; AddressSanitizer and Valgrind; Clang Static Analyzer          |
| Memory leaks ([CWE-401](https://cwe.mitre.org/data/definitions/401.html)) | Valgrind (Memcheck) on the test suite                                                            |
| Uncontrolled recursion ([CWE-674](https://cwe.mitre.org/data/definitions/674.html)) | iterative parser, binary readers, and destructor; bounded recursion in value operations; tests with deeply nested inputs |
| Uncontrolled resource consumption ([CWE-400](https://cwe.mitre.org/data/definitions/400.html)) | allocations based on announced sizes are capped; OSS-Fuzz with memory limits                     |
| Undefined behavior in general ([CWE-758](https://cwe.mitre.org/data/definitions/758.html)) | UndefinedBehaviorSanitizer; runtime assertions; Clang-Tidy, Cppcheck, Clang Static Analyzer, Infer |

In addition, every line of the library is covered by the unit tests, and all parsers are fuzz-tested around the clock
by [OSS-Fuzz](https://github.com/google/oss-fuzz/tree/master/projects/json).
