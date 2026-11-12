# nlohmann::basic_json_document::read

```
template<typename InputType>
void read(InputType&& input,
         const bool allow_exceptions = true,
         const bool ignore_comments = false,
         const bool ignore_trailing_commas = false);
```

(Re-)parses `input` into `*this`, discarding the document's previous value and reusing its memory (the node index, the decoded-string buffer, and, if applicable, the owned copy of the text) rather than allocating a fresh document. [`parse()`](https://json.nlohmann.me/api/basic_json_document/parse/index.md) is implemented in terms of this function, applied to a default-constructed document.

## Template parameters

`InputType` : A compatible input; see [`parse`](https://json.nlohmann.me/api/basic_json_document/parse/#template-parameters).

## Parameters

`input` (in) : Input to parse from.

`allow_exceptions` (in) : whether to throw exceptions in case of a parse error (optional, `true` by default)

`ignore_comments` (in) : whether comments should be ignored and treated like whitespace (`true`) or yield a parse error (`false`); (optional, `false` by default)

`ignore_trailing_commas` (in) : whether trailing commas in arrays or objects should be ignored and treated like whitespace (`true`) or yield a parse error (`false`); (optional, `false` by default)

## Exceptions

Same as [`parse`](https://json.nlohmann.me/api/basic_json_document/parse/#exceptions).

## Complexity

Linear in the length of the input.

## Notes

Every view taken from `*this` before the call — including the previous [`root()`](https://json.nlohmann.me/api/basic_json_document/root/index.md) — is invalidated, whether or not the new parse succeeds; take fresh views from [`root()`](https://json.nlohmann.me/api/basic_json_document/root/index.md) afterward.

`input` must not point into the document itself

`read()` releases the document's previous text, its decoded strings, and (for an editable document) its edits *before* it parses `input`. An `input` that is, or points into, any of them violates a precondition: it may seem to work, parse empty or garbled text, be reported by a sanitizer, or read freed memory (undefined behavior).

This applies to every `string_view` obtained from the document whose characters live in memory that `read()` releases:

- [`source()`](https://json.nlohmann.me/api/basic_json_document/source/index.md) of a document that owns its text;
- [`get_string()`](https://json.nlohmann.me/api/basic_json_view/get_string/index.md) (also as `get<string_view_t>()` or a `string_view` member of a decoded struct) of a string with escapes, of a string of a document that owns its text, and of an edited string;
- [`number_token()`](https://json.nlohmann.me/api/basic_json_view/number_token/index.md) of a number of a document that owns its text, and of a number written by an edit;
- the key of an object member (`key()`) if it has escapes, was written by an edit, or the document owns its text.

It does not apply to a text that the caller owns and the document borrows, nor to the strings, keys, and tokens that are read from such a text unchanged, nor to the decoded strings of a borrowed [image](https://json.nlohmann.me/api/basic_json_document/load/index.md), which live in the caller's image: `read()` never touches them. To parse JSON that a document holds in a string of its own (for example, JSON embedded in a string value), copy the string first, for example with `std::string inner(doc.root()["payload"].get_string()); doc.read(inner);`.

A debug build (one without `NDEBUG`) checks this with `assert()`: an `input` in the document's text, decoded strings, or image, or in the most recent buffer of strings written by edits, ends the program. (Strings written by earlier edits are not covered.) A release build does not check, to keep the cost of reusing a document at a minimum. The check uses `assert()` directly, not [`JSON_ASSERT`](https://json.nlohmann.me/api/macros/json_assert/index.md), which `json.hpp` undefines at its end.

`input` is borrowed or owned by the same rules as [`parse()`](https://json.nlohmann.me/api/basic_json_document/parse/#notes); a document can borrow on one call and own on the next, since ownership is decided freshly each time. An input that is copied (see the table in [`parse()`](https://json.nlohmann.me/api/basic_json_document/parse/#notes)) is written into the document's previous owned copy, reusing its memory; a moved-in `std::string` replaces it.

Reusing a document matters most for large inputs: the operating system provides the memory of a fresh node index one page at a time, and every page costs a page fault the first time it is written. On x86-64 Linux (4 KiB pages), parsing a 55 MB document into a reused document took about 40 % less time than parsing it into a fresh one. Programs that parse many documents of similar size should therefore keep one document and call `read()`.

An integer argument that is not a `bool` where the flags are expected, such as `read(ptr, len)`, does not compile; see [`parse`](https://json.nlohmann.me/api/basic_json_document/parse/#notes).

## Examples

Example

The example below parses a sequence of messages into the same document, reusing its memory instead of allocating a new document for each one.

```
#include <iostream>
#include <string>
#include <vector>
#include <nlohmann/json_view.hpp>

using nlohmann::json_document;

int main()
{
    std::cout << std::boolalpha;

    std::vector<std::string> messages =
    {
        R"({"id": 1})", R"({"id": 2, "tag": "x"})", R"({"id": 3})"
    };

    // parse into the same document over and over: its node index and decode
    // buffer are reused instead of being freed and reallocated for each message
    json_document doc;
    std::size_t total = 0;
    for (const auto& msg : messages)
    {
        doc.read(msg);
        total += doc.root().size();
    }
    std::cout << total << '\n';

    // read() can also change what kind of input is owned/borrowed between calls
    doc.read(std::string(R"({"owned": true})"));
    std::cout << doc.owns_source() << '\n';
}
```

Output:

```
4
true
```

## See also

- [`parse`](https://json.nlohmann.me/api/basic_json_document/parse/index.md) - deserialize from a compatible input
- [`root`](https://json.nlohmann.me/api/basic_json_document/root/index.md) - the view of the root value
- [`load`](https://json.nlohmann.me/api/basic_json_document/load/index.md) - read a document from an image instead of parsing JSON text
- [Zero-copy JSON views](https://json.nlohmann.me/features/json_view/lifetime/index.md) - reusing a document and what it invalidates

## Version history

- Added in version 3.13.0 unreleased.
