# Ownership and lifetime

A document either **borrows** the text it was parsed from, or **owns** its own copy of it; call [`owns_source()`](https://json.nlohmann.me/api/basic_json_document/owns_source/index.md) to find out which happened. [`parse()`](https://json.nlohmann.me/api/basic_json_document/parse/index.md) decides this from the value category and type of its argument (an lvalue `std::string` is borrowed; an rvalue `std::string` is moved in, owned without a copy; a stream is read into an owned buffer; and so on — see [`parse`'s Notes](https://json.nlohmann.me/api/basic_json_document/parse/#notes) for the full table). [`parse_copy()`](https://json.nlohmann.me/api/basic_json_document/parse_copy/index.md) always owns a copy, regardless of the input.

A borrowed document depends on your buffer

If a document borrows its text, that text **must outlive the document** (and every view taken from it) and must stay **unmodified** for as long as the document exists, since floating-point values and unescaped strings are read from it lazily. Reading or writing through a view after the underlying buffer is gone is undefined behavior, exactly as it would be for a dangling `std::string_view`.

## When a view is valid

A view is valid only while all of the following hold:

- the document is alive,
- the document has not been re-parsed since the view was taken (with [`read()`](https://json.nlohmann.me/api/basic_json_document/read/index.md) or [`parse()`](https://json.nlohmann.me/api/basic_json_document/parse/index.md) into it),
- the document has not had [`shrink_to_fit()`](https://json.nlohmann.me/api/basic_json_document/shrink_to_fit/index.md) called on it since, and
- if the document borrows its source text, that text is still alive and unmodified.

Moving the `basic_json_document<>` itself is fine and does **not** invalidate its views: the index is a separate heap allocation that keeps its address across the move. Take a fresh view from [`root()`](https://json.nlohmann.me/api/basic_json_document/root/index.md) whenever any of the other conditions above was not met. Edits of an [editable document](https://json.nlohmann.me/features/json_view/editing/index.md) keep views valid, too; see [What stays valid](https://json.nlohmann.me/features/json_view/editing/#what-stays-valid-and-what-an-edit-costs).

Four timelines of a document and its views, each bar showing when an object is alive or valid and when it dangles. Destroying the borrowed text, re-parsing, or shrinking the document invalidates the views taken before; moving the document does not.

## Why views can dangle

A view can dangle, exactly like a `std::string_view`: nothing stops you from using it after its document is gone. This is deliberate. A view is two pointers and trivially copyable; making it safe (a `std::shared_ptr` in the document and a `std::weak_ptr` in each view) would make it larger, add reference counting to every copy, and a `lock()` to every access — exactly the costs the view exists to avoid. What is caught is the obvious case: because a view dies with its document, [`root()`](https://json.nlohmann.me/api/basic_json_document/root/index.md) is not callable on a temporary document: `auto v = json_document::parse(text).root();` does not compile. Give the document a name first.

The same holds for what a view hands out without copying: a string from [`get_string()`](https://json.nlohmann.me/api/basic_json_view/get_string/index.md), a token from [`number_token()`](https://json.nlohmann.me/api/basic_json_view/number_token/index.md), and [`string_view` members](https://json.nlohmann.me/features/json_view/reading/#string_view-members) of decoded structs are valid only as long as the document and, if it borrows, its source text.

This includes [`read()`](https://json.nlohmann.me/api/basic_json_document/read/index.md): it releases the document's text, decoded strings, and edits before it parses its input, so the input must not be a `string_view` obtained from the document itself: its [`source()`](https://json.nlohmann.me/api/basic_json_document/source/index.md), a string from `get_string()`, a token from `number_token()`, or a key from an iterator (those of a borrowed text that the caller owns, read unchanged, are not affected). To re-parse a string that the document holds, for example JSON embedded in a string value, copy the string into a `std::string` first and pass the copy; see [`read()`](https://json.nlohmann.me/api/basic_json_document/read/#notes) for the exact list.

Example: borrowed and owned documents, and when views become invalid

```
#include <iostream>
#include <string>
#include <utility>
#include <nlohmann/json_view.hpp>

using nlohmann::json_document;

int main()
{
    std::cout << std::boolalpha;

    // BORROWED: doc only points into `text`; `text` must outlive `doc`
    std::string text = R"({"a": 1})";
    json_document doc = json_document::parse(text);
    std::cout << doc.owns_source() << '\n'; // false

    // a view is valid as long as the document is alive, has not been
    // re-parsed (read()) or shrunk (shrink_to_fit()), and -- if borrowed --
    // the source text is alive
    nlohmann::json_view v = doc.root();
    std::cout << v.is_object() << '\n';

    // re-parsing the SAME document invalidates views taken before the call;
    // `v` above must not be used after this line
    doc.read(R"([1, 2, 3])");
    v = doc.root(); // take a fresh view instead
    std::cout << v.is_array() << '\n';

    // moving the document does not invalidate views: the node index is
    // heap-allocated and does not move with the document object
    json_document moved = std::move(doc);
    std::cout << v.is_array() << '\n';
}
```

Output:

```
false
true
true
true
```

## See also

- [Zero-copy JSON views](https://json.nlohmann.me/features/json_view/index.md) - overview
- [`basic_json_document`](https://json.nlohmann.me/api/basic_json_document/index.md) - the document that owns the parsed index
- [`owns_source()`](https://json.nlohmann.me/api/basic_json_document/owns_source/index.md) - whether a document borrows its source text

## Version history

- Added in version 3.13.0 unreleased.
