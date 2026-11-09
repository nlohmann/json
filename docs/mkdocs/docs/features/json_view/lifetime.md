# Ownership and lifetime

A document either **borrows** the text it was parsed from, or **owns** its own copy of it; call
[`owns_source()`](../../api/basic_json_document/owns_source.md) to find out which happened.
[`parse()`](../../api/basic_json_document/parse.md) decides this from the value category and type of its argument (an
lvalue `#!cpp std::string` is borrowed; an rvalue `#!cpp std::string` is moved in, owned without a copy; a stream is
read into an owned buffer; and so on — see [`parse`'s Notes](../../api/basic_json_document/parse.md#notes) for the
full table). [`parse_copy()`](../../api/basic_json_document/parse_copy.md) always owns a copy, regardless of the input.

!!! warning "A borrowed document depends on your buffer"

    If a document borrows its text, that text **must outlive the document** (and every view taken from it) and must
    stay **unmodified** for as long as the document exists, since floating-point values and unescaped strings are
    read from it lazily. Reading or writing through a view after the underlying buffer is gone is undefined behavior,
    exactly as it would be for a dangling `#!cpp std::string_view`.

## When a view is valid

A view is valid only while all of the following hold:

- the document is alive,
- the document has not been re-parsed since the view was taken (with
  [`read()`](../../api/basic_json_document/read.md) or [`parse()`](../../api/basic_json_document/parse.md) into it),
- the document has not had [`shrink_to_fit()`](../../api/basic_json_document/shrink_to_fit.md) called on it since, and
- if the document borrows its source text, that text is still alive and unmodified.

Moving the `basic_json_document<>` itself is fine and does **not** invalidate its views: the index is a separate heap
allocation that keeps its address across the move. Take a fresh view from
[`root()`](../../api/basic_json_document/root.md) whenever any of the other conditions above was not met. Edits of an
[editable document](editing.md) keep views valid, too; see [What stays valid](editing.md#what-stays-valid-and-what-an-edit-costs).

<div class="nj-fig-wrap" markdown>
--8<-- "images/json_view_lifetime.svg"
</div>

<p class="nj-caption" markdown>Four timelines of a document and its views, each bar showing when an object is alive or valid and when it dangles. Destroying the borrowed text, re-parsing, or shrinking the document invalidates the views taken before; moving the document does not.</p>

## Why views can dangle

A view can dangle, exactly like a `#!cpp std::string_view`: nothing stops you from using it after its document is
gone. This is deliberate. A view is two pointers and trivially copyable; making it safe (a `#!cpp std::shared_ptr` in
the document and a `#!cpp std::weak_ptr` in each view) would make it larger, add reference counting to every copy,
and a `lock()` to every access — exactly the costs the view exists to avoid. What is caught is the obvious case:
because a view dies with its document, [`root()`](../../api/basic_json_document/root.md) is not callable on a
temporary document: `#!cpp auto v = json_document::parse(text).root();` does not compile. Give the document a name
first.

The same holds for what a view hands out without copying: a string from
[`get_string()`](../../api/basic_json_view/get_string.md), a token from
[`number_token()`](../../api/basic_json_view/number_token.md), and [`string_view` members](reading.md#string_view-members)
of decoded structs are valid only as long as the document and, if it borrows, its source text.

??? example "Example: borrowed and owned documents, and when views become invalid"

    ```cpp
    --8<-- "examples/json_view_ownership.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/json_view_ownership.output"
    ```

## See also

- [Zero-copy JSON views](index.md) - overview
- [`basic_json_document`](../../api/basic_json_document/index.md) - the document that owns the parsed index
- [`owns_source()`](../../api/basic_json_document/owns_source.md) - whether a document borrows its source text

## Version history

- Added in version 3.13.0.
