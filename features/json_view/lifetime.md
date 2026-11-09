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
<svg class="nj-fig nj-jsonview " viewBox="0 0 840 572" role="img" aria-labelledby="fig-jvt-title fig-jvt-title-d" xmlns="http://www.w3.org/2000/svg">
<title id="fig-jvt-title">When a json_view becomes invalid</title>
<desc id="fig-jvt-title-d">Four timelines. First: a document borrows a std::string; when the string is destroyed, the document and every view taken from it dangle. Second: doc.read() re-parses the document; views taken before are invalid, a fresh view from root() is valid. Third: doc.shrink_to_fit() has the same effect. Fourth: moving the document does not invalidate its views; destroying the moved-to document does.</desc>
<defs>
<marker id="jvt-bad" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path class="nj-jsonview-c-bad nj-jsonview-head" d="M0 1 L10 5 L0 9 z"/></marker>
</defs>
<rect class="nj-jsonview-bar nj-jsonview-c-struct" x="210" y="12" width="34" height="12" rx="3"/>
<text class="nj-jsonview-note" x="252" y="23" xml:space="preserve">alive / valid</text>
<rect class="nj-jsonview-bad" x="370" y="12" width="34" height="12" rx="3"/>
<text class="nj-jsonview-note" x="412" y="23" xml:space="preserve">dangling: using it is undefined behavior</text>
<path class="nj-jsonview-arr nj-jsonview-c-line" d="M210 44 L820 44"/>
<text class="nj-jsonview-tiny" x="820" y="38" text-anchor="end" xml:space="preserve">time →</text>
<text class="nj-jsonview-h nj-jsonview-sm2" x="16" y="74" xml:space="preserve">The borrowed text is destroyed</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="198" y="99" text-anchor="end" xml:space="preserve">std::string text</text>
<rect class="nj-jsonview-bar nj-jsonview-c-struct" x="210" y="87" width="260" height="16" rx="3"/>
<text class="nj-jsonview-mono nj-jsonview-sm" x="198" y="127" text-anchor="end" xml:space="preserve">json_document doc</text>
<rect class="nj-jsonview-bar nj-jsonview-c-struct" x="270" y="115" width="200" height="16" rx="3"/>
<rect class="nj-jsonview-bad" x="470" y="115" width="350" height="16" rx="3"/>
<text class="nj-jsonview-mono nj-jsonview-sm" x="198" y="155" text-anchor="end" xml:space="preserve">json_view v</text>
<rect class="nj-jsonview-bar nj-jsonview-c-struct" x="330" y="143" width="140" height="16" rx="3"/>
<rect class="nj-jsonview-bad" x="470" y="143" width="350" height="16" rx="3"/>
<path class="nj-jsonview-evt" d="M470 82 V168"/>
<text class="nj-jsonview-tiny nj-jsonview-c-bad" x="474" y="80" xml:space="preserve">text destroyed</text>
<text class="nj-jsonview-note nj-jsonview-onbad" x="476" y="155" xml:space="preserve">every view, and the document itself</text>
<text class="nj-jsonview-h nj-jsonview-sm2" x="16" y="202" xml:space="preserve">The document is re-parsed</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="198" y="227" text-anchor="end" xml:space="preserve">json_document doc</text>
<rect class="nj-jsonview-bar nj-jsonview-c-struct" x="210" y="215" width="610" height="16" rx="3"/>
<text class="nj-jsonview-mono nj-jsonview-sm" x="198" y="255" text-anchor="end" xml:space="preserve">json_view v</text>
<rect class="nj-jsonview-bar nj-jsonview-c-struct" x="270" y="243" width="200" height="16" rx="3"/>
<rect class="nj-jsonview-bad" x="470" y="243" width="350" height="16" rx="3"/>
<text class="nj-jsonview-mono nj-jsonview-sm" x="198" y="283" text-anchor="end" xml:space="preserve">v = doc.root()</text>
<rect class="nj-jsonview-bar nj-jsonview-c-struct" x="530" y="271" width="290" height="16" rx="3"/>
<path class="nj-jsonview-evt" d="M470 210 V296"/>
<text class="nj-jsonview-tiny nj-jsonview-c-bad" x="474" y="208" xml:space="preserve">doc.read(other)</text>
<text class="nj-jsonview-note nj-jsonview-onbad" x="476" y="255" xml:space="preserve">views taken before</text>
<text class="nj-jsonview-note nj-jsonview-onok" x="536" y="283" xml:space="preserve">a fresh view is valid again</text>
<text class="nj-jsonview-h nj-jsonview-sm2" x="16" y="330" xml:space="preserve">The document is shrunk</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="198" y="355" text-anchor="end" xml:space="preserve">json_document doc</text>
<rect class="nj-jsonview-bar nj-jsonview-c-struct" x="210" y="343" width="610" height="16" rx="3"/>
<text class="nj-jsonview-mono nj-jsonview-sm" x="198" y="383" text-anchor="end" xml:space="preserve">json_view v</text>
<rect class="nj-jsonview-bar nj-jsonview-c-struct" x="270" y="371" width="200" height="16" rx="3"/>
<rect class="nj-jsonview-bad" x="470" y="371" width="350" height="16" rx="3"/>
<text class="nj-jsonview-mono nj-jsonview-sm" x="198" y="411" text-anchor="end" xml:space="preserve">v = doc.root()</text>
<rect class="nj-jsonview-bar nj-jsonview-c-struct" x="530" y="399" width="290" height="16" rx="3"/>
<path class="nj-jsonview-evt" d="M470 338 V424"/>
<text class="nj-jsonview-tiny nj-jsonview-c-bad" x="474" y="336" xml:space="preserve">doc.shrink_to_fit()</text>
<text class="nj-jsonview-note nj-jsonview-onbad" x="476" y="383" xml:space="preserve">views taken before</text>
<text class="nj-jsonview-note nj-jsonview-onok" x="536" y="411" xml:space="preserve">a fresh view is valid again</text>
<text class="nj-jsonview-h nj-jsonview-sm2" x="16" y="458" xml:space="preserve">The document is moved, then destroyed</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="198" y="483" text-anchor="end" xml:space="preserve">json_document doc</text>
<rect class="nj-jsonview-bar nj-jsonview-c-struct" x="210" y="471" width="210" height="16" rx="3"/>
<text class="nj-jsonview-mono nj-jsonview-sm" x="198" y="511" text-anchor="end" xml:space="preserve">moved = std::move(doc)</text>
<rect class="nj-jsonview-bar nj-jsonview-c-struct" x="420" y="499" width="260" height="16" rx="3"/>
<text class="nj-jsonview-mono nj-jsonview-sm" x="198" y="539" text-anchor="end" xml:space="preserve">json_view v</text>
<rect class="nj-jsonview-bar nj-jsonview-c-struct" x="270" y="527" width="410" height="16" rx="3"/>
<rect class="nj-jsonview-bad" x="680" y="527" width="140" height="16" rx="3"/>
<path class="nj-jsonview-evt nj-jsonview-evt--ok" d="M420 466 V552"/>
<text class="nj-jsonview-tiny" x="424" y="464" xml:space="preserve">std::move: views stay valid</text>
<path class="nj-jsonview-evt" d="M680 466 V552"/>
<text class="nj-jsonview-tiny nj-jsonview-c-bad" x="684" y="464" xml:space="preserve">moved is destroyed</text>
</svg>

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

    ```json
    false
    true
    true
    true
    
    ```

## See also

- [Zero-copy JSON views](index.md) - overview
- [`basic_json_document`](../../api/basic_json_document/index.md) - the document that owns the parsed index
- [`owns_source()`](../../api/basic_json_document/owns_source.md) - whether a document borrows its source text

## Version history

- Added in version 3.13.0.
