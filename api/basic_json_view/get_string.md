# <small>nlohmann::basic_json_view::</small>get_string

```cpp
string_view_t get_string() const;
```

Returns the string value as a [`string_view_t`](index.md#member-types), without copying it.

## Return value

The string, as a [`string_view_t`](index.md#member-types) that points either into the document's
[`source()`](../basic_json_document/source.md) text (a string with no escape sequences), or into the document's own
buffer of decoded strings (a string that contains escape sequences, such as `#!json "\n"` or `#!json "\u00e9"`, which
had to be decoded once when the document was parsed).

## Exception safety

Strong guarantee: there are no changes to the view or the document it refers to.

## Exceptions

Throws [`type_error.302`](../../home/exceptions.md#jsonexceptiontype_error302) if the value is not a string; example:
`"type must be string, but is array"`.

This exception does not carry a [`JSON_DIAGNOSTICS`](../macros/json_diagnostics.md) path: the view has no
`BasicJsonType` value to point at, so the exception is created without one, even if `BasicJsonType` was built with
`JSON_DIAGNOSTICS` enabled.

## Complexity

Constant.

## Notes

`basic_json_view` has no `BasicJsonType` value stored anywhere, so unlike `BasicJsonType`, it has no `get_ref()` to
hand out a reference to a stored `string_t`. `get_string()` (equivalently, [`get<string_view_t>()`](get.md)) is the
zero-copy alternative: [`BasicJsonType::get_ref<const string_t&>()`](../basic_json/get_ref.md) is its closest
counterpart, except that it returns a view instead of a reference to a value that must already exist.

`get_string()` borrows the string: nothing is copied, whereas [`get<std::string>()`](get.md) copies it. For a borrowed
document, the returned [`string_view_t`](index.md#member-types) is valid as long as the caller's buffer; for an owned
one, as long as the document.

The returned [`string_view_t`](index.md#member-types) is valid exactly as long as the view that produced it -- see the
[validity rules](index.md) of `basic_json_view` -- and, for a string with no escapes, for as long as the document's
source text, which for a borrowed document must remain valid **and unmodified** for as long as the document exists,
since floating-point values and unescaped strings are read from the source lazily.

## Examples

??? example

    The example below pulls one field out of a JSON text that stands in for a large API response, and shows that no
    `#!cpp std::string` was allocated for it: the returned view still points inside the original buffer. A field that
    contains an escape sequence cannot point into the original text -- it was decoded once into the document's own
    buffer instead -- but still avoids a per-field allocation.

    ```cpp
    #include <iostream>
    #include <nlohmann/json_view.hpp>
    #include <string>
    
    using json_document = nlohmann::json_document;
    using json_view = nlohmann::json_view;
    
    int main()
    {
        // a "large response" stand-in: only the "id" field is ever read out of it
        const std::string text =
            R"({"id": "8f14e45f-ceea-467e-bb92-963f5e3c7a08", "note": "created via API\n", "payload": "..."})";
        const json_document doc = json_document::parse(text);
        const json_view response = doc.root();
    
        const json_view::string_view_t id = response["id"].get_string();
        std::cout << id << '\n';
    
        // no std::string was allocated for "id": its bytes still live inside
        // the original buffer, so id's data lies inside [text.data(),
        // text.data() + text.size())
        const bool id_in_source = id.data() >= text.data() && id.data() + id.size() <= text.data() + text.size();
        std::cout << std::boolalpha << id_in_source << '\n';
    
        // "note" contains an escape sequence ('\n'), so it was decoded once
        // into the document's own buffer -- get_string() still avoids a copy
        // into a new std::string, but the bytes no longer live inside "text"
        const json_view::string_view_t note = response["note"].get_string();
        const bool note_in_source = note.data() >= text.data() && note.data() + note.size() <= text.data() + text.size();
        std::cout << std::boolalpha << note_in_source << '\n';
    }
    
    ```

    Output:

    ```json
    8f14e45f-ceea-467e-bb92-963f5e3c7a08
    true
    false
    
    ```

## See also

- [get](get.md) - convert the value to a given type (`#!cpp get<string_view_t>()` is equivalent to this function)
- [number_token](number_token.md) - a number's token text, without a copy
- [`BasicJsonType::get_ref`](../basic_json/get_ref.md) - the closest counterpart of `basic_json`

## Version history

- Added in version 3.13.0.
