# <small>nlohmann::basic_json_document::</small>parse_copy

```cpp
template<typename InputType>
static basic_json_document parse_copy(InputType&& input,
                                      const bool allow_exceptions = true,
                                      const bool ignore_comments = false,
                                      const bool ignore_trailing_commas = false);
```

Deserialize from a compatible input, always taking the document's own copy of it, regardless of the value category or
type of `input`. Unlike [`parse()`](parse.md), the returned document never depends on `input` staying alive.

## Template parameters

`InputType`
:   A compatible input; see [`parse`](parse.md#template-parameters).

## Parameters

`input` (in)
:   Input to parse from.

`allow_exceptions` (in)
:   whether to throw exceptions in case of a parse error (optional, `#!cpp true` by default)

`ignore_comments` (in)
:   whether comments should be ignored and treated like whitespace (`#!cpp true`) or yield a parse error
    (`#!cpp false`); (optional, `#!cpp false` by default)

`ignore_trailing_commas` (in)
:   whether trailing commas in arrays or objects should be ignored and treated like whitespace (`#!cpp true`) or
    yield a parse error (`#!cpp false`); (optional, `#!cpp false` by default)

## Return value

The parsed document, with [`owns_source()`](owns_source.md) `#!cpp true`. If `allow_exceptions` is `#!cpp false` and
the input is not valid JSON, the returned document is discarded; see [`is_discarded`](is_discarded.md).

## Exceptions

Same as [`parse`](parse.md#exceptions).

## Complexity

Linear in the length of the input.

## Notes

`parse_copy()` accepts and rejects exactly what [`parse()`](parse.md) does, and classifies numbers the same way; it
only differs in that the input is always copied rather than sometimes borrowed. Prefer [`parse()`](parse.md) when the
input's lifetime already covers the document's, since it avoids the copy for borrowed inputs.

An integer argument that is not a `#!cpp bool` where the flags are expected, such as `#!cpp parse_copy(ptr, len)`, does not
compile; see [`parse`](parse.md#notes).

## Examples

??? example

    The example below returns a document from a function whose local buffer would otherwise not outlive it.

    ```cpp
    #include <iostream>
    #include <nlohmann/json_view.hpp>
    
    using json_document = nlohmann::json_document;
    
    json_document parse_from_temporary_buffer()
    {
        char buffer[] = R"({"a": 1})";
        // parse() would borrow `buffer`, which is about to go out of scope;
        // parse_copy() takes its own copy instead, so the returned document does
        // not depend on `buffer` afterward
        return json_document::parse_copy(buffer);
    }
    
    int main()
    {
        std::cout << std::boolalpha;
    
        json_document doc = parse_from_temporary_buffer();
        std::cout << doc.owns_source() << '\n';
        std::cout << doc.root().is_object() << '\n';
    }
    
    ```

    Output:

    ```json
    true
    true
    
    ```

## See also

- [parse](parse.md) - deserialize from a compatible input, borrowing it where possible
- [owns_source](owns_source.md) - return whether the document holds its own copy of the text

## Version history

- Added in version 3.13.0.
