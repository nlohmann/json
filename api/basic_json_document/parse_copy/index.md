# nlohmann::basic_json_document::parse_copy

```
template<typename InputType>
static basic_json_document parse_copy(InputType&& input,
                                      const bool allow_exceptions = true,
                                      const bool ignore_comments = false,
                                      const bool ignore_trailing_commas = false);
```

Deserialize from a compatible input, always taking the document's own copy of it, regardless of the value category or type of `input`. Unlike [`parse()`](https://json.nlohmann.me/api/basic_json_document/parse/index.md), the returned document never depends on `input` staying alive.

## Template parameters

`InputType` : A compatible input; see [`parse`](https://json.nlohmann.me/api/basic_json_document/parse/#template-parameters).

## Parameters

`input` (in) : Input to parse from.

`allow_exceptions` (in) : whether to throw exceptions in case of a parse error (optional, `true` by default)

`ignore_comments` (in) : whether comments should be ignored and treated like whitespace (`true`) or yield a parse error (`false`); (optional, `false` by default)

`ignore_trailing_commas` (in) : whether trailing commas in arrays or objects should be ignored and treated like whitespace (`true`) or yield a parse error (`false`); (optional, `false` by default)

## Return value

The parsed document, with [`owns_source()`](https://json.nlohmann.me/api/basic_json_document/owns_source/index.md) `true`. If `allow_exceptions` is `false` and the input is not valid JSON, the returned document is discarded; see [`is_discarded`](https://json.nlohmann.me/api/basic_json_document/is_discarded/index.md).

## Exceptions

Same as [`parse`](https://json.nlohmann.me/api/basic_json_document/parse/#exceptions).

## Complexity

Linear in the length of the input.

## Notes

`parse_copy()` accepts and rejects exactly what [`parse()`](https://json.nlohmann.me/api/basic_json_document/parse/index.md) does, and classifies numbers the same way; it only differs in that the input is always copied rather than sometimes borrowed. Prefer [`parse()`](https://json.nlohmann.me/api/basic_json_document/parse/index.md) when the input's lifetime already covers the document's, since it avoids the copy for borrowed inputs.

An integer argument that is not a `bool` where the flags are expected, such as `parse_copy(ptr, len)`, does not compile; see [`parse`](https://json.nlohmann.me/api/basic_json_document/parse/#notes).

## Examples

Example

The example below returns a document from a function whose local buffer would otherwise not outlive it.

```
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

```
true
true
```

## See also

- [parse](https://json.nlohmann.me/api/basic_json_document/parse/index.md) - deserialize from a compatible input, borrowing it where possible
- [owns_source](https://json.nlohmann.me/api/basic_json_document/owns_source/index.md) - return whether the document holds its own copy of the text

## Version history

- Added in version 3.13.0 unreleased.
