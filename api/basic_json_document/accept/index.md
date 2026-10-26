# nlohmann::basic_json_document::accept

```
template<typename InputType>
static bool accept(InputType&& input,
                   const bool ignore_comments = false,
                   const bool ignore_trailing_commas = false);
```

Checks whether the input is valid JSON, accepting and rejecting exactly what [`BasicJsonType::accept()`](https://json.nlohmann.me/api/basic_json/accept/index.md) does, with the same options. Unlike [`parse()`](https://json.nlohmann.me/api/basic_json_document/parse/index.md), this function never throws an exception for invalid input, and the returned `bool` is the only result -- no document is returned.

The result is the same as that of `BasicJsonType::accept()` by design; the difference is how the check is made. This function runs the document's index builder (and discards the index), while `BasicJsonType::accept()` runs the SAX parser with a handler that ignores every event. Use this one if you go on to parse the same input with [`parse()`](https://json.nlohmann.me/api/basic_json_document/parse/index.md) anyway, so that both use the same code; either is fine for a plain yes/no answer.

## Template parameters

`InputType` : A compatible input; see [`parse`](https://json.nlohmann.me/api/basic_json_document/parse/#template-parameters).

## Parameters

`input` (in) : Input to check.

`ignore_comments` (in) : whether comments should be ignored and treated like whitespace (`true`) or yield a parse error (`false`); (optional, `false` by default)

`ignore_trailing_commas` (in) : whether trailing commas in arrays or objects should be ignored and treated like whitespace (`true`) or yield a parse error (`false`); (optional, `false` by default)

## Return value

Whether the input is valid JSON.

## Exception safety

Strong guarantee: this function itself never throws for an invalid input; it can only throw what allocating the input's own copy (for inputs that are always read into a buffer) throws.

## Complexity

Linear in the length of the input.

## Notes

An integer argument that is not a `bool` where the flags are expected, such as `accept(ptr, len)`, does not compile; see [`parse`](https://json.nlohmann.me/api/basic_json_document/parse/#notes).

## Examples

Example

```
#include <iostream>
#include <nlohmann/json.hpp>
#include <nlohmann/json_view.hpp>

using nlohmann::json_document;

int main()
{
    std::cout << std::boolalpha;

    // accept() behaves exactly like basic_json::accept(): the same inputs are
    // accepted or rejected, with the same ignore_comments/ignore_trailing_commas
    // options
    std::cout << json_document::accept(R"({"a": 1})") << '\n';
    std::cout << json_document::accept(R"({"a": 1,})") << '\n'; // trailing comma: rejected by default
    std::cout << json_document::accept(R"({"a": 1,})", false, true) << '\n'; // ignore_trailing_commas

    std::cout << (json_document::accept(R"({"a": 1})") == nlohmann::json::accept(R"({"a": 1})")) << '\n';
}
```

Output:

```
true
false
true
true
```

## See also

- [parse](https://json.nlohmann.me/api/basic_json_document/parse/index.md) - deserialize from a compatible input
- [`BasicJsonType::accept`](https://json.nlohmann.me/api/basic_json/accept/index.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0 unreleased.
