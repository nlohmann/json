# <small>nlohmann::basic_json_document::</small>accept

```cpp
template<typename InputType>
static bool accept(InputType&& input,
                   const bool ignore_comments = false,
                   const bool ignore_trailing_commas = false);
```

Checks whether the input is valid JSON, accepting and rejecting exactly what
[`BasicJsonType::accept()`](../basic_json/accept.md) does, with the same options. Unlike [`parse()`](parse.md), this
function never throws an exception for invalid input, and the returned `#!cpp bool` is the only result -- no document
is returned.

## Template parameters

`InputType`
:   A compatible input; see [`parse`](parse.md#template-parameters).

## Parameters

`input` (in)
:   Input to check.

`ignore_comments` (in)
:   whether comments should be ignored and treated like whitespace (`#!cpp true`) or yield a parse error
    (`#!cpp false`); (optional, `#!cpp false` by default)

`ignore_trailing_commas` (in)
:   whether trailing commas in arrays or objects should be ignored and treated like whitespace (`#!cpp true`) or
    yield a parse error (`#!cpp false`); (optional, `#!cpp false` by default)

## Return value

Whether the input is valid JSON.

## Exception safety

Strong guarantee: this function itself never throws for an invalid input; it can only throw what allocating the
input's own copy (for inputs that are always read into a buffer) throws.

## Complexity

Linear in the length of the input.

## Examples

??? example

    ```cpp
    --8<-- "examples/basic_json_document__accept.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_document__accept.output"
    ```

## See also

- [parse](parse.md) - deserialize from a compatible input
- [`BasicJsonType::accept`](../basic_json/accept.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0.
