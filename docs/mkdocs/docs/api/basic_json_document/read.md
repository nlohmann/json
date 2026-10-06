# <small>nlohmann::basic_json_document::</small>read

```cpp
template<typename InputType>
void read(InputType&& input,
         const bool allow_exceptions = true,
         const bool ignore_comments = false,
         const bool ignore_trailing_commas = false);
```

(Re-)parses `input` into `#!cpp *this`, discarding the document's previous value and reusing its memory (the node
index, the decoded-string buffer, and, if applicable, the owned copy of the text) rather than allocating a fresh
document. [`parse()`](parse.md) is implemented in terms of this function, applied to a default-constructed document.

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

## Exceptions

Same as [`parse`](parse.md#exceptions).

## Complexity

Linear in the length of the input.

## Notes

Every view taken from `#!cpp *this` before the call -- including the previous [`root()`](root.md) -- is invalidated,
whether or not the new parse succeeds; take fresh views from [`root()`](root.md) afterward.

`input` is borrowed or owned by the same rules as [`parse()`](parse.md#notes); a document can borrow on one call and
own on the next, since ownership is decided freshly each time.

Reusing a document matters most for large inputs: the operating system provides the memory of a fresh node index one
page at a time, and every page costs a page fault the first time it is written. On x86-64 Linux (4 KiB pages), parsing
a 55 MB document into a reused document took about 40 % less time than parsing it into a fresh one. Programs that parse
many documents of similar size should therefore keep one document and call `read()`.

## Examples

??? example

    The example below parses a sequence of messages into the same document, reusing its memory instead of allocating
    a new document for each one.

    ```cpp
    --8<-- "examples/basic_json_document__read.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_document__read.output"
    ```

## See also

- [parse](parse.md) - deserialize from a compatible input
- [root](root.md) - the view of the root value

## Version history

- Added in version 3.13.0.
