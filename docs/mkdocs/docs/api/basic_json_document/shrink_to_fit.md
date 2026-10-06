# <small>nlohmann::basic_json_document::</small>shrink_to_fit

```cpp
void shrink_to_fit();
```

Releases capacity that is no longer needed, both of the node index and of the buffer for decoded strings (strings that
contained escape sequences), e.g. after [`read()`](read.md) replaced a large document with a much smaller one. Like
`#!cpp std::vector::shrink_to_fit()`, this is a non-binding request: the library may keep more capacity than strictly
necessary.

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes to the document.

## Exceptions

May throw `#!cpp std::bad_alloc` if the reallocation fails; on exception, the document is unchanged.

## Complexity

Linear in [`node_count()`](node_count.md) plus the length of the decoded strings.

## Notes

!!! warning "Invalidates views"

    Unlike moving the document, `shrink_to_fit()` **invalidates every view taken from this document before the
    call**, including a previously obtained [`root()`](root.md): the node index is moved into a new, smaller
    allocation, and the old one is freed. Take a fresh view from [`root()`](root.md) after calling this function.

This is unlike `#!cpp std::vector::shrink_to_fit()`, which promises nothing about validity but in practice often
leaves iterators alone when it did not need to reallocate; here, an implementation that avoids a reallocation when
possible would be an internal optimization only, not a guarantee to rely on.

## Examples

??? example

    ```cpp
    --8<-- "examples/basic_json_document__shrink_to_fit.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_document__shrink_to_fit.output"
    ```

## See also

- [node_count](node_count.md) - the number of index entries
- [memory_usage](memory_usage.md) - the number of bytes held by the document
- [root](root.md) - the view of the root value

## Version history

- Added in version 3.13.0.
