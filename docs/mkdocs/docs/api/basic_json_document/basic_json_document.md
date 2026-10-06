# <small>nlohmann::basic_json_document::</small>basic_json_document

```cpp
// (1)
basic_json_document() = default;

// (2)
basic_json_document(basic_json_document&& other) noexcept = default;

// (3)
basic_json_document(const basic_json_document&) = delete;
```

1. Creates an empty (discarded) document: [`root()`](root.md) returns a discarded view, and
   [`is_discarded()`](is_discarded.md) is `#!cpp true`.
2. Move constructor. Takes over `other`'s index and, if owned, its text; `other` is left as an empty document. Views
   taken from `other` before the move remain valid, because the index is heap-allocated independently of the
   `basic_json_document` object.
3. `basic_json_document` is move-only. Copying is disabled because it would either duplicate a potentially large index
   and text, or leave two documents claiming to borrow the same buffer.

## Parameters

`other` (in)
:   another document to move the index and text from

## Exception safety

No-throw guarantee: the default and move constructors never throw exceptions.

## Complexity

Constant, for the default and move constructors.

## Examples

??? example

    The example below shows the default constructor and demonstrates that `basic_json_document` is move-only.

    ```cpp
    --8<-- "examples/basic_json_document__basic_json_document.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_document__basic_json_document.output"
    ```

## See also

- [parse](parse.md) - deserialize from a compatible input
- [is_discarded](is_discarded.md) - return whether the last parse failed

## Version history

- Added in version 3.13.0.
