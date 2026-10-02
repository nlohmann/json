# <small>nlohmann::basic_json_view::</small>contains

```cpp
// (1)
bool contains(string_view_t key) const;
bool contains(const char* key) const;
bool contains(const string_t& key) const;

// (2)
bool contains(const json_pointer& ptr) const;
```

1. Checks whether the value is an object with a member with key `key`.
2. Checks whether a JSON pointer `ptr` can be resolved, starting at this value.

## Parameters

`key` (in)
:   key value to check its existence

`ptr` (in)
:   JSON pointer to check its existence

## Return value

1. `#!cpp true` if the value is an object and has a member with key `key`, `#!cpp false` otherwise
2. `#!cpp true` if `ptr` can be resolved to a value starting at this view, `#!cpp false` otherwise

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

1. Linear in the number of members: as for [`ordered_json`](../ordered_json.md), members are compared one after
   another, in document order, stopping at the first match. Each comparison first checks the key's length -- already
   known from the index, without reading the key bytes -- before comparing its content.
2. Linear in the number of reference tokens of `ptr` and, for each token, in the number of members of the object at
   that level or the index into the array -- as for [`operator[]`](operator[].md#complexity) and
   [`at`](at.md#complexity) with a JSON pointer.

## Notes

Overload 1 always returns `#!cpp false` when the value is not an object -- including a [discarded](is_discarded.md)
view.

!!! info "Postconditions"

    If `#!cpp v.contains(key)` returns `#!cpp true`, then `#!cpp v[key]` is not [discarded](is_discarded.md). If
    `#!cpp v.contains(ptr)` returns `#!cpp true`, then `#!cpp v[ptr]` is not discarded and `#!cpp v.at(ptr)` does not
    throw.

!!! info "Overload 2 never throws"

    Unlike [`BasicJsonType::contains(const json_pointer&)`](../basic_json/contains.md), which can throw for certain
    malformed pointers (for instance an empty array-index reference token), overload 2 never throws: a missing key,
    an out-of-range or malformed array index, a `#!cpp "-"` index, or a reference token used on a primitive all
    simply make it return `#!cpp false`.

## Examples

??? example "Example: (1) check with key"

    The example below counts how many of a batch of records carry an optional `retry_of` field, using `contains()`
    to check without ever materializing a single record of the batch.

    ```cpp
    --8<-- "examples/basic_json_view__contains.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_view__contains.output"
    ```

??? example "Example: (2) check with JSON pointer"

    The example below checks an optional, nested field with a JSON pointer, and shows two pointers that
    `#!cpp contains()` resolves to `#!cpp false` without throwing.

    ```cpp
    --8<-- "examples/basic_json_view__contains_json_pointer.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_view__contains_json_pointer.output"
    ```

## See also

- [find](find.md) - find a value in an object
- [count](count.md) - returns the number of occurrences of a key
- [at](at.md), [operator[]](operator[].md) - resolve a JSON pointer and throw, or return a discarded view
- [`BasicJsonType::contains`](../basic_json/contains.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0.
