# JSON Patch and Diff

## Patches

JSON Patch ([RFC 6902](https://tools.ietf.org/html/rfc6902)) defines a JSON document structure for expressing a sequence
of operations to apply to a JSON document. Operations address locations in the document using
[JSON Pointer](json_pointer.md) paths. With the [`patch`](../api/basic_json/patch.md) function, a JSON Patch is applied
to the current JSON value by executing all operations from the patch, yielding the patched document as a new value.

!!! tip "Applying a patch without copying"

    [`patch`](../api/basic_json/patch.md) leaves the original value unchanged and returns the patched result as a copy.
    If the document is large and the original value is no longer needed,
    [`patch_inplace`](../api/basic_json/patch_inplace.md) applies the same operations in place instead.

!!! note "Duplicate member names"

    Duplicate member names inside an operation object are resolved by the parser before the patch is applied (the last
    one is kept, see [`object_t`](../api/basic_json/object_t.md#behavior)), so
    `#!json {"op": "add", "op": "remove", "path": "/a"}` is a `remove` operation.

??? example "Example: apply a JSON Patch"

    The following code shows how a JSON patch is applied to a value.

    ```cpp
    --8<-- "examples/patch.cpp"
    ```
    
    Output:

    ```json
    --8<-- "examples/patch.output"
    ```

## Diff

The library can also calculate a JSON patch (i.e., a **diff**) given two JSON values with the
[`diff`](../api/basic_json/diff.md) function.

```mermaid
flowchart LR
    S["source"] -->|"diff(source, target)"| P["patch"]
    S -->|"source.patch(patch)"| T["target"]
    P -.->|"applied to source, yields"| T
```

!!! success "Invariant"

    For two JSON values *source* and *target*, the following code yields true:

    ```cpp
    source.patch(diff(source, target)) == target;
    ```

    The equality holds up to [`operator==`](../api/basic_json/operator_eq.md), with these exceptions:

    - `NaN` and [discarded](../api/basic_json/is_discarded.md) values are not equal to themselves, so the invariant
      cannot hold for them. `diff` emits a `replace` operation for such a value, and a `NaN` in a patch is serialized
      as `#!json null`.
    - Numbers that compare equal produce no operation even if their types differ: `diff(1, 1.0)`, `diff(1u, 1)`, and
      `diff(0.0, -0.0)` return `#!json []`, so the patched value keeps the number type of *source*.
    - A [binary value](binary_values.md) in a patch is serialized as an object
      (`#!json {"bytes":[...],"subtype":null}`), so a patch that was dumped and parsed again no longer holds a binary
      value.

??? example "Example: create a JSON Patch from the difference of two values"

    The following code shows how a JSON patch is created as a diff for two JSON values.

    ```cpp
    --8<-- "examples/diff.cpp"
    ```
    
    Output:

    ```json
    --8<-- "examples/diff.output"
    ```

## See also

- [JSON Pointer](json_pointer.md) - the addressing scheme used for patch paths
- [JSON Merge Patch](merge_patch.md) - a simpler, less expressive alternative patch format
- [`patch`](../api/basic_json/patch.md) - apply a JSON Patch, returning the result as a copy
- [`patch_inplace`](../api/basic_json/patch_inplace.md) - apply a JSON Patch without copying
- [`diff`](../api/basic_json/diff.md) - compute a JSON Patch from two values
