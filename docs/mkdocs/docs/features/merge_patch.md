# JSON Merge Patch

The library supports JSON Merge Patch ([RFC 7386](https://tools.ietf.org/html/rfc7386)) as a patch format.
The merge patch format is primarily intended for use with the HTTP PATCH method as a means of describing a set of
modifications to a target resource's content. This function applies a merge patch to the current JSON value.

Instead of using [JSON Pointer](json_pointer.md) to specify values to be manipulated, it describes the changes using a
syntax that closely mimics the document being modified. Unlike [JSON Patch](json_patch.md), a JSON Merge Patch cannot
express every kind of change (e.g., it cannot reorder array elements or remove a specific array element), but it is
easier to read and write for object-shaped documents.

??? example

    The following code shows how a JSON Merge Patch is applied to a JSON document.

    ```cpp
    --8<-- "examples/merge_patch.cpp"
    ```
    
    Output:

    ```json
    --8<-- "examples/merge_patch.output"
    ```

## See also

- [JSON Patch and Diff](json_patch.md) - a more expressive alternative that describes a sequence of operations
- [JSON Pointer](json_pointer.md) - the addressing scheme used by JSON Patch
- Function [`merge_patch`](../api/basic_json/merge_patch.md)
