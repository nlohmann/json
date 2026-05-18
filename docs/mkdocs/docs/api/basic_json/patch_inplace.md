# <small>nlohmann::basic_json::</small>patch_inplace

```cpp
void patch_inplace(const basic_json& json_patch) const;
```

[JSON Patch](http://jsonpatch.com) defines a JSON document structure for expressing a sequence of operations to apply to
a JSON document. With this function, a JSON Patch is applied to the current JSON value by executing all operations from
the patch. This function applies a JSON patch in place and returns void.

## Parameters

`json_patch` (in)
:   JSON patch document

## Exception safety

No guarantees, value may be corrupted by an unsuccessful patch operation.

## Exceptions

- Throws [`parse_error.104`](../../home/exceptions.md#jsonexceptionparse_error104) if the JSON patch does not consist of
  an array of objects.
- Throws [`parse_error.105`](../../home/exceptions.md#jsonexceptionparse_error105) if the JSON patch is malformed (e.g.,
  mandatory attributes are missing); example: `"operation add must have member path"`.
- Throws [`out_of_range.401`](../../home/exceptions.md#jsonexceptionout_of_range401) if an array index is out of range.
- Throws [`out_of_range.403`](../../home/exceptions.md#jsonexceptionout_of_range403) if a JSON pointer inside the patch
  could not be resolved successfully in the current JSON value; example: `"key baz not found"`.
- Throws [`out_of_range.405`](../../home/exceptions.md#jsonexceptionout_of_range405) if JSON pointer has no parent
  ("add", "remove", "move")
- Throws [`out_of_range.501`](../../home/exceptions.md#jsonexceptionother_error501) if "test" operation was
  unsuccessful.

## Complexity

Linear in the size of the JSON value and the length of the JSON patch. As usually the patch affects only a fraction of
the JSON value, the complexity can usually be neglected.

## Notes

Unlike [`patch`](patch.md), `patch_inplace` applies the operation "in place" and no copy of the JSON value is created.
That makes it faster for large documents by avoiding the copy. However, the JSON value might be corrupted if the
function throws an exception.

## Examples

??? example

    The following code shows how a JSON patch is applied to a value.
     
    ```cpp
    --8<-- "examples/patch_inplace.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/patch_inplace.output"
    ```

## See also

- [RFC 6902 (JSON Patch)](https://tools.ietf.org/html/rfc6902)
- [RFC 6901 (JSON Pointer)](https://tools.ietf.org/html/rfc6901)
- [patch](patch.md) applies a JSON Merge Patch
- [merge_patch](merge_patch.md) applies a JSON Merge Patch

## Version history

- Added in version 3.11.0.
