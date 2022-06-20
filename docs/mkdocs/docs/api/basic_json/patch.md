# <small>nlohmann::basic_json::</small>patch

```cpp
basic_json patch(const basic_json& json_patch) const;
```

[JSON Patch](http://jsonpatch.com) defines a JSON document structure for expressing a sequence of operations to apply to
a JSON document. With this function, a JSON Patch is applied to the current JSON value by executing all operations from
the patch.

## Parameters

`json_patch` (in)
:   JSON patch document

## Return value

patched document

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

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

Linear in the size of the JSON value and the length of the JSON patch. As usually only a fraction of the JSON value is
affected by the patch, the complexity can usually be neglected.

## Notes

The application of a patch is atomic: Either all operations succeed and the patched document is returned or an exception
is thrown. In any case, the original value is not changed: the patch is applied to a copy of the value.

## Examples

??? example

    The following code shows how a JSON patch is applied to a value.
     
    ```cpp
    --8<-- "examples/patch.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/patch.output"
    ```

## See also

- [RFC 6902 (JSON Patch)](https://tools.ietf.org/html/rfc6902)
- [RFC 6901 (JSON Pointer)](https://tools.ietf.org/html/rfc6901)
- [merge_patch](merge_patch.md) applies a JSON Merge Patch

## Version history

- Added in version 2.0.0.
