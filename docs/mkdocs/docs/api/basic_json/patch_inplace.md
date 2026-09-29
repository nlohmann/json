# <small>nlohmann::basic_json::</small>patch_inplace

```cpp
void patch_inplace(const basic_json& json_patch);
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
  mandatory attributes are missing); example: `"operation 'add' must have member 'path'"`.
- Throws [`out_of_range.401`](../../home/exceptions.md#jsonexceptionout_of_range401) if an array index is out of range.
- Throws [`parse_error.106`](../../home/exceptions.md#jsonexceptionparse_error106) if an array index in a "path" or
  "from" member begins with '0'; example: `"array index '01' must not begin with '0'"`.
- Throws [`parse_error.107`](../../home/exceptions.md#jsonexceptionparse_error107) if a "path" or "from" member is not
  empty and does not begin with a slash (`/`); example: `"JSON pointer must be empty or begin with '/' - was: 'a'"`.
- Throws [`parse_error.108`](../../home/exceptions.md#jsonexceptionparse_error108) if a tilde (`~`) in a "path" or
  "from" member is not followed by `0` or `1`; example: `"escape character '~' must be followed with '0' or '1'"`.
- Throws [`parse_error.109`](../../home/exceptions.md#jsonexceptionparse_error109) if an array index in a "path" or
  "from" member is not a number; example: `"array index 'foo' is not a number"`.
- Throws [`out_of_range.402`](../../home/exceptions.md#jsonexceptionout_of_range402) if the array index `-` is used
  where an existing element is required (the "path" of "replace", the "from" of "move" and "copy"); example:
  `"array index '-' (3) is out of range"`.
- Throws [`out_of_range.403`](../../home/exceptions.md#jsonexceptionout_of_range403) if a JSON pointer inside the patch
  could not be resolved successfully in the current JSON value; example: `"key baz not found"`.
- Throws [`out_of_range.404`](../../home/exceptions.md#jsonexceptionout_of_range404) if a reference token of a JSON
  pointer inside the patch cannot be resolved, e.g., `-` in a "remove" operation or `1a` for an array; example:
  `"unresolved reference token '-'"`.
- Throws [`out_of_range.405`](../../home/exceptions.md#jsonexceptionout_of_range405) if JSON pointer has no parent
  ("add", "remove", "move")
- Throws [`out_of_range.411`](../../home/exceptions.md#jsonexceptionout_of_range411) if an "add" operation's target
  location has a parent that is neither an object nor an array.
- Throws [`out_of_range.413`](../../home/exceptions.md#jsonexceptionout_of_range413) if a "remove" operation's target
  location has a parent that is neither an object nor an array.
- Throws [`out_of_range.414`](../../home/exceptions.md#jsonexceptionout_of_range414) if a "move" operation's "from"
  location is a proper prefix of its "path" location.
- Throws [`other_error.501`](../../home/exceptions.md#jsonexceptionother_error501) if "test" operation was
  unsuccessful.

## Complexity

Linear in the size of the JSON value and the length of the JSON patch. As usually the patch affects only a fraction of
the JSON value, the complexity can usually be neglected.

## Notes

Unlike [`patch`](patch.md), `patch_inplace` applies the operation "in place" and no copy of the JSON value is created.
That makes it faster for large documents by avoiding the copy. However, the JSON value might be corrupted if the
function throws an exception.

## Examples

??? example "Example: apply a JSON patch in place"

    The following code shows how a JSON patch is applied to a value.
     
    ```cpp
    --8<-- "examples/patch_inplace.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/patch_inplace.output"
    ```

??? example "Example: out_of_range.403 exception with a partially applied patch"

    The following code shows a patch whose first operation succeeds and whose second operation fails. Because
    `patch_inplace` applies each operation directly to the value, the first operation's effect is still visible after
    the exception is caught, unlike [`patch`](patch.md).

    ```cpp
    --8<-- "examples/patch_inplace__exception.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/patch_inplace__exception.output"
    ```

## See also

- [RFC 6902 (JSON Patch)](https://tools.ietf.org/html/rfc6902)
- [RFC 6901 (JSON Pointer)](https://tools.ietf.org/html/rfc6901)
- [patch](patch.md) applies a JSON Patch
- [merge_patch](merge_patch.md) applies a JSON Merge Patch

## Version history

- Added in version 3.11.0.
- Added [`out_of_range.411`](../../home/exceptions.md#jsonexceptionout_of_range411) and stopped relying on an internal assertion when an "add" operation's
  target location has a non-object/non-array parent in version 3.13.0.
- Added [`out_of_range.413`](../../home/exceptions.md#jsonexceptionout_of_range413) and stopped silently ignoring a "remove" operation whose target
  location has a non-object/non-array parent in version 3.13.0.
- Added [`out_of_range.414`](../../home/exceptions.md#jsonexceptionout_of_range414) and rejected a "move" operation whose "from" location is a proper
  prefix of its "path" location instead of silently producing a corrupted result in version 3.13.0.
