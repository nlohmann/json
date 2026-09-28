# <small>nlohmann::basic_json::</small>merge_diff

```cpp
static basic_json merge_diff(const basic_json& source,
                             const basic_json& target);
```

Creates a [JSON Merge Patch](https://tools.ietf.org/html/rfc7396) so that value `source` can be changed into the value
`target` by calling the [`merge_patch`](merge_patch.md) function. The patch contains only what differs: changed and
added members with their new values, and removed members with the value `#!json null`. Nested objects are compared
member by member; any other value that differs, including an array, is replaced as a whole.

For two JSON values `source` and `target`, where `target` contains no object member whose value is `#!json null`, the
following code yields always `#!cpp true`:
```cpp
basic_json patched = source;
patched.merge_patch(merge_diff(source, target));
patched == target;
```

## Parameters

`source` (in)
:   JSON value to compare from

`target` (in)
:   JSON value to compare against

## Return value

a JSON Merge Patch to convert the `source` to `target`

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

## Complexity

Linear in the sizes of `source` and `target`, times the cost of looking up a key in an object: logarithmic in the size
of the object for [`json`](../json.md), and linear for [`ordered_json`](../ordered_json.md). For `ordered_json`,
comparing two objects with `n` and `m` members therefore takes O(n·m).

## Notes

- A merge patch uses `#!json null` to remove a member, so it cannot set a member to `#!json null`. As in RFC 7396, a
  `#!json null` member of `target` is treated as absent: the patch removes the member from `source` instead of setting
  it to `#!json null`. A member that is `#!json null` in both `source` and `target` is unchanged and left out of the
  patch, so `source` keeps it.
- A merge patch cannot reorder object members, and [`merge_patch`](merge_patch.md) appends added members at the end.
  For [`ordered_json`](../ordered_json.md), the patched value therefore has the same members as `target`, but not
  necessarily in the same order, and may compare unequal to it. The patch lists changed and removed members in the
  order of `source`, followed by added members in the order of `target`.

## Examples

??? example

    The following code shows how a JSON Merge Patch is created as a diff for two JSON values.

    ```cpp
    --8<-- "examples/merge_diff.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/merge_diff.output"
    ```

## See also

- [RFC 7396 (JSON Merge Patch)](https://tools.ietf.org/html/rfc7396)
- [merge_patch](merge_patch.md) applies a JSON Merge Patch
- [diff](diff.md) creates a diff as a JSON Patch

## Version history

- Added in version 3.13.0.
