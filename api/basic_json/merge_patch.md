# <small>nlohmann::basic_json::</small>merge_patch

```cpp
void merge_patch(const basic_json& apply_patch);
```

The merge patch format is primarily intended for use with the HTTP PATCH method as a means of describing a set of
modifications to a target resource's content. This function applies a merge patch to the current JSON value.

The function implements the following algorithm from Section 2 of
[RFC 7396 (JSON Merge Patch)](https://tools.ietf.org/html/rfc7396):

```python
define MergePatch(Target, Patch):
  if Patch is an Object:
    if Target is not an Object:
      Target = {} // Ignore the contents and set it to an empty Object
    for each Name/Value pair in Patch:
      if Value is null:
        if Name exists in Target:
          remove the Name/Value pair from Target
      else:
        Target[Name] = MergePatch(Target[Name], Value)
    return Target
  else:
    return Patch
```

Thereby, `Target` is the current object; that is, the patch is applied to the current value.

## Parameters

`apply_patch` (in)
:   the patch to apply

## Exception safety

Basic guarantee: if an exception is thrown during the operation, the JSON value may be partially modified.

## Complexity

Linear in the total number of values (including nested ones) in `apply_patch`, times the cost of a key-based object
operation (looking up, adding, or erasing a member): logarithmic for [`json`](../json.md), and linear for
[`ordered_json`](../ordered_json.md) (see [`ordered_map` complexity](../ordered_map.md#complexity)). For
`ordered_json`, patching an object that has `n` members with a patch that has `m` members therefore takes O(n·m). The
cost also includes one copy of `apply_patch` (see the notes below).

## Notes

- `apply_patch` may be `#!cpp *this` itself or refer to a value contained in `#!cpp *this` (for example, a subobject
  returned by `#!cpp (*this)[key]`); it is read as it was when `merge_patch()` was called, before any modification of
  `#!cpp *this`. To make this possible, the function copies `apply_patch` before it modifies `#!cpp *this`, so the cost
  includes one copy of the patch.
- A merge patch uses `#!json null` to remove a member, so it cannot set a member to `#!json null`: applying
  `#!json {"a":null}` to `#!json {"a":1}` gives `#!json {}`.
- Arrays are not merged: an array in the patch replaces the target value as a whole, and a `#!json null` inside an
  array is kept as an element. `#!json null` members of the target that the patch does not mention are preserved.
- A `#!json null` in the patch only removes a member; it does not prevent the creation of the enclosing objects.
  Applying `#!json {"a":{"b":null}}` to `#!json {}` gives `#!json {"a":{}}` (see example 15 in Appendix A of the RFC).
- If `apply_patch` is not an object, it replaces the target as a whole. In particular, a `#!json null` patch turns the
  target into `#!json null`. If `apply_patch` is an object and the target is not, the target is first replaced by an
  empty object, so applying `#!json {}` to `#!json 1` gives `#!json {}`.
- A merge patch cannot express every change; for example, it cannot reorder array elements or remove a specific array
  element. Use [JSON Patch](../../features/json_patch.md) ([RFC 6902](https://tools.ietf.org/html/rfc6902)) for that.
  [`merge_diff`](merge_diff.md) has a matching limitation, see its notes.
- A [discarded](is_discarded.md) value is treated like any other non-object value: a discarded
  `apply_patch` turns the target into a discarded value, and an object patch replaces a discarded target by an object
  as described above.

## Examples

??? example

    The following code shows how a JSON Merge Patch is applied to a JSON document.
     
    ```cpp
    #include <iostream>
    #include <nlohmann/json.hpp>
    #include <iomanip> // for std::setw
    
    using nlohmann::json;
    using namespace nlohmann::literals;
    
    int main()
    {
        // the original document
        json document = R"({
                    "title": "Goodbye!",
                    "author": {
                        "givenName": "John",
                        "familyName": "Doe"
                    },
                    "tags": [
                        "example",
                        "sample"
                    ],
                    "content": "This will be unchanged"
                })"_json;
    
        // the patch
        json patch = R"({
                    "title": "Hello!",
                    "phoneNumber": "+01-123-456-7890",
                    "author": {
                        "familyName": null
                    },
                    "tags": [
                        "example"
                    ]
                })"_json;
    
        // apply the patch
        document.merge_patch(patch);
    
        // output original and patched document
        std::cout << std::setw(4) << document << '\n';
    }
    
    ```
    
    Output:
    
    ```json
    {
        "author": {
            "givenName": "John"
        },
        "content": "This will be unchanged",
        "phoneNumber": "+01-123-456-7890",
        "tags": [
            "example"
        ],
        "title": "Hello!"
    }
    
    ```

## See also

- [RFC 7396 (JSON Merge Patch)](https://tools.ietf.org/html/rfc7396) - specification of JSON Merge Patch
- [`patch`](patch.md) - apply a JSON patch
- [`merge_diff`](merge_diff.md) - creates a diff as a JSON Merge Patch
- [JSON Merge Patch](../../features/merge_patch.md) - the article on JSON Merge Patch

## Version history

- Added in version 3.1.0.
- Fixed use of freed or relocated memory when `apply_patch` is `#!cpp *this` or refers to a value contained in
  `#!cpp *this`, in version 3.13.0.
