# basic_json::merge_patch

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

## Complexity

Linear in the lengths of `apply_patch`.

## Example

??? example

    The following code shows how a JSON Merge Patch is applied to a JSON document.
     
    ```cpp
    --8<-- "examples/merge_patch.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/merge_patch.output"
    ```

## Version history

- Added in version 3.0.0.
