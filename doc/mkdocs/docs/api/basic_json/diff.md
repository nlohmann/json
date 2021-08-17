# basic_json::diff

```cpp
static basic_json diff(const basic_json& source,
                       const basic_json& target);
```

Creates a [JSON Patch](http://jsonpatch.com) so that value `source` can be changed into the value `target` by calling
[`patch`](patch.md) function.

For two JSON values `source` and `target`, the following code yields always `#!cpp true`:
```cpp
source.patch(diff(source, target)) == target;
```

## Parameters

`source` (in)
:   JSON value to compare from

`target` (in)
:   JSON value to compare against

## Return value

a JSON patch to convert the `source` to `target`

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

## Complexity

Linear in the lengths of `source` and `target`.

## Note

Currently, only `remove`, `add`, and `replace` operations are generated.
          
## Example

??? example

    The following code shows how a JSON patch is created as a diff for two JSON values.
     
    ```cpp
    --8<-- "examples/diff.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/diff.output"
    ```

## Version history

- Added in version 2.0.0.
