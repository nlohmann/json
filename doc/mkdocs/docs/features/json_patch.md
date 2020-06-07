# JSON Patch and Diff

## Patches

JSON Patch ([RFC 6902](https://tools.ietf.org/html/rfc6902)) defines a JSON document structure for expressing a sequence of operations to apply to a JSON) document. With the `patch` function, a JSON Patch is applied to the current JSON value by executing all operations from the patch.

??? example

    The following code shows how a JSON patch is applied to a value.

    ```cpp
    --8<-- "examples/patch.cpp"
    ```
    
    Output:

    ```json
    --8<-- "examples/patch.output"
    ```

## Diff

The library can also calculate a JSON patch (i.e., a **diff**) given two JSON values.

!!! success "Invariant"

    For two JSON values *source* and *target*, the following code yields always true:

    ```cüü
    source.patch(diff(source, target)) == target;
    ```

??? example

    The following code shows how a JSON patch is created as a diff for two JSON values.

    ```cpp
    --8<-- "examples/diff.cpp"
    ```
    
    Output:

    ```json
    --8<-- "examples/diff.output"
    ```
