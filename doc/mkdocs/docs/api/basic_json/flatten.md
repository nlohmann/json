# <small>nlohmann::basic_json::</small>flatten

```cpp
basic_json flatten() const;
```

The function creates a JSON object whose keys are JSON pointers (see [RFC 6901](https://tools.ietf.org/html/rfc6901))
and whose values are all primitive (see [`is_primitive()`](is_primitive.md) for more information). The original JSON
value can be restored using the [`unflatten()`](unflatten.md) function.
    
## Return value

an object that maps JSON pointers to primitive values

## Exception safety

Strong exception safety: if an exception occurs, the original value stays intact.

## Complexity

Linear in the size the JSON value.

## Notes

Empty objects and arrays are flattened to `#!json null` and will not be reconstructed correctly by the
[`unflatten()`](unflatten.md) function.

## Examples

??? example

    The following code shows how a JSON object is flattened to an object whose keys consist of JSON pointers.
    
    ```cpp
    --8<-- "examples/flatten.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/flatten.output"
    ```

## See also

- [unflatten](unflatten.md) the reverse function

## Version history

- Added in version 2.0.0.
