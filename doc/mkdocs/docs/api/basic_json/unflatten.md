# basic_json::unflatten

```cpp
basic_json unflatten() const;
```

The function restores the arbitrary nesting of a JSON value that has been flattened before using the
[`flatten()`](flatten.md) function. The JSON value must meet certain constraints:

1. The value must be an object.
2. The keys must be JSON pointers (see [RFC 6901](https://tools.ietf.org/html/rfc6901))
3. The mapped values must be primitive JSON types.
    
## Return value

the original JSON from a flattened version

## Exceptions

The function can throw the following exceptions:

- Throws [`type_error.314`](../../home/exceptions.md#jsonexceptiontype_error314) if value is not an object
- Throws [`type_error.315`](../../home/exceptions.md#jsonexceptiontype_error315) if object values are not primitive

## Exception safety

Strong exception safety: if an exception occurs, the original value stays intact.

## Complexity

Linear in the size the JSON value.

## Notes

Empty objects and arrays are flattened by [`flatten()`](flatten.md) to `#!json null` values and can not unflattened to
their original type. Apart from this example, for a JSON value `j`, the following is always true:
`#!cpp j == j.flatten().unflatten()`.

## Example

??? example

    The following code shows how a flattened JSON object is unflattened into the original nested JSON object.
    
    ```cpp
    --8<-- "examples/unflatten.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/unflatten.output"
    ```

## Version history

- Added in version 2.0.0.
