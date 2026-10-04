# <small>nlohmann::basic_json::</small>unflatten

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

## Exception safety

Strong exception safety: if an exception occurs, the original value stays intact.

## Exceptions

The function can throw the following exceptions:

- Throws [`type_error.314`](../../home/exceptions.md#jsonexceptiontype_error314) if value is not an object
- Throws [`type_error.315`](../../home/exceptions.md#jsonexceptiontype_error315) if object values are not primitive
- Throws [`type_error.313`](../../home/exceptions.md#jsonexceptiontype_error313) if a key (JSON pointer) leads to a
  conflicting nesting; example: `"invalid value to unflatten"`
- Throws [`parse_error.106`](../../home/exceptions.md#jsonexceptionparse_error106) if an array index in a key begins
  with '0'; example: `"array index '01' must not begin with '0'"`
- Throws [`parse_error.107`](../../home/exceptions.md#jsonexceptionparse_error107) if a key is not empty and does not
  begin with a slash (`/`); example: `"JSON pointer must be empty or begin with '/' - was: 'a'"`
- Throws [`parse_error.108`](../../home/exceptions.md#jsonexceptionparse_error108) if a tilde (`~`) in a key is not
  followed by `0` or `1`; example: `"escape character '~' must be followed with '0' or '1'"`
- Throws [`parse_error.109`](../../home/exceptions.md#jsonexceptionparse_error109) if an array index in a key is not a
  number; example: `"array index 'one' is not a number"`
- Throws [`out_of_range.404`](../../home/exceptions.md#jsonexceptionout_of_range404) if a level becomes an array
  (because one of its keys is `0`) and another key at that level cannot be an array index; example:
  `"unresolved reference token 'x'"`

## Complexity

Linear in the size of the JSON value.

## Notes

Empty objects and arrays are flattened by [`flatten()`](flatten.md) to `#!json null` values and cannot unflattened to
their original type.

A flattened array and a flattened object whose keys are array indices are indistinguishable, because both are
described by the same JSON pointers. A value is therefore restored as an array if and only if one of its keys is the
reference token `0`, and as an object otherwise: `#!json {"2": 1}` is restored unchanged, whereas `#!json {"0": 1}` is
restored as `#!json [1]`. This decision does not depend on the order in which the flattened object is iterated.

Apart from these two cases, for a JSON value `j`, the following is always true:
`#!cpp j == j.flatten().unflatten()`.

## Examples

??? example

    The following code shows how a flattened JSON object is unflattened into the original nested JSON object.
    
    ```cpp
    --8<-- "examples/unflatten.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/unflatten.output"
    ```

## See also

- [flatten](flatten.md) the reverse function

## Version history

- Added in version 2.0.0.
- Made the array/object decision independent of the object's iteration order in version 3.13.0.
