# basic_json::contains

```cpp
template<typename KeyT>
bool contains(KeyT && key) const;
```

Check whether an element exists in a JSON object with key equivalent to `key`. If the element is not found or the JSON
value is not an object, `#!cpp false` is returned.

## Template parameters

`KeyT`
:   A type for an object key other than `basic_json::json_pointer`.

## Parameters

`key` (in)
:   key value to check its existence.
    
## Return value

`#!cpp true` if an element with specified `key` exists. If no such element with such key is found or the JSON value is
not an object, `#!cpp false` is returned.

## Exception safety

Strong exception safety: if an exception occurs, the original value stays intact.

## Complexity

Logarithmic in the size of the JSON object.

## Notes

This method always returns `#!cpp false` when executed on a JSON type that is not an object.

## Example

??? example

    The example shows how `contains()` is used.
    
    ```cpp
    --8<-- "examples/contains.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/contains.output"
    ```

## Version history

- Added in version 3.6.0.
