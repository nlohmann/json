# <small>nlohmann::basic_json::</small>count

```cpp
template<typename KeyT>
size_type count(KeyT&& key) const;
```

Returns the number of elements with key `key`. If `ObjectType` is the default `std::map` type, the return value will
always be `0` (`key` was not found) or `1` (`key` was found).

## Template parameters

`KeyT`
:   A type for an object key.

## Parameters

`key` (in)
:   key value of the element to count.
    
## Return value

Number of elements with key `key`. If the JSON value is not an object, the return value will be `0`.

## Exception safety

Strong exception safety: if an exception occurs, the original value stays intact.

## Complexity

Logarithmic in the size of the JSON object.

## Notes

This method always returns `0` when executed on a JSON type that is not an object.

## Examples

??? example

    The example shows how `count()` is used.
    
    ```cpp
    --8<-- "examples/count.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/count.output"
    ```

## Version history

- Added in version 1.0.0.
