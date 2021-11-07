# <small>nlohmann::basic_json::</small>find

```cpp
template<typename KeyT>
iterator find(KeyT&& key);

template<typename KeyT>
const_iterator find(KeyT&& key) const;
```

Finds an element in a JSON object with key equivalent to `key`. If the element is not found or the JSON value is not an
object, `end()` is returned.

## Template parameters

`KeyT`
:   A type for an object key.

## Parameters

`key` (in)
:   key value of the element to search for.
    
## Return value

Iterator to an element with key equivalent to `key`. If no such element is found or the JSON value is not an object,
past-the-end (see `end()`) iterator is returned.

## Exception safety

Strong exception safety: if an exception occurs, the original value stays intact.

## Complexity

Logarithmic in the size of the JSON object.

## Notes

This method always returns `end()` when executed on a JSON type that is not an object.

## Examples

??? example

    The example shows how `find()` is used.
    
    ```cpp
    --8<-- "examples/find__key_type.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/find__key_type.output"
    ```

## See also

- [contains](contains.md) checks whether a key exists

## Version history

- Added in version 1.0.0.
