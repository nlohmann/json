# basic_json::find

```cpp
template<typename KeyT>
iterator find(const KeyT& key);

template<typename KeyT>
const_iterator find(const KeyT& key) const
```

Finds an element in a JSON object with key equivalent to `key`. If the element is not found or the JSON value is not an
object, `end()` is returned.

## Template parameters

`KeyT`
:   A type for an object key that is less-than comparable with `string_t`. This can also be a string literal or a string
    view (C++17).

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

## Example

??? example

    The example shows how `find()` is used.
    
    ```cpp
    --8<-- "examples/find__key_type.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/find__key_type.output"
    ```

## Version history

- Added in version 1.0.0.
