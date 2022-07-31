# <small>nlohmann::basic_json::</small>find

```cpp
// (1)
iterator find(const typename object_t::key_type& key);
const_iterator find(const typename object_t::key_type& key) const;

// (2)
template<typename KeyType>
iterator find(KeyType&& key);
template<typename KeyType>
const_iterator find(KeyType&& key) const;
```

1. Finds an element in a JSON object with a key equivalent to `key`. If the element is not found or the
   JSON value is not an object, `end()` is returned.
2. See 1. This overload is only available if `KeyType` is comparable with `#!cpp typename object_t::key_type` and
   `#!cpp typename object_comparator_t::is_transparent` denotes a type.

## Template parameters

`KeyType`
:   A type for an object key other than [`json_pointer`](../json_pointer/index.md) that is comparable with
    [`string_t`](string_t.md) using  [`object_comparator_t`](object_comparator_t.md).
    This can also be a string view (C++17).

## Parameters

`key` (in)
:   key value of the element to search for.
    
## Return value

Iterator to an element with a key equivalent to `key`. If no such element is found or the JSON value is not an object,
a past-the-end iterator (see `end()`) is returned.

## Exception safety

Strong exception safety: if an exception occurs, the original value stays intact.

## Complexity

Logarithmic in the size of the JSON object.

## Notes

This method always returns `end()` when executed on a JSON type that is not an object.

## Examples

??? example "Example: (1) find object element by key"

    The example shows how `find()` is used.
    
    ```cpp
    --8<-- "examples/find__object_t_key_type.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/find__object_t_key_type.output"
    ```

??? example "Example: (2) find object element by key using string_view"

    The example shows how `find()` is used.
    
    ```cpp
    --8<-- "examples/find__keytype.c++17.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/find__keytype.c++17.output"
    ```

## See also

- [contains](contains.md) checks whether a key exists

## Version history

1. Added in version 3.11.0.
2. Added in version 1.0.0. Changed to support comparable types in version 3.11.0.
