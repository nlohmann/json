# <small>nlohmann::basic_json::</small>count

```cpp
// (1)
size_type count(const typename object_t::key_type& key) const;

// (2)
template<typename KeyType>
size_type count(KeyType&& key) const;
```

1. Returns the number of elements with key `key`. If `ObjectType` is the default `std::map` type, the return value will
   always be `0` (`key` was not found) or `1` (`key` was found).
2. See 1. This overload is only available if `KeyType` is comparable with `#!cpp typename object_t::key_type` and
   `#!cpp typename object_comparator_t::is_transparent` denotes a type.

## Template parameters

`KeyType`
:   A type for an object key other than [`json_pointer`](../json_pointer/index.md) that is comparable with
    [`string_t`](string_t.md) using  [`object_comparator_t`](object_comparator_t.md).
    This can also be a string view (C++17).

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

1. Added in version 3.11.0.
2. Added in version 1.0.0. Changed parameter `key` type to `KeyType&&` in version 3.11.0.
