# <small>nlohmann::basic_json::</small>contains

```cpp
// (1)
template<typename KeyT>
bool contains(KeyT && key) const;

// (2)
bool contains(const json_pointer& ptr) const;
```

1. Check whether an element exists in a JSON object with key equivalent to `key`. If the element is not found or the 
   JSON value is not an object, `#!cpp false` is returned.
2. Check whether the given JSON pointer `ptr` can be resolved in the current JSON value.

## Template parameters

`KeyT`
:   A type for an object key other than `basic_json::json_pointer`.

## Parameters

`key` (in)
:   key value to check its existence.

`ptr` (in)
:   JSON pointer to check its existence.

## Return value

1. `#!cpp true` if an element with specified `key` exists. If no such element with such key is found or the JSON value
   is not an object, `#!cpp false` is returned.
2. `#!cpp true` if the JSON pointer can be resolved to a stored value, `#!cpp false` otherwise.

## Exception safety

Strong exception safety: if an exception occurs, the original value stays intact.

## Exceptions

1. The function does not throw exceptions.
2. The function can throw the following exceptions:
    - Throws [`parse_error.106`](../../home/exceptions.md#jsonexceptionparse_error106) if an array index begins with
      `0`.
    - Throws [`parse_error.109`](../../home/exceptions.md#jsonexceptionparse_error109) if an array index was not a
      number.

## Complexity

Logarithmic in the size of the JSON object.

## Notes

1. This method always returns `#!cpp false` when executed on a JSON type that is not an object.
2. This method can be executed on any JSON value type.

!!! info "Postconditions"

    If `#!cpp j.contains(x)` returns `#!c true` for a key or JSON pointer `x`, then it is safe to call `j[x]`.

## Examples

??? example "Example (1) check with key"

    The example shows how `contains()` is used.
    
    ```cpp
    --8<-- "examples/contains.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/contains.output"
    ```

??? example "Example (1) check with JSON pointer"

    The example shows how `contains()` is used.
    
    ```cpp
    --8<-- "examples/contains_json_pointer.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/contains_json_pointer.output"
    ```

## Version history

1. Added in version 3.6.0.
2. Added in version 3.7.0.
