# basic_json::emplace

```cpp
template<class... Args>
std::pair<iterator, bool> emplace(Args&& ... args);
```

Inserts a new element into a JSON object constructed in-place with the given `args` if there is no element with the key
in the container. If the function is called on a JSON null value, an empty object is created before appending the value
created from `args`.

## Template parameters

`Args`
:   compatible types to create a `basic_json` object

## Parameters

`args` (in)
:   arguments to forward to a constructor of `basic_json`

## Return value

a pair consisting of an iterator to the inserted element, or the already-existing element if no insertion happened, and
a `#!cpp bool` denoting whether the insertion took place.

## Exceptions

Throws [`type_error.311`](../../home/exceptions.md#jsonexceptiontype_error311) when called on a type other than JSON
object or `#!json null`; example: `"cannot use emplace() with number"`

## Complexity

Logarithmic in the size of the container, O(log(`size()`)).

## Examples

??? example

    The example shows how `emplace()` can be used to add elements to a JSON object. Note how the `#!json null` value was
    silently converted to a JSON object. Further note how no value is added if there was already one value stored with
    the same key.
            
    ```cpp
    --8<-- "examples/emplace.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/emplace.output"
    ```

## Version history

- Since version 2.0.8.
