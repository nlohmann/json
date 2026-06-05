# <small>nlohmann::basic_json::</small>emplace_back

```cpp
template<class... Args>
reference emplace_back(Args&& ... args);
```

Creates a JSON value from the passed parameters `args` to the end of the JSON value. If the function is called on a JSON
`#!json null` value, an empty array is created before appending the value created from `args`.

## Template parameters

`Args`
:   compatible types to create a `basic_json` object

## Iterator invalidation

By adding an element to the end of the array, a reallocation can happen, in which case all iterators (including the
[`end()`](end.md) iterator) and all references to the elements are invalidated. Otherwise, only the [`end()`](end.md)
iterator is invalidated.

## Parameters

`args` (in)
:   arguments to forward to a constructor of `basic_json`

## Return value

reference to the inserted element

## Exceptions

Throws [`type_error.311`](../../home/exceptions.md#jsonexceptiontype_error311) when called on a type other than JSON
array or `#!json null`; example: `"cannot use emplace_back() with number"`

## Complexity

Amortized constant.

## Examples

??? example

    The example shows how `emplace_back()` can be used to add elements to a JSON array. Note how the `null` value was
    silently converted to a JSON array.
        
    ```cpp
    --8<-- "examples/emplace_back.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/emplace_back.output"
    ```

## See also

- [operator+=](operator+=.md) add a value to an array/object
- [push_back](push_back.md) add a value to an array/object

## Version history

- Since version 2.0.8.
- Returns reference since 3.7.0.
