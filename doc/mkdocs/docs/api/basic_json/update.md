# basic_json::update

```cpp
// (1)
void update(const_reference j);

// (2)
void update(const_iterator first, const_iterator last);
```

1. Inserts all values from JSON object `j` and overwrites existing keys.
2. Inserts all values from from range `[first, last)` and overwrites existing keys.

The function is motivated by Python's [dict.update](https://docs.python.org/3.6/library/stdtypes.html#dict.update)
function.

## Parameters

`j` (in)
:   JSON object to read values from

`first` (in)
:   begin of the range of elements to insert

`last` (in)
:   end of the range of elements to insert

## Exceptions

1. The function can throw the following exceptions:
    - Throws [`type_error.312`](../../home/exceptions.md#jsonexceptiontype_error312) if called on JSON values other than
      objects; example: `"cannot use update() with string"`
2. The function can throw thw following exceptions:
    - Throws [`type_error.312`](../../home/exceptions.md#jsonexceptiontype_error312) if called on JSON values other than
      objects; example: `"cannot use update() with string"`
    - Throws [`invalid_iterator.202`](../../home/exceptions.md#jsonexceptioninvalid_iterator202) if called on an
      iterator which does not belong to the current JSON value; example: `"iterator does not fit current value"`
    - Throws [`invalid_iterator.210`](../../home/exceptions.md#jsonexceptioninvalid_iterator210) if `first` and `last`
      do not belong to the same JSON value; example: `"iterators do not fit"`

## Complexity

1. O(N*log(size() + N)), where N is the number of elements to insert.
2. O(N*log(size() + N)), where N is the number of elements to insert.

## Example

??? example

    The example shows how `update()` is used.
    
    ```cpp
    --8<-- "examples/update.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/update.output"
    ```

??? example

    The example shows how `update()` is used.
    
    ```cpp
    --8<-- "examples/update__range.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/update__range.output"
    ```

## Version history

- Added in version 3.0.0.
