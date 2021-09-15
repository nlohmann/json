# basic_json::max_size

```cpp
size_type max_size() const noexcept;
```

Returns the maximum number of elements a JSON value is able to hold due to system or library implementation limitations,
i.e. `std::distance(begin(), end())` for the JSON value.
    
## Return value

The return value depends on the different types and is defined as follows:

Value type  | return value
----------- | -------------
null        | `0` (same as [`size()`](size.md))
boolean     | `1` (same as [`size()`](size.md))
string      | `1` (same as [`size()`](size.md))
number      | `1` (same as [`size()`](size.md))
binary      | `1` (same as [`size()`](size.md))
object      | result of function `object_t::max_size()`
array       | result of function `array_t::max_size()`

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant, as long as [`array_t`](array_t.md) and [`object_t`](object_t.md) satisfy the
[Container](https://en.cppreference.com/w/cpp/named_req/Container) concept; that is, their `max_size()` functions have
constant complexity.

## Notes

This function does not return the maximal length of a string stored as JSON value -- it returns the maximal number of
string elements the JSON value can store which is `1`.

## Example

??? example

    The following code calls `max_size()` on the different value types. Note the output is implementation specific.
        
    ```cpp
    --8<-- "examples/max_size.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/max_size.output"
    ```

## Version history

- Added in version 1.0.0.
- Extended to return `1` for binary types in version 3.8.0.
