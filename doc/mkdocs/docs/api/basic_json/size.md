# <small>nlohmann::basic_json::</small>size

```cpp
size_type size() const noexcept;
```

Returns the number of elements in a JSON value.
    
## Return value

The return value depends on the different types and is defined as follows:

| Value type | return value                        |
|------------|-------------------------------------|
| null       | `0`                                 |
| boolean    | `1`                                 |
| string     | `1`                                 |
| number     | `1`                                 |
| binary     | `1`                                 |
| object     | result of function object_t::size() |
| array      | result of function array_t::size()  |

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant, as long as [`array_t`](array_t.md) and [`object_t`](object_t.md) satisfy the
[Container](https://en.cppreference.com/w/cpp/named_req/Container) concept; that is, their `size()` functions have
constant complexity.

## Notes

This function does not return the length of a string stored as JSON value -- it returns the number of elements in the
JSON value which is `1` in the case of a string.

## Examples

??? example

    The following code calls `size()` on the different value types.
    
    ```cpp
    --8<-- "examples/size.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/size.output"
    ```

## Version history

- Added in version 1.0.0.
- Extended to return `1` for binary types in version 3.8.0.
