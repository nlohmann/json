# <small>nlohmann::basic_json::</small>clear

```cpp
void clear() noexcept;
```

Clears the content of a JSON value and resets it to the default value as if [`basic_json(value_t)`](basic_json.md) would
have been called with the current value type from [`type()`](type.md):

| Value type | initial value        |
|------------|----------------------|
| null       | `null`               |
| boolean    | `false`              |
| string     | `""`                 |
| number     | `0`                  |
| binary     | An empty byte vector |
| object     | `{}`                 |
| array      | `[]`                 |

Has the same effect as calling

```.cpp
*this = basic_json(type());
```

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Linear in the size of the JSON value.

## Notes

All iterators, pointers and references related to this container are invalidated.

## Examples

??? example

    The example below shows the effect of `clear()` to different
    JSON types.
    
    ```cpp
    --8<-- "examples/clear.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/clear.output"
    ```

## Version history

- Added in version 1.0.0.
- Added support for binary types in version 3.8.0.
