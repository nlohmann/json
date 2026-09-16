# <small>nlohmann::basic_json::</small>initializer_list_t

```cpp
using initializer_list_t = std::initializer_list<detail::json_ref<basic_json>>;
```

The type used for the initializer-list [constructor](basic_json.md) (overload 5) and for functions
such as [`operator=`](operator=.md) that accept a braced-init-list of JSON values. Each element wraps a
`basic_json` value or something convertible to one, deferring the decision of whether the list should be
parsed as a JSON array or a JSON object to the constructor itself.

See the [constructor](basic_json.md) documentation for how `initializer_list_t` values are interpreted.

## Examples

??? example

    The example shows how an `initializer_list_t` is used to construct a JSON value.

    ```cpp
    --8<-- "examples/initializer_list_t.cpp"
    ```

    Output:

    ```
    --8<-- "examples/initializer_list_t.output"
    ```

## Version history

- Since version 1.0.0.
