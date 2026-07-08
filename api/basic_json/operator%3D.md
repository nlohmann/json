# <small>nlohmann::basic_json::</small>operator=

```cpp
basic_json& operator=(basic_json other) noexcept (
    std::is_nothrow_move_constructible<value_t>::value &&
    std::is_nothrow_move_assignable<value_t>::value &&
    std::is_nothrow_move_constructible<json_value>::value &&
    std::is_nothrow_move_assignable<json_value>::value &&
    std::is_nothrow_move_assignable<json_base_class_t>::value
);
```

Copy assignment operator. Copies a JSON value via the "copy and swap" strategy: It is expressed in terms of the copy
constructor, destructor, and the `swap()` member function.

## Parameters

`other` (in)
:   value to copy from

## Exception safety

Strong guarantee: if an exception is thrown while copying `other`, there are no changes to `#!cpp *this`.

## Complexity

Linear.

## Examples

??? example

    The code below shows and example for the copy assignment. It creates a copy of value `a` which is then swapped with
    `b`. Finally, the copy of `a` (which is the null value after the swap) is destroyed.
     
    ```cpp
    --8<-- "examples/basic_json__copyassignment.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/basic_json__copyassignment.output"
    ```

## See also

- [basic_json](basic_json.md) create a JSON value
- [swap](swap.md) exchanges the contents of two JSON values

## Version history

- Added in version 1.0.0.
