# <small>nlohmann::basic_json::</small>end

```cpp
iterator end() noexcept;
const_iterator end() const noexcept;
```

Returns an iterator to one past the last element.

![Illustration from cppreference.com](../../images/range-begin-end.svg)

## Return value

iterator one past the last element

## Exception safety

No-throw guarantee: this member function never throws exceptions.

## Complexity

Constant.

## Examples

??? example

    The following code shows an example for `end()`.
    
    ```cpp
    --8<-- "examples/end.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/end.output"
    ```

## Version history

- Added in version 1.0.0.
