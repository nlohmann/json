# basic_json::cend

```cpp
const_iterator cend() const noexcept;
```

Returns an iterator to one past the last element.

![Illustration from cppreference.com](../../images/range-begin-end.svg)

## Return value

iterator one past the last element

## Exception safety

No-throw guarantee: this member function never throws exceptions.

## Complexity

Constant.

## Example

??? example

    The following code shows an example for `cend()`.
    
    ```cpp
    --8<-- "examples/cend.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/cend.output"
    ```

## Version history

- Added in version 1.0.0.
