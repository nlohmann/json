# basic_json::cbegin

```cpp
const_iterator cbegin() const noexcept;
```

Returns an iterator to the first element.

![Illustration from cppreference.com](../../images/range-begin-end.svg)

## Return value

iterator to the first element

## Exception safety

No-throw guarantee: this member function never throws exceptions.

## Complexity

Constant.

## Example

??? example

    The following code shows an example for `cbegin()`.
    
    ```cpp
    --8<-- "examples/cbegin.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/cbegin.output"
    ```

## Version history

- Added in version 1.0.0.
