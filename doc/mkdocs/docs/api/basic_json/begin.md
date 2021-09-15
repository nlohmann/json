# basic_json::begin

```cpp
iterator begin() noexcept;
const_iterator begin() const noexcept;
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

    The following code shows an example for `begin()`.
    
    ```cpp
    --8<-- "examples/begin.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/begin.output"
    ```

## Version history

- Added in version 1.0.0.
