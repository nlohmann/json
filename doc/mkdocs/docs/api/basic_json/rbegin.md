# basic_json::rbegin

```cpp
reverse_iterator rbegin() noexcept;
const_reverse_iterator rbegin() const noexcept;
```

Returns an iterator to the reverse-beginning; that is, the last element.

![Illustration from cppreference.com](../../images/range-rbegin-rend.svg)

## Return value

reverse iterator to the first element

## Exception safety

No-throw guarantee: this member function never throws exceptions.

## Complexity

Constant.

## Example

??? example

    The following code shows an example for `rbegin()`.
    
    ```cpp
    --8<-- "examples/rbegin.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/rbegin.output"
    ```

## Version history

- Added in version 1.0.0.
