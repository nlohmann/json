# <small>nlohmann::basic_json::</small>crbegin

```cpp
const_reverse_iterator crbegin() const noexcept;
```

Returns an iterator to the reverse-beginning; that is, the last element.

![Illustration from cppreference.com](../../images/range-rbegin-rend.svg)

## Return value

reverse iterator to the first element

## Exception safety

No-throw guarantee: this member function never throws exceptions.

## Complexity

Constant.

## Examples

??? example

    The following code shows an example for `crbegin()`.
    
    ```cpp
    --8<-- "examples/crbegin.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/crbegin.output"
    ```

## Version history

- Added in version 1.0.0.
