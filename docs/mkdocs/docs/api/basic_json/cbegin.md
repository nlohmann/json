# <small>nlohmann::basic_json::</small>cbegin

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

## Examples

??? example

    The following code shows an example for `cbegin()`.
    
    ```cpp
    --8<-- "examples/cbegin.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/cbegin.output"
    ```

## See also

- [begin](begin.md) returns an iterator to the first element
- [cend](cend.md) returns a const iterator to one past the last element
- [crbegin](crbegin.md) returns a const reverse iterator to the last element
- [Iterators](../../features/iterators.md) - the article on iterators

## Version history

- Added in version 1.0.0.
