# <small>nlohmann::basic_json::</small>cend

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

## Examples

??? example

    The following code shows an example for `cend()`.
    
    ```cpp
    --8<-- "examples/cend.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/cend.output"
    ```

## See also

- [end](end.md) returns an iterator to one past the last element
- [cbegin](cbegin.md) returns a const iterator to the first element
- [crend](crend.md) returns a const reverse iterator to one before the first element
- [Iterators](../../features/iterators.md) - the article on iterators
- [basic_json_view::cend](../basic_json_view/cend.md) - the same iteration on a zero-copy view

## Version history

- Added in version 1.0.0.
