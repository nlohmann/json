# <small>nlohmann::basic_json::</small>crbegin

```cpp
const_reverse_iterator crbegin() const noexcept;
```

Returns an iterator to the reverse-beginning; that is, the last element.

![Illustration from cppreference.com](../../images/range-rbegin-rend.svg)

## Return value

reverse iterator to the last element

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

## See also

- [crend](crend.md) returns a const reverse iterator to one before the first element
- [rbegin](rbegin.md) returns a reverse iterator to the last element
- [cbegin](cbegin.md) returns a const iterator to the first element
- [Iterators](../../features/iterators.md) - the article on iterators

## Version history

- Added in version 1.0.0.
