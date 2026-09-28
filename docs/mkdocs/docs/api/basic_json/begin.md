# <small>nlohmann::basic_json::</small>begin

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

## Examples

??? example

    The following code shows an example for `begin()`.
    
    ```cpp
    --8<-- "examples/begin.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/begin.output"
    ```

## See also

- [end](end.md) - returns an iterator to one past the last element
- [basic_json_view::begin](../basic_json_view/begin.md) - the same iteration on a zero-copy view (in document order,
  not sorted by key)

## Version history

- Added in version 1.0.0.
