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
    #include <iostream>
    #include <nlohmann/json.hpp>
    
    using json = nlohmann::json;
    
    int main()
    {
        // create an array value
        json array = {1, 2, 3, 4, 5};
    
        // get an iterator to one past the last element
        json::const_iterator it = array.cend();
    
        // decrement the iterator to point to the last element
        --it;
    
        // serialize the element that the iterator points to
        std::cout << *it << '\n';
    }
    
    ```
    
    Output:
    
    ```json
    5
    
    ```

## See also

- [end](end.md) returns an iterator to one past the last element
- [cbegin](cbegin.md) returns a const iterator to the first element
- [crend](crend.md) returns a const reverse iterator to one before the first element
- [Iterators](../../features/iterators.md) - the article on iterators
- [basic_json_view::cend](../basic_json_view/cend.md) - the same iteration on a zero-copy view

## Version history

- Added in version 1.0.0.
