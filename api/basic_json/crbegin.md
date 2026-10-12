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
    #include <iostream>
    #include <nlohmann/json.hpp>
    
    using json = nlohmann::json;
    
    int main()
    {
        // create an array value
        json array = {1, 2, 3, 4, 5};
    
        // get an iterator to the reverse-beginning
        json::const_reverse_iterator it = array.crbegin();
    
        // serialize the element that the iterator points to
        std::cout << *it << '\n';
    }
    
    ```
    
    Output:
    
    ```json
    5
    
    ```

## See also

- [crend](crend.md) returns a const reverse iterator to one before the first element
- [rbegin](rbegin.md) returns a reverse iterator to the last element
- [cbegin](cbegin.md) returns a const iterator to the first element
- [Iterators](../../features/iterators.md) - the article on iterators

## Version history

- Added in version 1.0.0.
