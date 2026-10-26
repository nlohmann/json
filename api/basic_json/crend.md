# <small>nlohmann::basic_json::</small>crend

```cpp
const_reverse_iterator crend() const noexcept;
```

Returns an iterator to the reverse-end; that is, one before the first element. This element acts as a placeholder,
attempting to access it results in undefined behavior.

![Illustration from cppreference.com](../../images/range-rbegin-rend.svg)

## Return value

reverse iterator to the element following the last element

## Exception safety

No-throw guarantee: this member function never throws exceptions.

## Complexity

Constant.

## Examples

??? example

    The following code shows an example for `crend()`.
    
    ```cpp
    #include <iostream>
    #include <nlohmann/json.hpp>
    
    using nlohmann::json;
    
    int main()
    {
        // create an array value
        json array = {1, 2, 3, 4, 5};
    
        // get an iterator to the reverse-end
        json::const_reverse_iterator it = array.crend();
    
        // increment the iterator to point to the first element
        --it;
    
        // serialize the element that the iterator points to
        std::cout << *it << '\n';
    }
    
    ```
    
    Output:
    
    ```json
    1
    
    ```

## See also

- [crbegin](crbegin.md) returns a const reverse iterator to the last element
- [rend](rend.md) returns a reverse iterator to one before the first element
- [cend](cend.md) returns a const iterator to one past the last element
- [Iterators](../../features/iterators.md) - the article on iterators

## Version history

- Added in version 1.0.0.
