# <small>nlohmann::basic_json::</small>end

```cpp
iterator end() noexcept;
const_iterator end() const noexcept;
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

    The following code shows an example for `end()`.
    
    ```cpp
    #include <iostream>
    #include <nlohmann/json.hpp>
    
    using json = nlohmann::json;
    
    int main()
    {
        // create an array value
        json array = {1, 2, 3, 4, 5};
    
        // get an iterator to one past the last element
        json::iterator it = array.end();
    
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

- [begin](begin.md) returns an iterator to the first element
- [cend](cend.md) returns a const iterator to one past the last element
- [rend](rend.md) returns a reverse iterator to one before the first element
- [Iterators](../../features/iterators.md) - the article on iterators
- [basic_json_view::end](../basic_json_view/end.md) - the same iteration on a zero-copy view

## Version history

- Added in version 1.0.0.
