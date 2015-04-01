# nlohmann::basic_json::empty

```cpp
bool empty() const noexcept;
```

Checks if the container has no elements; that is, whether `begin() == end()`.

## Parameters

(none)

## Return value

`true` if the container is empty, `false` otherwise. Note that the JSON types string, number, and boolean are never empty, null values are always empty.

## Exceptions

`noexcept` specification: `noexcept`.

## Complexity

Constant (assuming types `ObjectType` and `ArrayType` satisfy the [Container](http://en.cppreference.com/w/cpp/concept/Container) concept).

## Example

The following code uses empty to check if a `json` container contains any elements:

```cpp
#include <json.hpp>
#include <iostream>
  
int main()
{
    nlohman::json numbers;
    std::cout << "Initially, numbers.empty(): " << numbers.empty() << '\n';
    
    numbers.push_back(42);
    numbers.push_back(13317); 
    std::cout << "After adding elements, numbers.empty(): " << numbers.empty() << '\n';
}
```

### Output

    Initially, numbers.empty(): 1
    After adding elements, numbers.empty(): 0

## Requirements

The `empty` member function is part of the [Container](http://en.cppreference.com/w/cpp/concept/Container) requirement.

## See also

- `size()`
