# nlohmann::basic_json::emplace_back

```
template<class... Args>
reference emplace_back(Args&& ... args);
```

Creates a JSON value from the passed parameters `args` to the end of the JSON value. If the function is called on a JSON `null` value, an empty array is created before appending the value created from `args`.

## Template parameters

`Args` : compatible types to create a `basic_json` object

## Iterator invalidation

By adding an element to the end of the array, a reallocation can happen, in which case all iterators (including the [`end()`](https://json.nlohmann.me/api/basic_json/end/index.md) iterator) and all references to the elements are invalidated. Otherwise, only the [`end()`](https://json.nlohmann.me/api/basic_json/end/index.md) iterator is invalidated.

## Parameters

`args` (in) : arguments to forward to a constructor of `basic_json`

## Return value

reference to the inserted element

## Exceptions

Throws [`type_error.311`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error311) when called on a type other than JSON array or `null`; example: `"cannot use emplace_back() with number"`

## Complexity

Amortized constant.

## Examples

Example

The example shows how `emplace_back()` can be used to add elements to a JSON array. Note how the `null` value was silently converted to a JSON array.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create JSON values
    json array = {1, 2, 3, 4, 5};
    json null;

    // print values
    std::cout << array << '\n';
    std::cout << null << '\n';

    // add values
    array.emplace_back(6);
    null.emplace_back("first");
    null.emplace_back(3, "second");

    // print values
    std::cout << array << '\n';
    std::cout << null << '\n';
}
```

Output:

```
[1,2,3,4,5]
null
[1,2,3,4,5,6]
["first",["second","second","second"]]
```

## See also

- [operator+=](https://json.nlohmann.me/api/basic_json/operator%2B%3D/index.md) add a value to an array/object
- [push_back](https://json.nlohmann.me/api/basic_json/push_back/index.md) add a value to an array/object
- [Modifying values](https://json.nlohmann.me/features/modifying_values/index.md) - the article on modifying values

## Version history

- Since version 2.0.8.
- Returns reference since 3.7.0.
