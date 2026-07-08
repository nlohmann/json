# nlohmann::basic_json::array

```
static basic_json array(initializer_list_t init = {});
```

Creates a JSON array value from a given initializer list. That is, given a list of values `a, b, c`, creates the JSON value `[a, b, c]`. If the initializer list is empty, the empty array `[]` is created.

## Parameters

`init` (in) : initializer list with JSON values to create an array from (optional)

## Return value

JSON array value

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

## Complexity

Linear in the size of `init`.

## Notes

This function is only needed to express two edge cases that cannot be realized with the initializer list constructor ([`basic_json(initializer_list_t, bool, value_t)`](https://json.nlohmann.me/api/basic_json/basic_json/index.md)). These cases are:

1. creating an array whose elements are all pairs whose first element is a string -- in this case, the initializer list constructor would create an object, taking the first elements as keys
1. creating an empty array -- passing the empty initializer list to the initializer list constructor yields an empty object

## Examples

Example

The following code shows an example for the `array` function.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create JSON arrays
    json j_no_init_list = json::array();
    json j_empty_init_list = json::array({});
    json j_nonempty_init_list = json::array({1, 2, 3, 4});
    json j_list_of_pairs = json::array({ {"one", 1}, {"two", 2} });

    // serialize the JSON arrays
    std::cout << j_no_init_list << '\n';
    std::cout << j_empty_init_list << '\n';
    std::cout << j_nonempty_init_list << '\n';
    std::cout << j_list_of_pairs << '\n';
}
```

Output:

```
[]
[]
[1,2,3,4]
[["one",1],["two",2]]
```

## See also

- [`basic_json(initializer_list_t)`](https://json.nlohmann.me/api/basic_json/basic_json/index.md) - create a JSON value from an initializer list
- [`object`](https://json.nlohmann.me/api/basic_json/object/index.md) - create a JSON object value from an initializer list
- [Creating JSON values](https://json.nlohmann.me/features/creating_values/index.md) - the article on creating JSON values

## Version history

- Added in version 1.0.0.
