# nlohmann::basic_json::object

```
static basic_json object(initializer_list_t init = {});
```

Creates a JSON object value from a given initializer list. The initializer lists elements must be pairs, and their first elements must be strings. If the initializer list is empty, the empty object `{}` is created.

## Parameters

`init` (in) : initializer list with JSON values to create an object from (optional)

## Return value

JSON object value

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

## Exceptions

Throws [`type_error.301`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error301) if `init` is not a list of pairs whose first elements are strings. In this case, no object can be created. When such a value is passed to `basic_json(initializer_list_t, bool, value_t)`, an array would have been created from the passed initializer list `init`. See the example below.

## Complexity

Linear in the size of `init`.

## Notes

This function is only added for symmetry reasons. In contrast to the related function `array(initializer_list_t)`, there are no cases that can only be expressed by this function. That is, any initializer list `init` can also be passed to the initializer list constructor `basic_json(initializer_list_t, bool, value_t)`.

## Examples

Example

The following code shows an example for the `object` function.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create JSON objects
    json j_no_init_list = json::object();
    json j_empty_init_list = json::object({});
    json j_list_of_pairs = json::object({ {"one", 1}, {"two", 2} });

    // serialize the JSON objects
    std::cout << j_no_init_list << '\n';
    std::cout << j_empty_init_list << '\n';
    std::cout << j_list_of_pairs << '\n';

    // example for an exception
    try
    {
        // can only create an object from a list of pairs
        json j_invalid_object = json::object({{ "one", 1, 2 }});
    }
    catch (const json::type_error& e)
    {
        std::cout << e.what() << '\n';
    }
}
```

Output:

```
{}
{}
{"one":1,"two":2}
[json.exception.type_error.301] cannot create object from initializer list
```

## See also

- [`basic_json(initializer_list_t)`](https://json.nlohmann.me/api/basic_json/basic_json/index.md) - create a JSON value from an initializer list
- [`array`](https://json.nlohmann.me/api/basic_json/array/index.md) - create a JSON array value from an initializer list
- [Creating JSON values](https://json.nlohmann.me/features/creating_values/index.md) - the article on creating JSON values

## Version history

- Added in version 1.0.0.
