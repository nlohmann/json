# nlohmann::basic_json::emplace

```
template<class... Args>
std::pair<iterator, bool> emplace(Args&& ... args);
```

Inserts a new element into a JSON object constructed in-place with the given `args` if there is no element with the key in the container. If the function is called on a JSON null value, an empty object is created before appending the value created from `args`.

## Template parameters

`Args` : compatible types to create a `basic_json` object

## Iterator invalidation

For [`ordered_json`](https://json.nlohmann.me/api/ordered_json/index.md), adding a value to an object can yield a reallocation, in which case all iterators (including the `end()` iterator) and all references to the elements are invalidated.

## Parameters

`args` (in) : arguments to forward to a constructor of `basic_json`

## Return value

a pair consisting of an iterator to the inserted element, or the already-existing element if no insertion happened, and a `bool` denoting whether the insertion took place.

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes to any JSON value.

## Exceptions

Throws [`type_error.311`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error311) when called on a type other than JSON object or `null`; example: `"cannot use emplace() with number"`

## Complexity

Logarithmic in the size of the container, O(log(`size()`)).

## Examples

Example

The example shows how `emplace()` can be used to add elements to a JSON object. Note how the `null` value was silently converted to a JSON object. Further note how no value is added if there was already one value stored with the same key.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create JSON values
    json object = {{"one", 1}, {"two", 2}};
    json null;

    // print values
    std::cout << object << '\n';
    std::cout << null << '\n';

    // add values
    auto res1 = object.emplace("three", 3);
    null.emplace("A", "a");
    null.emplace("B", "b");

    // the following call will not add an object, because there is already
    // a value stored at key "B"
    auto res2 = null.emplace("B", "c");

    // print values
    std::cout << object << '\n';
    std::cout << *res1.first << " " << std::boolalpha << res1.second << '\n';

    std::cout << null << '\n';
    std::cout << *res2.first << " " << std::boolalpha << res2.second << '\n';
}
```

Output:

```
{"one":1,"two":2}
null
{"one":1,"three":3,"two":2}
3 true
{"A":"a","B":"b"}
"b" false
```

## See also

- [emplace_back](https://json.nlohmann.me/api/basic_json/emplace_back/index.md) add a value to an array
- [insert](https://json.nlohmann.me/api/basic_json/insert/index.md) add values to an array/object
- [Modifying values](https://json.nlohmann.me/features/modifying_values/index.md) - the article on modifying values

## Version history

- Since version 2.0.8.
