# std::swap\<basic_json>

```
namespace std {
    void swap(nlohmann::basic_json& j1, nlohmann::basic_json& j2);
}
```

Exchanges the values of two JSON objects.

## Parameters

`j1` (in, out) : value to be replaced by `j2`

`j2` (in, out) : value to be replaced by `j1`

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Possible implementation

```
void swap(nlohmann::basic_json& j1, nlohmann::basic_json& j2)
{
    j1.swap(j2);
}
```

## Examples

Example

The following code shows how two values are swapped with `std::swap`.

```
#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create JSON values
    json j1 = {{"one", 1}, {"two", 2}};
    json j2 = {1, 2, 4, 8, 16};

    std::cout << "j1 = " << j1 << " | j2 = " << j2 << '\n';

    // swap values
    std::swap(j1, j2);

    std::cout << "j1 = " << j1 << " | j2 = " << j2 << std::endl;
}
```

Output:

```
j1 = {"one":1,"two":2} | j2 = [1,2,4,8,16]
j1 = [1,2,4,8,16] | j2 = {"one":1,"two":2}
```

## See also

- [swap](https://json.nlohmann.me/api/basic_json/swap/index.md)

## Version history

- Added in version 1.0.0.
- Extended for arbitrary basic_json types in version 3.10.5.
