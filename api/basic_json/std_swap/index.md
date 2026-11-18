# std::swap\<basic_json>

```
namespace std {
    void swap(nlohmann::basic_json& j1, nlohmann::basic_json& j2) noexcept(
        is_nothrow_move_constructible<nlohmann::basic_json>::value &&
        is_nothrow_move_assignable<nlohmann::basic_json>::value
    );
}
```

Exchanges the values of two JSON objects.

This specialization is only provided before C++20, which no longer allows specializing function templates in namespace `std`. With C++20 (and in generic code with any standard), use the idiom `using std::swap; swap(j1, j2);`: it finds the [`swap`](https://json.nlohmann.me/api/basic_json/swap/index.md) friend function (overload 2) by argument-dependent lookup. A qualified `std::swap(j1, j2)` still compiles with C++20, but uses the generic `std::swap`, which swaps by three moves instead of exchanging the contents.

## Parameters

`j1` (in, out) : value to be replaced by `j2`

`j2` (in, out) : value to be replaced by `j1`

## Exception safety

No-throw guarantee if the `noexcept` condition above holds: it holds unless moving the [`json_base_class_t`](https://json.nlohmann.me/api/basic_json/json_base_class_t/index.md) can throw. With the default base class, this function never throws exceptions.

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

using nlohmann::json;

int main()
{
    // create JSON values
    json j1 = {{"one", 1}, {"two", 2}};
    json j2 = {1, 2, 4, 8, 16};

    std::cout << "j1 = " << j1 << " | j2 = " << j2 << '\n';

    // swap values
    std::swap(j1, j2);

    std::cout << "j1 = " << j1 << " | j2 = " << j2 << '\n';
}
```

Output:

```
j1 = {"one":1,"two":2} | j2 = [1,2,4,8,16]
j1 = [1,2,4,8,16] | j2 = {"one":1,"two":2}
```

## See also

- [`swap`](https://json.nlohmann.me/api/basic_json/swap/index.md) - exchange the contents of two JSON values

## Version history

- Added in version 1.0.0.
- Extended for arbitrary basic_json types in version 3.10.5.
- Not provided with C++20 since version 3.9.0.
