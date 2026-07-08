# nlohmann::basic_json::operator\<=>

```
// since C++20
class basic_json {
    std::partial_ordering operator<=>(const_reference rhs) const noexcept;  // (1)

    template<typename ScalarType>
    std::partial_ordering operator<=>(const ScalarType rhs) const noexcept; // (2)
};
```

1. 3-way compares two JSON values producing a result of type `std::partial_ordering` according to the following rules:

   - Two JSON values compare with a result of `std::partial_ordering::unordered` if either value is discarded.
   - If both JSON values are of the same type, the result is produced by 3-way comparing their stored values using their respective `operator<=>`.
   - Integer and floating-point numbers are converted to their common type and then 3-way compared using their respective `operator<=>`. For instance, comparing an integer and a floating-point value will 3-way compare the first value converted to floating-point with the second value.
   - Otherwise, yields a result by comparing the type (see [`value_t`](https://json.nlohmann.me/api/basic_json/value_t/index.md)).

1. 3-way compares a JSON value and a scalar or a scalar and a JSON value by converting the scalar to a JSON value and 3-way comparing both JSON values (see 1).

## Template parameters

`ScalarType` : a scalar type according to `std::is_scalar<ScalarType>::value`

## Parameters

`rhs` (in) : second value to consider

## Return value

the `std::partial_ordering` of the 3-way comparison of `*this` and `rhs`

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Linear.

## Notes

Comparing `NaN`

- `NaN` values are unordered within the domain of numbers. The following comparisons all yield `std::partial_ordering::unordered`:
  1. Comparing a `NaN` with itself.
  1. Comparing a `NaN` with another `NaN`.
  1. Comparing a `NaN` and any other number.

## Examples

Example: (1) comparing JSON values

The example demonstrates comparing several JSON values.

```
#include <compare>
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

const char* to_string(const std::partial_ordering& po)
{
    if (std::is_lt(po))
    {
        return "less";
    }
    else if (std::is_gt(po))
    {
        return "greater";
    }
    else if (std::is_eq(po))
    {
        return "equivalent";
    }
    return "unordered";
}

int main()
{
    // create several JSON values
    json array_1 = {1, 2, 3};
    json array_2 = {1, 2, 4};
    json object_1 = {{"A", "a"}, {"B", "b"}};
    json object_2 = {{"B", "b"}, {"A", "a"}};
    json number = 17;
    json string = "foo";
    json discarded = json(json::value_t::discarded);

    // output values and comparisons
    std::cout << array_1 << " <=> " << array_2 << " := " << to_string(array_1 <=> array_2) << '\n'; // *NOPAD*
    std::cout << object_1 << " <=> " << object_2 << " := " << to_string(object_1 <=> object_2) << '\n'; // *NOPAD*
    std::cout << string << " <=> " << number << " := " << to_string(string <=> number) << '\n'; // *NOPAD*
    std::cout << string << " <=> " << discarded << " := " << to_string(string <=> discarded) << '\n'; // *NOPAD*
}
```

Output:

```
[1,2,3] <=> [1,2,4] := less
{"A":"a","B":"b"} <=> {"A":"a","B":"b"} := equivalent
"foo" <=> 17 := greater
"foo" <=> <discarded> := unordered
```

Example: (2) comparing JSON values and scalars

The example demonstrates comparing several JSON values and scalars.

```
#include <compare>
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

const char* to_string(const std::partial_ordering& po)
{
    if (std::is_lt(po))
    {
        return "less";
    }
    else if (std::is_gt(po))
    {
        return "greater";
    }
    else if (std::is_eq(po))
    {
        return "equivalent";
    }
    return "unordered";
}

int main()
{
    using float_limits = std::numeric_limits<json::number_float_t>;
    constexpr auto nan = float_limits::quiet_NaN();

    // create several JSON values
    json boolean = false;
    json number = 17;
    json string = "17";

    // output values and comparisons
    std::cout << std::boolalpha << std::fixed;
    std::cout << boolean << " <=> " << true << " := " << to_string(boolean <=> true) << '\n'; // *NOPAD*
    std::cout << number << " <=> " << 17.0 << " := " << to_string(number <=> 17.0) << '\n'; // *NOPAD*
    std::cout << number << " <=> " << nan << " := " << to_string(number <=> nan) << '\n'; // *NOPAD*
    std::cout << string << " <=> " << 17 << " := " << to_string(string <=> 17) << '\n'; // *NOPAD*
}
```

Output:

```
false <=> true := less
17 <=> 17.000000 := equivalent
17 <=> nan := unordered
"17" <=> 17 := greater
```

## See also

- [**operator==**](https://json.nlohmann.me/api/basic_json/operator_eq/index.md) - comparison: equal
- [**operator!=**](https://json.nlohmann.me/api/basic_json/operator_ne/index.md) - comparison: not equal
- [**operator\<**](https://json.nlohmann.me/api/basic_json/operator_lt/index.md) - comparison: less than
- [**operator\<=**](https://json.nlohmann.me/api/basic_json/operator_le/index.md) - comparison: less than or equal
- [**operator>**](https://json.nlohmann.me/api/basic_json/operator_gt/index.md) - comparison: greater than
- [**operator>=**](https://json.nlohmann.me/api/basic_json/operator_ge/index.md) - comparison: greater than or equal

## Version history

1. Added in version 3.11.0.
1. Added in version 3.11.0.
