# nlohmann::json_pointer::operator\<=>

```
// since C++20
class json_pointer {
    template<typename RefStringTypeRhs>
    std::strong_ordering operator<=>(const json_pointer<RefStringTypeRhs>& rhs) const noexcept; // *NOPAD*
};
```

3-way compares two JSON pointers by lexicographically comparing their sequences of reference tokens: corresponding reference tokens are compared with `string_t`'s own `operator<=>`, and the first pair of tokens that differs determines the result. If all corresponding reference tokens compare equal, the JSON pointer with fewer reference tokens is ordered first.

## Template parameters

`RefStringTypeRhs` : the string type of the right-hand side JSON pointer

## Parameters

`rhs` (in) : JSON pointer to compare `*this` with

## Return value

the `std::strong_ordering` of the 3-way comparison of `*this` and `rhs`

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Linear in the number of reference tokens.

## Notes

Ordering enables use as an associative container key

Together with [`operator==`](https://json.nlohmann.me/api/json_pointer/operator_eq/index.md), `operator<=>` makes `json_pointer` a `LessThanComparable` type, so it can be used as the key type of ordered associative containers such as `std::map` or `std::set`.

Before C++20

Without C++20's three-way comparison, `json_pointer` provides a non-member `operator<` instead, which orders JSON pointers the same way. JSON pointers can therefore be used as keys of ordered associative containers with any supported C++ standard.

## Examples

Example

The example demonstrates 3-way comparing JSON pointers.

```
#include <compare>
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

const char* to_string(const std::strong_ordering& so)
{
    if (std::is_lt(so))
    {
        return "less";
    }
    else if (std::is_gt(so))
    {
        return "greater";
    }
    return "equal";
}

int main()
{
    // different JSON pointers
    json::json_pointer ptr1("/a/b");
    json::json_pointer ptr2("/a/c");
    json::json_pointer ptr3("/a/b/c");
    json::json_pointer ptr4("/a/b");

    // 3-way compare JSON pointers
    std::cout << "\"" << ptr1 << "\" <=> \"" << ptr2 << "\": " << to_string(ptr1 <=> ptr2) << '\n' // *NOPAD*
              << "\"" << ptr1 << "\" <=> \"" << ptr3 << "\": " << to_string(ptr1 <=> ptr3) << '\n' // *NOPAD*
              << "\"" << ptr1 << "\" <=> \"" << ptr4 << "\": " << to_string(ptr1 <=> ptr4) << std::endl; // *NOPAD*
}
```

Output:

```
"/a/b" <=> "/a/c": less
"/a/b" <=> "/a/b/c": less
"/a/b" <=> "/a/b": equal
```

## See also

- [operator==](https://json.nlohmann.me/api/json_pointer/operator_eq/index.md) compare: equal
- [operator!=](https://json.nlohmann.me/api/json_pointer/operator_ne/index.md) compare: not equal

## Version history

- Added in version 3.11.2.
