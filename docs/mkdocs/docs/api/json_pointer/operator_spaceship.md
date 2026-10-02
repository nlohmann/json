# <small>nlohmann::json_pointer::</small>operator<=>

```cpp
// since C++20
class json_pointer {
    template<typename RefStringTypeRhs>
    std::strong_ordering operator<=>(const json_pointer<RefStringTypeRhs>& rhs) const noexcept; // *NOPAD*
};
```

3-way compares two JSON pointers by lexicographically comparing their sequences of reference tokens: corresponding
reference tokens are compared with `string_t`'s own `operator<=>`, and the first pair of tokens that differs
determines the result. If all corresponding reference tokens compare equal, the JSON pointer with fewer reference
tokens is ordered first.

## Template parameters

`RefStringTypeRhs`
:   the string type of the right-hand side JSON pointer

## Parameters

`rhs` (in)
:   JSON pointer to compare `*this` with

## Return value

the `std::strong_ordering` of the 3-way comparison of `*this` and `rhs`

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Linear in the number of reference tokens.

## Notes

!!! note "Ordering enables use as an associative container key"

    Together with [`operator==`](operator_eq.md), `operator<=>` makes `json_pointer` a `LessThanComparable` type, so
    it can be used as the key type of ordered associative containers such as `std::map` or `std::set`.

!!! note "Before C++20"

    Without C++20's three-way comparison, `json_pointer` provides a non-member `operator<` instead, which orders JSON
    pointers the same way. JSON pointers can therefore be used as keys of ordered associative containers with any
    supported C++ standard.

## Examples

??? example

    The example demonstrates 3-way comparing JSON pointers.

    ```cpp
    --8<-- "examples/json_pointer__operator_spaceship.c++20.cpp"
    ```

    Output:

    ```
    --8<-- "examples/json_pointer__operator_spaceship.c++20.output"
    ```

## See also

- [operator==](operator_eq.md) compare: equal
- [operator!=](operator_ne.md) compare: not equal

## Version history

- Added in version 3.11.2.
