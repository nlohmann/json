# nlohmann::json_pointer::operator==

```
// until C++20
template<typename RefStringTypeLhs, typename RefStringTypeRhs>
bool operator==(
    const json_pointer<RefStringTypeLhs>& lhs,
    const json_pointer<RefStringTypeRhs>& rhs) noexcept;            // (1)

template<typename RefStringTypeLhs, typename StringType>
bool operator==(
    const json_pointer<RefStringTypeLhs>& lhs,
    const StringType& rhs);                                         // (2)

template<typename RefStringTypeRhs, typename StringType>
bool operator==(
    const StringType& lhs,
    const json_pointer<RefStringTypeRhs>& rhs);                     // (2)

// since C++20
class json_pointer {
    template<typename RefStringTypeRhs>
    bool operator==(
        const json_pointer<RefStringTypeRhs>& rhs) const noexcept;  // (1)

    bool operator==(const string_t& rhs) const;                     // (2)
};
```

1. Compares two JSON pointers for equality by comparing their reference tokens.
1. Compares a JSON pointer and a string or a string and a JSON pointer for equality by converting the string to a JSON pointer and comparing the JSON pointers according to 1.

## Template parameters

`RefStringTypeLhs`, `RefStringTypeRhs` : the string type of the left-hand side or right-hand side JSON pointer, respectively

`StringType` : the string type derived from the `json_pointer` operand ([`json_pointer::string_t`](https://json.nlohmann.me/api/json_pointer/string_t/index.md))

## Parameters

`lhs` (in) : first value to consider

`rhs` (in) : second value to consider

## Return value

whether the values `lhs`/`*this` and `rhs` are equal

## Exception safety

1. No-throw guarantee: this function never throws exceptions.
1. Strong exception safety: if an exception occurs, the original value stays intact.

## Exceptions

1. (none)
1. The function can throw the following exceptions:
1. Throws [parse_error.107](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error107) if the given JSON pointer `s` is nonempty and does not begin with a slash (`/`); see example below.
1. Throws [parse_error.108](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error108) if a tilde (`~`) in the given JSON pointer `s` is not followed by `0` (representing `~`) or `1` (representing `/`); see example below.

## Complexity

Constant if `lhs` and `rhs` differ in the number of reference tokens, otherwise linear in the number of reference tokens.

## Notes

Deprecation

Overload 2 is deprecated and will be removed in a future major version release.

## Examples

Example: (1) Comparing JSON pointers

The example demonstrates comparing JSON pointers.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // different JSON pointers
    json::json_pointer ptr0;
    json::json_pointer ptr1("");
    json::json_pointer ptr2("/foo");

    // compare JSON pointers
    std::cout << std::boolalpha
              << "\"" << ptr0 << "\" == \"" << ptr0 << "\": " << (ptr0 == ptr0) << '\n'
              << "\"" << ptr0 << "\" == \"" << ptr1 << "\": " << (ptr0 == ptr1) << '\n'
              << "\"" << ptr1 << "\" == \"" << ptr2 << "\": " << (ptr1 == ptr2) << '\n'
              << "\"" << ptr2 << "\" == \"" << ptr2 << "\": " << (ptr2 == ptr2) << std::endl;
}
```

Output:

```
"" == "": true
"" == "": true
"" == "/foo": false
"/foo" == "/foo": true
```

Example: (2) Comparing JSON pointers and strings

The example demonstrates comparing JSON pointers and strings, and when doing so may raise an exception.

```
#include <exception>
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // different JSON pointers
    json::json_pointer ptr0;
    json::json_pointer ptr1("");
    json::json_pointer ptr2("/foo");

    // different strings
    std::string str0("");
    std::string str1("/foo");
    std::string str2("bar");

    // compare JSON pointers and strings
    std::cout << std::boolalpha
              << "\"" << ptr0 << "\" == \"" << str0 << "\": " << (ptr0 == str0) << '\n'
              << "\"" << str0 << "\" == \"" << ptr1 << "\": " << (str0 == ptr1) << '\n'
              << "\"" << ptr2 << "\" == \"" << str1 << "\": " << (ptr2 == str1) << std::endl;

    try
    {
        std::cout << "\"" << str2 << "\" == \"" << ptr2 << "\": " << (str2 == ptr2) << std::endl;
    }
    catch (const json::parse_error& ex)
    {
        std::cout << ex.what() << std::endl;
    }
}
```

Output:

```
"" == "": true
"" == "": true
"/foo" == "/foo": true
"bar" == "/foo": [json.exception.parse_error.107] parse error at byte 1: JSON pointer must be empty or begin with '/' - was: 'bar'
```

## Version history

1. Added in version 2.1.0. Added C++20 member functions in version 3.11.2.
1. Added for backward compatibility and deprecated in version 3.11.2.
