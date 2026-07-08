# nlohmann::basic_json::swap

```
// (1)
void swap(reference other) noexcept (
    std::is_nothrow_move_constructible<value_t>::value &&
    std::is_nothrow_move_assignable<value_t>::value &&
    std::is_nothrow_move_constructible<json_value>::value &&
    std::is_nothrow_move_assignable<json_value>::value
);

// (2)
friend void swap(reference left, reference right) noexcept (
    std::is_nothrow_move_constructible<value_t>::value &&
    std::is_nothrow_move_assignable<value_t>::value &&
    std::is_nothrow_move_constructible<json_value>::value &&
    std::is_nothrow_move_assignable<json_value>::value
);

// (3)
void swap(array_t& other);

// (4)
void swap(object_t& other);

// (5)
void swap(string_t& other);

// (6)
void swap(binary_t& other);

// (7)
void swap(typename binary_t::container_type& other);
```

1. Exchanges the contents of the JSON value with those of `other`. Does not invoke any move, copy, or swap operations on individual elements. All iterators and references remain valid. The past-the-end iterator is invalidated.
1. Exchanges the contents of the JSON value from `left` with those of `right`. Does not invoke any move, copy, or swap operations on individual elements. All iterators and references remain valid. The past-the-end iterator is invalidated. Implemented as a friend function callable via ADL.
1. Exchanges the contents of a JSON array with those of `other`. Does not invoke any move, copy, or swap operations on individual elements. All iterators and references remain valid. The past-the-end iterator is invalidated.
1. Exchanges the contents of a JSON object with those of `other`. Does not invoke any move, copy, or swap operations on individual elements. All iterators and references remain valid. The past-the-end iterator is invalidated.
1. Exchanges the contents of a JSON string with those of `other`. Does not invoke any move, copy, or swap operations on individual elements. All iterators and references remain valid. The past-the-end iterator is invalidated.
1. Exchanges the contents of a binary value with those of `other`. Does not invoke any move, copy, or swap operations on individual elements. All iterators and references remain valid. The past-the-end iterator is invalidated.
1. Exchanges the contents of a binary value with those of `other`. Does not invoke any move, copy, or swap operations on individual elements. All iterators and references remain valid. The past-the-end iterator is invalidated. Unlike version (6), no binary subtype is involved.

## Parameters

`other` (in, out) : value to exchange the contents with

`left` (in, out) : value to exchange the contents with

`right` (in, out) : value to exchange the contents with

## Exceptions

1. No-throw guarantee: this function never throws exceptions.
1. No-throw guarantee: this function never throws exceptions.
1. Throws [`type_error.310`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error310) if called on JSON values other than arrays; example: `"cannot use swap(array_t&) with boolean"`
1. Throws [`type_error.310`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error310) if called on JSON values other than objects; example: `"cannot use swap(object_t&) with boolean"`
1. Throws [`type_error.310`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error310) if called on JSON values other than strings; example: `"cannot use swap(string_t&) with boolean"`
1. Throws [`type_error.310`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error310) if called on JSON values other than binaries; example: `"cannot use swap(binary_t&) with boolean"`
1. Throws [`type_error.310`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error310) if called on JSON values other than binaries; example: `"cannot use swap(binary_t::container_type&) with boolean"`

## Complexity

Constant.

## Examples

Example: Swap JSON value (1, 2)

The example below shows how JSON values can be swapped with `swap()`.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create two JSON values
    json j1 = {1, 2, 3, 4, 5};
    json j2 = {{"pi", 3.141592653589793}, {"e", 2.718281828459045}};

    // swap the values
    j1.swap(j2);

    // output the values
    std::cout << "j1 = " << j1 << '\n';
    std::cout << "j2 = " << j2 << '\n';
}
```

Output:

```
j1 = {"e":2.718281828459045,"pi":3.141592653589793}
j2 = [1,2,3,4,5]
```

Example: Swap array (3)

The example below shows how arrays can be swapped with `swap()`.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create a JSON value
    json value = {{"array", {1, 2, 3, 4}}};

    // create an array_t
    json::array_t array = {"Snap", "Crackle", "Pop"};

    // swap the array stored in the JSON value
    value["array"].swap(array);

    // output the values
    std::cout << "value = " << value << '\n';
    std::cout << "array = " << array << '\n';
}
```

Output:

```
value = {"array":["Snap","Crackle","Pop"]}
array = [1,2,3,4]
```

Example: Swap object (4)

The example below shows how objects can be swapped with `swap()`.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create a JSON value
    json value = { {"translation", {{"one", "eins"}, {"two", "zwei"}}} };

    // create an object_t
    json::object_t object = {{"cow", "Kuh"}, {"dog", "Hund"}};

    // swap the object stored in the JSON value
    value["translation"].swap(object);

    // output the values
    std::cout << "value = " << value << '\n';
    std::cout << "object = " << object << '\n';
}
```

Output:

```
value = {"translation":{"cow":"Kuh","dog":"Hund"}}
object = {"one":"eins","two":"zwei"}
```

Example: Swap string (5)

The example below shows how strings can be swapped with `swap()`.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create a JSON value
    json value = { "the good", "the bad", "the ugly" };

    // create string_t
    json::string_t string = "the fast";

    // swap the object stored in the JSON value
    value[1].swap(string);

    // output the values
    std::cout << "value = " << value << '\n';
    std::cout << "string = " << string << '\n';
}
```

Output:

```
value = ["the good","the fast","the ugly"]
string = the bad
```

Example: Swap binary (6)

The example below shows how binary values can be swapped with `swap()`.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create a binary value
    json value = json::binary({1, 2, 3});

    // create a binary_t
    json::binary_t binary = {{4, 5, 6}};

    // swap the object stored in the JSON value
    value.swap(binary);

    // output the values
    std::cout << "value = " << value << '\n';
    std::cout << "binary = " << json(binary) << '\n';
}
```

Output:

```
value = {"bytes":[4,5,6],"subtype":null}
binary = {"bytes":[1,2,3],"subtype":null}
```

## See also

- [std::swap\<basic_json>](https://json.nlohmann.me/api/basic_json/std_swap/index.md)
- [operator=](https://json.nlohmann.me/api/basic_json/operator%3D/index.md) copy assignment
- [basic_json](https://json.nlohmann.me/api/basic_json/basic_json/index.md) create a JSON value

## Version history

1. Since version 1.0.0.
1. Since version 1.0.0.
1. Since version 1.0.0.
1. Since version 1.0.0.
1. Since version 1.0.0.
1. Since version 3.8.0.
1. Since version 3.8.0.
