# nlohmann::basic_json::erase

```
// (1)
iterator erase(iterator pos);
const_iterator erase(const_iterator pos);

// (2)
iterator erase(iterator first, iterator last);
const_iterator erase(const_iterator first, const_iterator last);

// (3)
size_type erase(const typename object_t::key_type& key);

// (4)
template<typename KeyType>
size_type erase(KeyType&& key);

// (5)
void erase(const size_type idx);
```

1. Removes an element from a JSON value specified by iterator `pos`. The iterator `pos` must be valid and dereferenceable. Thus, the `end()` iterator (which is valid, but is not dereferenceable) cannot be used as a value for `pos`.

   If called on a primitive type other than `null`, the resulting JSON value will be `null`.

1. Remove an element range specified by `[first; last)` from a JSON value. The iterator `first` does not need to be dereferenceable if `first == last`: erasing an empty range is a no-op.

   If called on a primitive type other than `null`, the resulting JSON value will be `null`.

1. Removes an element from a JSON object by key.

1. See 3. This overload is only available if `KeyType` is comparable with `typename object_t::key_type` and `typename object_comparator_t::is_transparent` denotes a type.

1. Removes an element from a JSON array by index.

## Template parameters

`KeyType` : A type for an object key other than [`json_pointer`](https://json.nlohmann.me/api/json_pointer/index.md) that is comparable with [`string_t`](https://json.nlohmann.me/api/basic_json/string_t/index.md) using [`object_comparator_t`](https://json.nlohmann.me/api/basic_json/object_comparator_t/index.md). This can also be a string view (C++17).

## Parameters

`pos` (in) : iterator to the element to remove

`first` (in) : iterator to the beginning of the range to remove

`last` (in) : iterator past the end of the range to remove

`key` (in) : object key of the elements to remove

`idx` (in) : array index of the element to remove

## Return value

1. Iterator following the last removed element. If the iterator `pos` refers to the last element, the `end()` iterator is returned.
1. Iterator following the last removed element. If the iterator `last` refers to the last element, the `end()` iterator is returned.
1. Number of elements removed. If `ObjectType` is the default `std::map` type, the return value will always be `0` (`key` was not found) or `1` (`key` was found).
1. See 3.
1. (none)

## Exception safety

Strong exception safety: if an exception occurs, the original value stays intact.

## Exceptions

1. The function can throw the following exceptions:
   - Throws [`type_error.307`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error307) if called on a `null` value; example: `"cannot use erase() with null"`
   - Throws [`invalid_iterator.202`](https://json.nlohmann.me/home/exceptions/#jsonexceptioninvalid_iterator202) if called on an iterator which does not belong to the current JSON value; example: `"iterator does not fit current value"`
   - Throws [`invalid_iterator.205`](https://json.nlohmann.me/home/exceptions/#jsonexceptioninvalid_iterator205) if called on a primitive type with invalid iterator (i.e., any iterator which is not `begin()`); example: `"iterator out of range"`
1. The function can throw the following exceptions:
   - Throws [`type_error.307`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error307) if called on a `null` value; example: `"cannot use erase() with null"`
   - Throws [`invalid_iterator.203`](https://json.nlohmann.me/home/exceptions/#jsonexceptioninvalid_iterator203) if called on iterators which does not belong to the current JSON value; example: `"iterators do not fit current value"`
   - Throws [`invalid_iterator.204`](https://json.nlohmann.me/home/exceptions/#jsonexceptioninvalid_iterator204) if called on a primitive type with invalid iterators (i.e., if `first != begin()` and `last != end()`); example: `"iterators out of range"`
1. The function can throw the following exceptions:
   - Throws [`type_error.307`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error307) when called on a type other than JSON object; example: `"cannot use erase() with null"`
1. See 3.
1. The function can throw the following exceptions:
   - Throws [`type_error.307`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error307) when called on a type other than JSON array; example: `"cannot use erase() with null"`
   - Throws [`out_of_range.401`](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range401) when `idx >= size()`; example: `"array index 17 is out of range"`

## Complexity

1. The complexity depends on the type:
   - objects: amortized constant
   - arrays: linear in distance between `pos` and the end of the container
   - strings and binary: linear in the length of the member
   - other types: constant
1. The complexity depends on the type:
   - objects: `log(size()) + std::distance(first, last)`
   - arrays: linear in the distance between `first` and `last`, plus linear in the distance between `last` and end of the container
   - strings and binary: linear in the length of the member
   - other types: constant
1. `log(size()) + count(key)`
1. `log(size()) + count(key)`
1. Linear in distance between `idx` and the end of the container.

## Notes

1. Invalidates iterators and references at or after the point of the `erase`, including the `end()` iterator.
1. (none)
1. References and iterators to the erased elements are invalidated. Other references and iterators are not affected.
1. See 3.
1. (none)

## Examples

Example: (1) remove element given an iterator

The example shows the effect of `erase()` for different JSON types using an iterator.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create JSON values
    json j_boolean = true;
    json j_number_integer = 17;
    json j_number_float = 23.42;
    json j_object = {{"one", 1}, {"two", 2}};
    json j_array = {1, 2, 4, 8, 16};
    json j_string = "Hello, world";

    // call erase()
    j_boolean.erase(j_boolean.begin());
    j_number_integer.erase(j_number_integer.begin());
    j_number_float.erase(j_number_float.begin());
    j_object.erase(j_object.find("two"));
    j_array.erase(j_array.begin() + 2);
    j_string.erase(j_string.begin());

    // print values
    std::cout << j_boolean << '\n';
    std::cout << j_number_integer << '\n';
    std::cout << j_number_float << '\n';
    std::cout << j_object << '\n';
    std::cout << j_array << '\n';
    std::cout << j_string << '\n';
}
```

Output:

```
null
null
null
{"one":1}
[1,2,8,16]
null
```

Example: (2) remove elements given an iterator range

The example shows the effect of `erase()` for different JSON types using an iterator range.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create JSON values
    json j_boolean = true;
    json j_number_integer = 17;
    json j_number_float = 23.42;
    json j_object = {{"one", 1}, {"two", 2}};
    json j_array = {1, 2, 4, 8, 16};
    json j_string = "Hello, world";

    // call erase()
    j_boolean.erase(j_boolean.begin(), j_boolean.end());
    j_number_integer.erase(j_number_integer.begin(), j_number_integer.end());
    j_number_float.erase(j_number_float.begin(), j_number_float.end());
    j_object.erase(j_object.find("two"), j_object.end());
    j_array.erase(j_array.begin() + 1, j_array.begin() + 3);
    j_string.erase(j_string.begin(), j_string.end());

    // print values
    std::cout << j_boolean << '\n';
    std::cout << j_number_integer << '\n';
    std::cout << j_number_float << '\n';
    std::cout << j_object << '\n';
    std::cout << j_array << '\n';
    std::cout << j_string << '\n';
}
```

Output:

```
null
null
null
{"one":1}
[1,8,16]
null
```

Example: (3) remove element from a JSON object given a key

The example shows the effect of `erase()` for different JSON types using an object key.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create a JSON object
    json j_object = {{"one", 1}, {"two", 2}};

    // call erase()
    auto count_one = j_object.erase("one");
    auto count_three = j_object.erase("three");

    // print values
    std::cout << j_object << '\n';
    std::cout << count_one << " " << count_three << '\n';
}
```

Output:

```
{"two":2}
1 0
```

Example: (4) remove element from a JSON object given a key using string_view

The example shows the effect of `erase()` for different JSON types using an object key.

```
#include <iostream>
#include <string_view>
#include <nlohmann/json.hpp>

using namespace std::string_view_literals;
using json = nlohmann::json;

int main()
{
    // create a JSON object
    json j_object = {{"one", 1}, {"two", 2}};

    // call erase()
    auto count_one = j_object.erase("one"sv);
    auto count_three = j_object.erase("three"sv);

    // print values
    std::cout << j_object << '\n';
    std::cout << count_one << " " << count_three << '\n';
}
```

Output:

```
{"two":2}
1 0
```

Example: (5) remove element from a JSON array given an index

The example shows the effect of `erase()` using an array index.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create a JSON array
    json j_array = {0, 1, 2, 3, 4, 5};

    // call erase()
    j_array.erase(2);

    // print values
    std::cout << j_array << '\n';
}
```

Output:

```
[0,1,3,4,5]
```

## See also

- [clear](https://json.nlohmann.me/api/basic_json/clear/index.md) clears the contents
- [insert](https://json.nlohmann.me/api/basic_json/insert/index.md) add values to an array/object
- [Modifying values](https://json.nlohmann.me/features/modifying_values/index.md) - the article on modifying values

## Version history

1. Added in version 1.0.0. Added support for binary types in version 3.8.0.
1. Added in version 1.0.0. Added support for binary types in version 3.8.0.
1. Added in version 1.0.0.
1. Added in version 3.11.0.
1. Added in version 1.0.0.
