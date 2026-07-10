# nlohmann::basic_json::operator[]

```
// (1)
reference operator[](size_type idx);
const_reference operator[](size_type idx) const;

// (2)
reference operator[](typename object_t::key_type key);
const_reference operator[](const typename object_t::key_type& key) const;

// (3)
template<typename KeyType>
reference operator[](KeyType&& key);
template<typename KeyType>
const_reference operator[](KeyType&& key) const;

// (4)
reference operator[](const json_pointer& ptr);
const_reference operator[](const json_pointer& ptr) const;
```

1. Returns a reference to the array element at specified location `idx`.
1. Returns a reference to the object element with specified key `key`. The non-const qualified overload takes the key by value.
1. See 2. This overload is only available if `KeyType` is comparable with `typename object_t::key_type` and `typename object_comparator_t::is_transparent` denotes a type.
1. Returns a reference to the element with specified JSON pointer `ptr`.

## Template parameters

`KeyType` : A type for an object key other than [`json_pointer`](https://json.nlohmann.me/api/json_pointer/index.md) that is comparable with [`string_t`](https://json.nlohmann.me/api/basic_json/string_t/index.md) using [`object_comparator_t`](https://json.nlohmann.me/api/basic_json/object_comparator_t/index.md). This can also be a string view (C++17).

## Iterator invalidation

For the non-const versions 1. and 4., when passing an **array** index that does not exist, it is created and filled with a `null` value before a reference to it is returned. For this, a reallocation can happen, in which case all iterators (including the [`end()`](https://json.nlohmann.me/api/basic_json/end/index.md) iterator) and all references to the elements are invalidated.

For [`ordered_json`](https://json.nlohmann.me/api/ordered_json/index.md), also passing an **object key** to the non-const versions 2., 3., and 4., a reallocation can happen which again invalidates all iterators and all references.

## Parameters

`idx` (in) : index of the element to access

`key` (in) : object key of the element to access

`ptr` (in) : JSON pointer to the desired element

## Return value

1. (const) reference to the element at index `idx`
1. (const) reference to the element at key `key`
1. (const) reference to the element at key `key`
1. (const) reference to the element pointed to by `ptr`

## Exception safety

Strong exception safety: if an exception occurs, the original value stays intact.

## Exceptions

1. The function can throw the following exceptions:
   - Throws [`type_error.305`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error305) if the JSON value is not an array or null; in that case, using the `[]` operator with an index makes no sense.
1. The function can throw the following exceptions:
   - Throws [`type_error.305`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error305) if the JSON value is not an object or null; in that case, using the `[]` operator with a key makes no sense.
1. See 2.
1. The function can throw the following exceptions:
   - Throws [`parse_error.106`](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error106) if an array index in the passed JSON pointer `ptr` begins with '0'.
   - Throws [`parse_error.109`](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error109) if an array index in the passed JSON pointer `ptr` is not a number.
   - Throws [`out_of_range.402`](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range402) if the array index '-' is used in the passed JSON pointer `ptr` for the const version.
   - Throws [`out_of_range.404`](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range404) if the JSON pointer `ptr` can not be resolved.
   - Throws [`out_of_range.410`](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range410) if an array index in the passed JSON pointer `ptr` exceeds the range of `size_type` (e.g., on 32-bit platforms).

## Complexity

1. Constant if `idx` is in the range of the array. Otherwise, linear in `idx - size()`.
1. Logarithmic in the size of the container.
1. Logarithmic in the size of the container.
1. Logarithmic in the size of the container.

## Notes

Undefined behavior and runtime assertions

The following cases apply to the **const** overloads; the non-const overloads instead insert the missing element (see the notes below).

1. If the element at index `idx` does not exist, the behavior is undefined.

1. If the element with key `key` does not exist, the behavior is undefined and is **guarded by a [runtime assertion](https://json.nlohmann.me/features/assertions/index.md)**!

1. The non-const version may add values: If `idx` is beyond the range of the array (i.e., `idx >= size()`), then the array is silently filled up with `null` values to make `idx` a valid reference to the last stored element. In case the value was `null` before, it is converted to an array.

1. If `key` is not found in the object, then it is silently added to the object and filled with a `null` value to make `key` a valid reference. In case the value was `null` before, it is converted to an object.

1. See 2.

1. `null` values are created in arrays and objects if necessary.

   In particular:

   - If the JSON pointer points to an object key that does not exist, it is created and filled with a `null` value before a reference to it is returned.
   - If the JSON pointer points to an array index that does not exist, it is created and filled with a `null` value before a reference to it is returned. All indices between the current maximum and the given index are also filled with `null`.
   - The special value `-` is treated as a synonym for the index past the end.

   Creating intermediate levels that don't exist yet

   When the JSON pointer traverses intermediate levels that don't exist at all yet (not just a missing leaf), each missing level is created as an array or an object depending on whether the corresponding pointer token parses as a non-negative integer: a numeric token creates an array, a non-numeric token creates an object. For example, on an initially `null` value, `/foo/0/0/0` creates nested arrays, while `/foo/one/one/one` creates nested objects. This is not specified by the JSON Pointer RFC; it is this library's own, intentional disambiguation rule. See also [JSON Pointer](https://json.nlohmann.me/features/json_pointer/index.md).

## Examples

Example: (1) access specified array element

The example below shows how array elements can be read and written using `[]` operator. Note the addition of `null` values.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create a JSON array
    json array = {1, 2, 3, 4, 5};

    // output element at index 3 (fourth element)
    std::cout << array[3] << '\n';

    // change last element to 6
    array[array.size() - 1] = 6;

    // output changed array
    std::cout << array << '\n';

    // write beyond array limit
    array[10] = 11;

    // output changed array
    std::cout << array << '\n';
}
```

Output:

```
4
[1,2,3,4,6]
[1,2,3,4,6,null,null,null,null,null,11]
```

Example: (1) access specified array element (const)

The example below shows how array elements can be read using the `[]` operator.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create JSON array
    const json array = {"first", "2nd", "third", "fourth"};

    // output element at index 2 (third element)
    std::cout << array.at(2) << '\n';
}
```

Output:

```
"third"
```

Example: (2) access specified object element

The example below shows how object elements can be read and written using the `[]` operator.

```
#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create a JSON object
    json object =
    {
        {"one", 1}, {"two", 2}, {"three", 2.9}
    };

    // output element with key "two"
    std::cout << object["two"] << "\n\n";

    // change element with key "three"
    object["three"] = 3;

    // output changed array
    std::cout << std::setw(4) << object << "\n\n";

    // mention nonexisting key
    object["four"];

    // write to nonexisting key
    object["five"]["really"]["nested"] = true;

    // output changed object
    std::cout << std::setw(4) << object << '\n';
}
```

Output:

```
2

{
    "one": 1,
    "three": 3,
    "two": 2
}

{
    "five": {
        "really": {
            "nested": true
        }
    },
    "four": null,
    "one": 1,
    "three": 3,
    "two": 2
}
```

Example: (2) access specified object element (const)

The example below shows how object elements can be read using the `[]` operator.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create a JSON object
    const json object =
    {
        {"one", 1}, {"two", 2}, {"three", 2.9}
    };

    // output element with key "two"
    std::cout << object["two"] << '\n';
}
```

Output:

```
2
```

Example: (3) access specified object element using string_view

The example below shows how object elements can be read using the `[]` operator.

```
#include <iostream>
#include <iomanip>
#include <string_view>
#include <nlohmann/json.hpp>

using namespace std::string_view_literals;
using json = nlohmann::json;

int main()
{
    // create a JSON object
    json object =
    {
        {"one", 1}, {"two", 2}, {"three", 2.9}
    };

    // output element with key "two"
    std::cout << object["two"sv] << "\n\n";

    // change element with key "three"
    object["three"sv] = 3;

    // output changed array
    std::cout << std::setw(4) << object << "\n\n";

    // mention nonexisting key
    object["four"sv];

    // write to nonexisting key
    object["five"sv]["really"sv]["nested"sv] = true;

    // output changed object
    std::cout << std::setw(4) << object << '\n';
}
```

Output:

```
2

{
    "one": 1,
    "three": 3,
    "two": 2
}

{
    "five": {
        "really": {
            "nested": true
        }
    },
    "four": null,
    "one": 1,
    "three": 3,
    "two": 2
}
```

Example: (3) access specified object element using string_view (const)

The example below shows how object elements can be read using the `[]` operator.

```
#include <iostream>
#include <string_view>
#include <nlohmann/json.hpp>

using namespace std::string_view_literals;
using json = nlohmann::json;

int main()
{
    // create a JSON object
    const json object =
    {
        {"one", 1}, {"two", 2}, {"three", 2.9}
    };

    // output element with key "two"
    std::cout << object["two"sv] << '\n';
}
```

Output:

```
2
```

Example: (4) access specified element via JSON Pointer

The example below shows how values can be read and written using JSON Pointers.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace nlohmann::literals;

int main()
{
    // create a JSON value
    json j =
    {
        {"number", 1}, {"string", "foo"}, {"array", {1, 2}}
    };

    // read-only access

    // output element with JSON pointer "/number"
    std::cout << j["/number"_json_pointer] << '\n';
    // output element with JSON pointer "/string"
    std::cout << j["/string"_json_pointer] << '\n';
    // output element with JSON pointer "/array"
    std::cout << j["/array"_json_pointer] << '\n';
    // output element with JSON pointer "/array/1"
    std::cout << j["/array/1"_json_pointer] << '\n';

    // writing access

    // change the string
    j["/string"_json_pointer] = "bar";
    // output the changed string
    std::cout << j["string"] << '\n';

    // "change" a nonexisting object entry
    j["/boolean"_json_pointer] = true;
    // output the changed object
    std::cout << j << '\n';

    // change an array element
    j["/array/1"_json_pointer] = 21;
    // "change" an array element with nonexisting index
    j["/array/4"_json_pointer] = 44;
    // output the changed array
    std::cout << j["array"] << '\n';

    // "change" the array element past the end
    j["/array/-"_json_pointer] = 55;
    // output the changed array
    std::cout << j["array"] << '\n';
}
```

Output:

```
1
"foo"
[1,2]
2
"bar"
{"array":[1,2],"boolean":true,"number":1,"string":"bar"}
[1,21,null,null,44]
[1,21,null,null,44,55]
```

Example: (4) access specified element via JSON Pointer (const)

The example below shows how values can be read using JSON Pointers.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace nlohmann::literals;

int main()
{
    // create a JSON value
    const json j =
    {
        {"number", 1}, {"string", "foo"}, {"array", {1, 2}}
    };

    // read-only access

    // output element with JSON pointer "/number"
    std::cout << j["/number"_json_pointer] << '\n';
    // output element with JSON pointer "/string"
    std::cout << j["/string"_json_pointer] << '\n';
    // output element with JSON pointer "/array"
    std::cout << j["/array"_json_pointer] << '\n';
    // output element with JSON pointer "/array/1"
    std::cout << j["/array/1"_json_pointer] << '\n';
}
```

Output:

```
1
"foo"
[1,2]
2
```

## See also

- documentation on [unchecked access](https://json.nlohmann.me/features/element_access/unchecked_access/index.md)
- documentation on [runtime assertions](https://json.nlohmann.me/features/assertions/index.md)
- see [`at`](https://json.nlohmann.me/api/basic_json/at/index.md) for access by reference with range checking
- see [`value`](https://json.nlohmann.me/api/basic_json/value/index.md) for access with default value

## Version history

1. Added in version 1.0.0.
1. Added in version 1.0.0. Added overloads for `T* key` in version 1.1.0. Removed overloads for `T* key` (replaced by 3) in version 3.11.0.
1. Added in version 3.11.0. Fixed in version 3.13.0 to consistently accept `std::string_view`-convertible keys, as already supported by [`at`](https://json.nlohmann.me/api/basic_json/at/index.md), [`value`](https://json.nlohmann.me/api/basic_json/value/index.md), [`find`](https://json.nlohmann.me/api/basic_json/find/index.md), and other lookup functions.
1. Added in version 2.0.0.
