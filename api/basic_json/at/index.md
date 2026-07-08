# nlohmann::basic_json::at

```
// (1)
reference at(size_type idx);
const_reference at(size_type idx) const;

// (2)
reference at(const typename object_t::key_type& key);
const_reference at(const typename object_t::key_type& key) const;

// (3)
template<typename KeyType>
reference at(KeyType&& key);
template<typename KeyType>
const_reference at(KeyType&& key) const;

// (4)
reference at(const json_pointer& ptr);
const_reference at(const json_pointer& ptr) const;
```

1. Returns a reference to the array element at specified location `idx`, with bounds checking.
1. Returns a reference to the object element with specified key `key`, with bounds checking.
1. See 2. This overload is only available if `KeyType` is comparable with `typename object_t::key_type` and `typename object_comparator_t::is_transparent` denotes a type.
1. Returns a reference to the element at specified JSON pointer `ptr`, with bounds checking.

## Template parameters

`KeyType` : A type for an object key other than [`json_pointer`](https://json.nlohmann.me/api/json_pointer/index.md) that is comparable with [`string_t`](https://json.nlohmann.me/api/basic_json/string_t/index.md) using [`object_comparator_t`](https://json.nlohmann.me/api/basic_json/object_comparator_t/index.md). This can also be a string view (C++17).

## Parameters

`idx` (in) : index of the element to access

`key` (in) : object key of the elements to access

`ptr` (in) : JSON pointer to the desired element

## Return value

1. reference to the element at index `idx`
1. reference to the element at key `key`
1. reference to the element at key `key`
1. reference to the element pointed to by `ptr`

## Exception safety

Strong exception safety: if an exception occurs, the original value stays intact.

## Exceptions

1. The function can throw the following exceptions:
   - Throws [`type_error.304`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error304) if the JSON value is not an array; in this case, calling `at` with an index makes no sense. See the example below.
   - Throws [`out_of_range.401`](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range401) if the index `idx` is out of range of the array; that is, `idx >= size()`. See the example below.
1. The function can throw the following exceptions:
   - Throws [`type_error.304`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error304) if the JSON value is not an object; in this case, calling `at` with a key makes no sense. See the example below.
   - Throws [`out_of_range.403`](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range403) if the key `key` is not stored in the object; that is, `find(key) == end()`. See the example below.
1. See 2.
1. The function can throw the following exceptions:
   - Throws [`parse_error.106`](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error106) if an array index in the passed JSON pointer `ptr` begins with '0'. See the example below.
   - Throws [`parse_error.109`](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error109) if an array index in the passed JSON pointer `ptr` is not a number. See the example below.
   - Throws [`out_of_range.401`](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range401) if an array index in the passed JSON pointer `ptr` is out of range. See the example below.
   - Throws [`out_of_range.402`](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range402) if the array index '-' is used in the passed JSON pointer `ptr`. As `at` provides checked access (and no elements are implicitly inserted), the index '-' is always invalid. See the example below.
   - Throws [`out_of_range.403`](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range403) if the JSON pointer describes a key of an object which cannot be found. See the example below.
   - Throws [`out_of_range.404`](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range404) if the JSON pointer `ptr` can not be resolved. See the example below.
   - Throws [`out_of_range.410`](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range410) if an array index in the passed JSON pointer `ptr` exceeds the range of `size_type` (e.g., on 32-bit platforms).

## Complexity

1. Constant.
1. Logarithmic in the size of the container.
1. Logarithmic in the size of the container.
1. Logarithmic in the size of the container.

## Examples

Example: (1) access specified array element with bounds checking

The example below shows how array elements can be read and written using `at()`. It also demonstrates the different exceptions that can be thrown.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create JSON array
    json array = {"first", "2nd", "third", "fourth"};

    // output element at index 2 (third element)
    std::cout << array.at(2) << '\n';

    // change element at index 1 (second element) to "second"
    array.at(1) = "second";

    // output changed array
    std::cout << array << '\n';

    // exception type_error.304
    try
    {
        // use at() on a non-array type
        json str = "I am a string";
        str.at(0) = "Another string";
    }
    catch (const json::type_error& e)
    {
        std::cout << e.what() << '\n';
    }

    // exception out_of_range.401
    try
    {
        // try to write beyond the array limit
        array.at(5) = "sixth";
    }
    catch (const json::out_of_range& e)
    {
        std::cout << e.what() << '\n';
    }
}
```

Output:

```
"third"
["first","second","third","fourth"]
[json.exception.type_error.304] cannot use at() with string
[json.exception.out_of_range.401] array index 5 is out of range
```

Example: (1) access specified array element with bounds checking

The example below shows how array elements can be read using `at()`. It also demonstrates the different exceptions that can be thrown.

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

    // exception type_error.304
    try
    {
        // use at() on a non-array type
        const json str = "I am a string";
        std::cout << str.at(0) << '\n';
    }
    catch (const json::type_error& e)
    {
        std::cout << e.what() << '\n';
    }

    // exception out_of_range.401
    try
    {
        // try to read beyond the array limit
        std::cout << array.at(5) << '\n';
    }
    catch (const json::out_of_range& e)
    {
        std::cout << e.what() << '\n';
    }
}
```

Output:

```
"third"
[json.exception.type_error.304] cannot use at() with string
[json.exception.out_of_range.401] array index 5 is out of range
```

Example: (2) access specified object element with bounds checking

The example below shows how object elements can be read and written using `at()`. It also demonstrates the different exceptions that can be thrown.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create JSON object
    json object =
    {
        {"the good", "il buono"},
        {"the bad", "il cattivo"},
        {"the ugly", "il brutto"}
    };

    // output element with key "the ugly"
    std::cout << object.at("the ugly") << '\n';

    // change element with key "the bad"
    object.at("the bad") = "il cattivo";

    // output changed array
    std::cout << object << '\n';

    // exception type_error.304
    try
    {
        // use at() on a non-object type
        json str = "I am a string";
        str.at("the good") = "Another string";
    }
    catch (const json::type_error& e)
    {
        std::cout << e.what() << '\n';
    }

    // exception out_of_range.401
    try
    {
        // try to write at a nonexisting key
        object.at("the fast") = "il rapido";
    }
    catch (const json::out_of_range& e)
    {
        std::cout << e.what() << '\n';
    }
}
```

Output:

```
"il brutto"
{"the bad":"il cattivo","the good":"il buono","the ugly":"il brutto"}
[json.exception.type_error.304] cannot use at() with string
[json.exception.out_of_range.403] key 'the fast' not found
```

Example: (2) access specified object element with bounds checking

The example below shows how object elements can be read using `at()`. It also demonstrates the different exceptions that can be thrown.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create JSON object
    const json object =
    {
        {"the good", "il buono"},
        {"the bad", "il cattivo"},
        {"the ugly", "il brutto"}
    };

    // output element with key "the ugly"
    std::cout << object.at("the ugly") << '\n';

    // exception type_error.304
    try
    {
        // use at() on a non-object type
        const json str = "I am a string";
        std::cout << str.at("the good") << '\n';
    }
    catch (const json::type_error& e)
    {
        std::cout << e.what() << '\n';
    }

    // exception out_of_range.401
    try
    {
        // try to read from a nonexisting key
        std::cout << object.at("the fast") << '\n';
    }
    catch (const json::out_of_range)
    {
        std::cout << "out of range" << '\n';
    }
}
```

Output:

```
"il brutto"
[json.exception.type_error.304] cannot use at() with string
out of range
```

Example: (3) access specified object element using string_view with bounds checking

The example below shows how object elements can be read and written using `at()`. It also demonstrates the different exceptions that can be thrown.

```
#include <iostream>
#include <string_view>
#include <nlohmann/json.hpp>

using namespace std::string_view_literals;
using json = nlohmann::json;

int main()
{
    // create JSON object
    json object =
    {
        {"the good", "il buono"},
        {"the bad", "il cattivo"},
        {"the ugly", "il brutto"}
    };

    // output element with key "the ugly" using string_view
    std::cout << object.at("the ugly"sv) << '\n';

    // change element with key "the bad" using string_view
    object.at("the bad"sv) = "il cattivo";

    // output changed array
    std::cout << object << '\n';

    // exception type_error.304
    try
    {
        // use at() with string_view on a non-object type
        json str = "I am a string";
        str.at("the good"sv) = "Another string";
    }
    catch (const json::type_error& e)
    {
        std::cout << e.what() << '\n';
    }

    // exception out_of_range.401
    try
    {
        // try to write at a nonexisting key using string_view
        object.at("the fast"sv) = "il rapido";
    }
    catch (const json::out_of_range& e)
    {
        std::cout << e.what() << '\n';
    }
}
```

Output:

```
"il brutto"
{"the bad":"il cattivo","the good":"il buono","the ugly":"il brutto"}
[json.exception.type_error.304] cannot use at() with string
[json.exception.out_of_range.403] key 'the fast' not found
```

Example: (3) access specified object element using string_view with bounds checking

The example below shows how object elements can be read using `at()`. It also demonstrates the different exceptions that can be thrown.

```
#include <iostream>
#include <string_view>
#include <nlohmann/json.hpp>

using namespace std::string_view_literals;
using json = nlohmann::json;

int main()
{
    // create JSON object
    const json object =
    {
        {"the good", "il buono"},
        {"the bad", "il cattivo"},
        {"the ugly", "il brutto"}
    };

    // output element with key "the ugly" using string_view
    std::cout << object.at("the ugly"sv) << '\n';

    // exception type_error.304
    try
    {
        // use at() with string_view on a non-object type
        const json str = "I am a string";
        std::cout << str.at("the good"sv) << '\n';
    }
    catch (const json::type_error& e)
    {
        std::cout << e.what() << '\n';
    }

    // exception out_of_range.401
    try
    {
        // try to read from a nonexisting key using string_view
        std::cout << object.at("the fast"sv) << '\n';
    }
    catch (const json::out_of_range& e)
    {
        std::cout << "out of range" << '\n';
    }
}
```

Output:

```
"il brutto"
[json.exception.type_error.304] cannot use at() with string
out of range
```

Example: (4) access specified element via JSON Pointer

The example below shows how object elements can be read and written using `at()`. It also demonstrates the different exceptions that can be thrown.

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
    std::cout << j.at("/number"_json_pointer) << '\n';
    // output element with JSON pointer "/string"
    std::cout << j.at("/string"_json_pointer) << '\n';
    // output element with JSON pointer "/array"
    std::cout << j.at("/array"_json_pointer) << '\n';
    // output element with JSON pointer "/array/1"
    std::cout << j.at("/array/1"_json_pointer) << '\n';

    // writing access

    // change the string
    j.at("/string"_json_pointer) = "bar";
    // output the changed string
    std::cout << j["string"] << '\n';

    // change an array element
    j.at("/array/1"_json_pointer) = 21;
    // output the changed array
    std::cout << j["array"] << '\n';

    // out_of_range.106
    try
    {
        // try to use an array index with leading '0'
        json::reference ref = j.at("/array/01"_json_pointer);
    }
    catch (const json::parse_error& e)
    {
        std::cout << e.what() << '\n';
    }

    // out_of_range.109
    try
    {
        // try to use an array index that is not a number
        json::reference ref = j.at("/array/one"_json_pointer);
    }
    catch (const json::parse_error& e)
    {
        std::cout << e.what() << '\n';
    }

    // out_of_range.401
    try
    {
        // try to use an invalid array index
        json::reference ref = j.at("/array/4"_json_pointer);
    }
    catch (const json::out_of_range& e)
    {
        std::cout << e.what() << '\n';
    }

    // out_of_range.402
    try
    {
        // try to use the array index '-'
        json::reference ref = j.at("/array/-"_json_pointer);
    }
    catch (const json::out_of_range& e)
    {
        std::cout << e.what() << '\n';
    }

    // out_of_range.403
    try
    {
        // try to use a JSON pointer to a nonexistent object key
        json::const_reference ref = j.at("/foo"_json_pointer);
    }
    catch (const json::out_of_range& e)
    {
        std::cout << e.what() << '\n';
    }

    // out_of_range.404
    try
    {
        // try to use a JSON pointer that cannot be resolved
        json::reference ref = j.at("/number/foo"_json_pointer);
    }
    catch (const json::out_of_range& e)
    {
        std::cout << e.what() << '\n';
    }
}
```

Output:

```
1
"foo"
[1,2]
2
"bar"
[1,21]
[json.exception.parse_error.106] parse error: array index '01' must not begin with '0'
[json.exception.parse_error.109] parse error: array index 'one' is not a number
[json.exception.out_of_range.401] array index 4 is out of range
[json.exception.out_of_range.402] array index '-' (2) is out of range
[json.exception.out_of_range.403] key 'foo' not found
[json.exception.out_of_range.404] unresolved reference token 'foo'
```

Example: (4) access specified element via JSON Pointer

The example below shows how object elements can be read using `at()`. It also demonstrates the different exceptions that can be thrown.

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
    std::cout << j.at("/number"_json_pointer) << '\n';
    // output element with JSON pointer "/string"
    std::cout << j.at("/string"_json_pointer) << '\n';
    // output element with JSON pointer "/array"
    std::cout << j.at("/array"_json_pointer) << '\n';
    // output element with JSON pointer "/array/1"
    std::cout << j.at("/array/1"_json_pointer) << '\n';

    // out_of_range.109
    try
    {
        // try to use an array index that is not a number
        json::const_reference ref = j.at("/array/one"_json_pointer);
    }
    catch (const json::parse_error& e)
    {
        std::cout << e.what() << '\n';
    }

    // out_of_range.401
    try
    {
        // try to use an invalid array index
        json::const_reference ref = j.at("/array/4"_json_pointer);
    }
    catch (const json::out_of_range& e)
    {
        std::cout << e.what() << '\n';
    }

    // out_of_range.402
    try
    {
        // try to use the array index '-'
        json::const_reference ref = j.at("/array/-"_json_pointer);
    }
    catch (const json::out_of_range& e)
    {
        std::cout << e.what() << '\n';
    }

    // out_of_range.403
    try
    {
        // try to use a JSON pointer to a nonexistent object key
        json::const_reference ref = j.at("/foo"_json_pointer);
    }
    catch (const json::out_of_range& e)
    {
        std::cout << e.what() << '\n';
    }

    // out_of_range.404
    try
    {
        // try to use a JSON pointer that cannot be resolved
        json::const_reference ref = j.at("/number/foo"_json_pointer);
    }
    catch (const json::out_of_range& e)
    {
        std::cout << e.what() << '\n';
    }
}
```

Output:

```
1
"foo"
[1,2]
2
[json.exception.parse_error.109] parse error: array index 'one' is not a number
[json.exception.out_of_range.401] array index 4 is out of range
[json.exception.out_of_range.402] array index '-' (2) is out of range
[json.exception.out_of_range.403] key 'foo' not found
[json.exception.out_of_range.404] unresolved reference token 'foo'
```

## See also

- documentation on [checked access](https://json.nlohmann.me/features/element_access/checked_access/index.md)
- [`operator[]`](https://json.nlohmann.me/api/basic_json/operator%5B%5D/index.md) for unchecked access by reference
- [`value`](https://json.nlohmann.me/api/basic_json/value/index.md) for access with default value

## Version history

1. Added in version 1.0.0.
1. Added in version 1.0.0.
1. Added in version 3.11.0.
1. Added in version 2.0.0.
