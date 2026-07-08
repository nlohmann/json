# nlohmann::basic_json::basic_json

```
// (1)
basic_json(const value_t v);

// (2)
basic_json(std::nullptr_t = nullptr) noexcept;

// (3)
template<typename CompatibleType>
basic_json(CompatibleType&& val) noexcept(noexcept(
           JSONSerializer<U>::to_json(std::declval<basic_json_t&>(),
                                      std::forward<CompatibleType>(val))));

// (4)
template<typename BasicJsonType>
basic_json(const BasicJsonType& val);

// (5)
basic_json(initializer_list_t init,
           bool type_deduction = true,
           value_t manual_type = value_t::array);

// (6)
basic_json(size_type cnt, const basic_json& val);

// (7)
basic_json(iterator first, iterator last);
basic_json(const_iterator first, const_iterator last);

// (8)
basic_json(const basic_json& other);

// (9)
basic_json(basic_json&& other) noexcept;
```

1. Create an empty JSON value with a given type. The value will be default initialized with an empty value which depends on the type:

   | Value type | initial value |
   | ---------- | ------------- |
   | null       | `null`        |
   | boolean    | `false`       |
   | string     | `""`          |
   | number     | `0`           |
   | object     | `{}`          |
   | array      | `[]`          |
   | binary     | empty array   |

   The postcondition of this constructor can be restored by calling [`clear()`](https://json.nlohmann.me/api/basic_json/clear/index.md).

1. Create a `null` JSON value. It either takes a null pointer as parameter (explicitly creating `null`) or no parameter (implicitly creating `null`). The passed null pointer itself is not read -- it is only used to choose the right constructor.

1. This is a "catch all" constructor for all compatible JSON types; that is, types for which a `to_json()` method exists. The constructor forwards the parameter `val` to that method (to `json_serializer<U>::to_json` method with `U = uncvref_t<CompatibleType>`, to be exact).

   Template type `CompatibleType` includes, but is not limited to, the following types:

   - **arrays**: [`array_t`](https://json.nlohmann.me/api/basic_json/array_t/index.md) and all kinds of compatible containers such as `std::vector`, `std::deque`, `std::list`, `std::forward_list`, `std::array`, `std::valarray`, `std::set`, `std::unordered_set`, `std::multiset`, and `std::unordered_multiset` with a `value_type` from which a `basic_json` value can be constructed.
   - **objects**: [`object_t`](https://json.nlohmann.me/api/basic_json/object_t/index.md) and all kinds of compatible associative containers such as `std::map`, `std::unordered_map`, `std::multimap`, and `std::unordered_multimap` with a `key_type` compatible to `string_t` and a `value_type` from which a `basic_json` value can be constructed.
   - **strings**: `string_t`, string literals, and all compatible string containers can be used.
   - **numbers**: [`number_integer_t`](https://json.nlohmann.me/api/basic_json/number_integer_t/index.md), [`number_unsigned_t`](https://json.nlohmann.me/api/basic_json/number_unsigned_t/index.md), [`number_float_t`](https://json.nlohmann.me/api/basic_json/number_float_t/index.md), and all convertible number types such as `int`, `size_t`, `int64_t`, `float` or `double` can be used.
   - **boolean**: `boolean_t` / `bool` can be used.
   - **binary**: `binary_t` / `std::vector<uint8_t>` may be used; unfortunately because string literals cannot be distinguished from binary character arrays by the C++ type system, all types compatible with `const char*` will be directed to the string constructor instead. This is both for backwards compatibility and due to the fact that a binary type is not a standard JSON type.

   See the examples below.

1. This is a constructor for existing `basic_json` types. It does not hijack copy/move constructors, since the parameter has different template arguments than the current ones.

   The constructor tries to convert the internal `m_value` of the parameter.

1. Creates a JSON value of type array or object from the passed initializer list `init`. In case `type_deduction` is `true` (default), the type of the JSON value to be created is deducted from the initializer list `init` according to the following rules:

   1. If the list is empty, an empty JSON object value `{}` is created.
   1. If the list consists of pairs whose first element is a string, a JSON object value is created where the first elements of the pairs are treated as keys and the second elements are as values.
   1. In all other cases, an array is created.

   The rules aim to create the best fit between a C++ initializer list and JSON values. The rationale is as follows:

   1. The empty initializer list is written as `{}` which is exactly an empty JSON object.
   1. C++ has no way of describing mapped types other than to list a list of pairs. As JSON requires that keys must be of type string, rule 2 is the weakest constraint one can pose on initializer lists to interpret them as an object.
   1. In all other cases, the initializer list could not be interpreted as a JSON object type, so interpreting it as a JSON array type is safe.

   With the rules described above, the following JSON values cannot be expressed by an initializer list:

   - the empty array (`[]`): use `array(initializer_list_t)` with an empty initializer list in this case
   - arrays whose elements satisfy rule 2: use `array(initializer_list_t)` with the same initializer list in this case

   Function [`array()`](https://json.nlohmann.me/api/basic_json/array/index.md) and [`object()`](https://json.nlohmann.me/api/basic_json/object/index.md) force array and object creation from initializer lists, respectively.

1. Constructs a JSON array value by creating `cnt` copies of a passed value. In case `cnt` is `0`, an empty array is created.

1. Constructs the JSON value with the contents of the range `[first, last)`. The semantics depend on the different types a JSON value can have:

   - In case of a `null` type, [invalid_iterator.206](https://json.nlohmann.me/home/exceptions/#jsonexceptioninvalid_iterator206) is thrown.
   - In case of other primitive types (number, boolean, or string), `first` must be `begin()` and `last` must be `end()`. In this case, the value is copied. Otherwise, [`invalid_iterator.204`](https://json.nlohmann.me/home/exceptions/#jsonexceptioninvalid_iterator204) is thrown.
   - In case of structured types (array, object), the constructor behaves as similar versions for `std::vector` or `std::map`; that is, a JSON array or object is constructed from the values in the range.

1. Creates a copy of a given JSON value.

1. Move constructor. Constructs a JSON value with the contents of the given value `other` using move semantics. It "steals" the resources from `other` and leaves it as JSON `null` value.

## Template parameters

`CompatibleType` : a type such that:

```
- `CompatibleType` is not derived from `std::istream`,
- `CompatibleType` is not `basic_json` (to avoid hijacking copy/move constructors),
- `CompatibleType` is not a different `basic_json` type (i.e. with different template arguments)
- `CompatibleType` is not a `basic_json` nested type (e.g., `json_pointer`, `iterator`, etc.)
- `json_serializer<U>` (with `U = uncvref_t<CompatibleType>`) has a `to_json(basic_json_t&, CompatibleType&&)`
  method
```

`BasicJsonType`: : a type such that:

```
- `BasicJsonType` is a `basic_json` type.
- `BasicJsonType` has different template arguments than `basic_json_t`.
```

`U`: : `uncvref_t<CompatibleType>`

## Parameters

`v` (in) : the type of the value to create

`val` (in) : the value to be forwarded to the respective constructor

`init` (in) : initializer list with JSON values

`type_deduction` (in) : internal parameter; when set to `true`, the type of the JSON value is deducted from the initializer list `init`; when set to `false`, the type provided via `manual_type` is forced. This mode is used by the functions `array(initializer_list_t)` and `object(initializer_list_t)`.

`manual_type` (in) : internal parameter; when `type_deduction` is set to `false`, the created JSON value will use the provided type (only `value_t::array` and `value_t::object` are valid); when `type_deduction` is set to `true`, this parameter has no effect

`cnt` (in) : the number of JSON copies of `val` to create

`first` (in) : the beginning of the range to copy from (included)

`last` (in) : the end of the range to copy from (excluded)

`other` (in) : the JSON value to copy/move

## Exception safety

1. Strong guarantee: if an exception is thrown, there are no changes to any JSON value.
1. No-throw guarantee: this constructor never throws exceptions.
1. Depends on the called constructor. For types directly supported by the library (i.e., all types for which no `to_json()` function was provided), a strong guarantee holds: if an exception is thrown, there are no changes to any JSON value.
1. Depends on the called constructor. For types directly supported by the library (i.e., all types for which no `to_json()` function was provided), a strong guarantee holds: if an exception is thrown, there are no changes to any JSON value.
1. Strong guarantee: if an exception is thrown, there are no changes to any JSON value.
1. Strong guarantee: if an exception is thrown, there are no changes to any JSON value.
1. Strong guarantee: if an exception is thrown, there are no changes to any JSON value.
1. Strong guarantee: if an exception is thrown, there are no changes to any JSON value.
1. No-throw guarantee: this constructor never throws exceptions.

## Exceptions

1. (none)
1. The function does not throw exceptions.
1. (none)
1. (none)
1. The function can throw the following exceptions:
   - Throws [`type_error.301`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error301) if `type_deduction` is `false`, `manual_type` is `value_t::object`, but `init` contains an element which is not a pair whose first element is a string. In this case, the constructor could not create an object. If `type_deduction` would have been `true`, an array would have been created. See `object(initializer_list_t)` for an example.
1. (none)
1. The function can throw the following exceptions:
   - Throws [`invalid_iterator.201`](https://json.nlohmann.me/home/exceptions/#jsonexceptioninvalid_iterator201) if iterators `first` and `last` are not compatible (i.e., do not belong to the same JSON value). In this case, the range `[first, last)` is undefined.
   - Throws [`invalid_iterator.204`](https://json.nlohmann.me/home/exceptions/#jsonexceptioninvalid_iterator204) if iterators `first` and `last` belong to a primitive type (number, boolean, or string), but `first` does not point to the first element anymore. In this case, the range `[first, last)` is undefined. See the example code below.
   - Throws [`invalid_iterator.206`](https://json.nlohmann.me/home/exceptions/#jsonexceptioninvalid_iterator206) if iterators `first` and `last` belong to a `null` value. In this case, the range `[first, last)` is undefined.
1. (none)
1. The function does not throw exceptions.

## Complexity

1. Constant.
1. Constant.
1. Usually linear in the size of the passed `val`, also depending on the implementation of the called `to_json()` method.
1. Usually linear in the size of the passed `val`, also depending on the implementation of the called `to_json()` method.
1. Linear in the size of the initializer list `init`.
1. Linear in `cnt`.
1. Linear in distance between `first` and `last`.
1. Linear in the size of `other`.
1. Constant.

## Notes

- Overload 5:

  Empty initializer list

  When used without parentheses around an empty initializer list, `basic_json()` is called instead of this function, yielding the JSON `null` value.

- Overload 7:

  Preconditions

  - Iterators `first` and `last` must be initialized. \*\*This precondition is enforced with a [runtime assertion](https://json.nlohmann.me/features/assertions/index.md).
  - Range `[first, last)` is valid. Usually, this precondition cannot be checked efficiently. Only certain edge cases are detected; see the description of the exceptions above. A violation of this precondition yields undefined behavior.

  Runtime assertion

  A precondition is enforced with a [runtime assertion](https://json.nlohmann.me/features/assertions/index.md).

- Overload 8:

  Postcondition

  `*this == other`

- Overload 9:

  Postconditions

  - `` `*this `` has the same value as `other` before the call.
  - `other` is a JSON `null` value

## Examples

Example: (1) create an empty value with a given type

The following code shows the constructor for different `value_t` values.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create the different JSON values with default values
    json j_null(json::value_t::null);
    json j_boolean(json::value_t::boolean);
    json j_number_integer(json::value_t::number_integer);
    json j_number_float(json::value_t::number_float);
    json j_object(json::value_t::object);
    json j_array(json::value_t::array);
    json j_string(json::value_t::string);

    // serialize the JSON values
    std::cout << j_null << '\n';
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
false
0
0.0
{}
[]
""
```

Example: (2) create a `null` object

The following code shows the constructor with and without a null pointer parameter.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // implicitly create a JSON null value
    json j1;

    // explicitly create a JSON null value
    json j2(nullptr);

    // serialize the JSON null value
    std::cout << j1 << '\n' << j2 << '\n';
}
```

Output:

```
null
null
```

Example: (3) create a JSON value from compatible types

The following code shows the constructor with several compatible types.

```
#include <iostream>
#include <deque>
#include <list>
#include <forward_list>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <valarray>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // ============
    // object types
    // ============

    // create an object from an object_t value
    json::object_t object_value = { {"one", 1}, {"two", 2} };
    json j_object_t(object_value);

    // create an object from std::map
    std::map<std::string, int> c_map
    {
        {"one", 1}, {"two", 2}, {"three", 3}
    };
    json j_map(c_map);

    // create an object from std::unordered_map
    std::unordered_map<const char*, double> c_umap
    {
        {"one", 1.2}, {"two", 2.3}, {"three", 3.4}
    };
    json j_umap(c_umap);

    // create an object from std::multimap
    std::multimap<std::string, bool> c_mmap
    {
        {"one", true}, {"two", true}, {"three", false}, {"three", true}
    };
    json j_mmap(c_mmap); // only one entry for key "three" is used

    // create an object from std::unordered_multimap
    std::unordered_multimap<std::string, bool> c_ummap
    {
        {"one", true}, {"two", true}, {"three", false}, {"three", true}
    };
    json j_ummap(c_ummap); // only one entry for key "three" is used

    // serialize the JSON objects
    std::cout << j_object_t << '\n';
    std::cout << j_map << '\n';
    std::cout << j_umap << '\n';
    std::cout << j_mmap << '\n';
    std::cout << j_ummap << "\n\n";

    // ===========
    // array types
    // ===========

    // create an array from an array_t value
    json::array_t array_value = {"one", "two", 3, 4.5, false};
    json j_array_t(array_value);

    // create an array from std::vector
    std::vector<int> c_vector {1, 2, 3, 4};
    json j_vec(c_vector);

    // create an array from std::valarray
    std::valarray<short> c_valarray {10, 9, 8, 7};
    json j_valarray(c_valarray);

    // create an array from std::deque
    std::deque<double> c_deque {1.2, 2.3, 3.4, 5.6};
    json j_deque(c_deque);

    // create an array from std::list
    std::list<bool> c_list {true, true, false, true};
    json j_list(c_list);

    // create an array from std::forward_list
    std::forward_list<std::int64_t> c_flist {12345678909876, 23456789098765, 34567890987654, 45678909876543};
    json j_flist(c_flist);

    // create an array from std::array
    std::array<unsigned long, 4> c_array {{1, 2, 3, 4}};
    json j_array(c_array);

    // create an array from std::set
    std::set<std::string> c_set {"one", "two", "three", "four", "one"};
    json j_set(c_set); // only one entry for "one" is used

    // create an array from std::unordered_set
    std::unordered_set<std::string> c_uset {"one", "two", "three", "four", "one"};
    json j_uset(c_uset); // only one entry for "one" is used

    // create an array from std::multiset
    std::multiset<std::string> c_mset {"one", "two", "one", "four"};
    json j_mset(c_mset); // both entries for "one" are used

    // create an array from std::unordered_multiset
    std::unordered_multiset<std::string> c_umset {"one", "two", "one", "four"};
    json j_umset(c_umset); // both entries for "one" are used

    // serialize the JSON arrays
    std::cout << j_array_t << '\n';
    std::cout << j_vec << '\n';
    std::cout << j_valarray << '\n';
    std::cout << j_deque << '\n';
    std::cout << j_list << '\n';
    std::cout << j_flist << '\n';
    std::cout << j_array << '\n';
    std::cout << j_set << '\n';
    std::cout << j_uset << '\n';
    std::cout << j_mset << '\n';
    std::cout << j_umset << "\n\n";

    // ============
    // string types
    // ============

    // create string from a string_t value
    json::string_t string_value = "The quick brown fox jumps over the lazy dog.";
    json j_string_t(string_value);

    // create a JSON string directly from a string literal
    json j_string_literal("The quick brown fox jumps over the lazy dog.");

    // create string from std::string
    std::string s_stdstring = "The quick brown fox jumps over the lazy dog.";
    json j_stdstring(s_stdstring);

    // serialize the JSON strings
    std::cout << j_string_t << '\n';
    std::cout << j_string_literal << '\n';
    std::cout << j_stdstring << "\n\n";

    // ============
    // number types
    // ============

    // create a JSON number from number_integer_t
    json::number_integer_t value_integer_t = -42;
    json j_integer_t(value_integer_t);

    // create a JSON number from number_unsigned_t
    json::number_integer_t value_unsigned_t = 17;
    json j_unsigned_t(value_unsigned_t);

    // create a JSON number from an anonymous enum
    enum { enum_value = 17 };
    json j_enum(enum_value);

    // create values of different integer types
    short n_short = 42;
    int n_int = -23;
    long n_long = 1024;
    int_least32_t n_int_least32_t = -17;
    uint8_t n_uint8_t = 8;

    // create (integer) JSON numbers
    json j_short(n_short);
    json j_int(n_int);
    json j_long(n_long);
    json j_int_least32_t(n_int_least32_t);
    json j_uint8_t(n_uint8_t);

    // create values of different floating-point types
    json::number_float_t v_ok = 3.141592653589793;
    json::number_float_t v_nan = NAN;
    json::number_float_t v_infinity = INFINITY;

    // create values of different floating-point types
    float n_float = 42.23;
    float n_float_nan = 1.0f / 0.0f;
    double n_double = 23.42;

    // create (floating point) JSON numbers
    json j_ok(v_ok);
    json j_nan(v_nan);
    json j_infinity(v_infinity);
    json j_float(n_float);
    json j_float_nan(n_float_nan);
    json j_double(n_double);

    // serialize the JSON numbers
    std::cout << j_integer_t << '\n';
    std::cout << j_unsigned_t << '\n';
    std::cout << j_enum << '\n';
    std::cout << j_short << '\n';
    std::cout << j_int << '\n';
    std::cout << j_long << '\n';
    std::cout << j_int_least32_t << '\n';
    std::cout << j_uint8_t << '\n';
    std::cout << j_ok << '\n';
    std::cout << j_nan << '\n';
    std::cout << j_infinity << '\n';
    std::cout << j_float << '\n';
    std::cout << j_float_nan << '\n';
    std::cout << j_double << "\n\n";

    // =============
    // boolean types
    // =============

    // create boolean values
    json j_truth = true;
    json j_falsity = false;

    // serialize the JSON booleans
    std::cout << j_truth << '\n';
    std::cout << j_falsity << '\n';
}
```

Output:

```
{"one":1,"two":2}
{"one":1,"three":3,"two":2}
{"one":1.2,"three":3.4,"two":2.3}
{"one":true,"three":false,"two":true}
{"one":true,"three":false,"two":true}

["one","two",3,4.5,false]
[1,2,3,4]
[10,9,8,7]
[1.2,2.3,3.4,5.6]
[true,true,false,true]
[12345678909876,23456789098765,34567890987654,45678909876543]
[1,2,3,4]
["four","one","three","two"]
["four","three","two","one"]
["four","one","one","two"]
["four","two","one","one"]

"The quick brown fox jumps over the lazy dog."
"The quick brown fox jumps over the lazy dog."
"The quick brown fox jumps over the lazy dog."

-42
17
17
42
-23
1024
-17
8
3.141592653589793
null
null
42.22999954223633
null
23.42

true
false
```

Note the output is platform-dependent.

Example: (5) create a container (array or object) from an initializer list

The example below shows how JSON values are created from initializer lists.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create JSON values
    json j_empty_init_list = json({});
    json j_object = { {"one", 1}, {"two", 2} };
    json j_array = {1, 2, 3, 4};
    json j_nested_object = { {"one", {1}}, {"two", {1, 2}} };
    json j_nested_array = { {{1}, "one"}, {{1, 2}, "two"} };

    // serialize the JSON value
    std::cout << j_empty_init_list << '\n';
    std::cout << j_object << '\n';
    std::cout << j_array << '\n';
    std::cout << j_nested_object << '\n';
    std::cout << j_nested_array << '\n';
}
```

Output:

```
{}
{"one":1,"two":2}
[1,2,3,4]
{"one":[1],"two":[1,2]}
[[[1],"one"],[[1,2],"two"]]
```

Example: (6) construct an array with count copies of a given value

The following code shows examples for creating arrays with several copies of a given value.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create an array by creating copies of a JSON value
    json value = "Hello";
    json array_0 = json(0, value);
    json array_1 = json(1, value);
    json array_5 = json(5, value);

    // serialize the JSON arrays
    std::cout << array_0 << '\n';
    std::cout << array_1 << '\n';
    std::cout << array_5 << '\n';
}
```

Output:

```
[]
["Hello"]
["Hello","Hello","Hello","Hello","Hello"]
```

Example: (7) construct a JSON container given an iterator range

The example below shows several ways to create JSON values by specifying a subrange with iterators.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create JSON values
    json j_array = {"alpha", "bravo", "charly", "delta", "easy"};
    json j_number = 42;
    json j_object = {{"one", "eins"}, {"two", "zwei"}};

    // create copies using iterators
    json j_array_range(j_array.begin() + 1, j_array.end() - 2);
    json j_number_range(j_number.begin(), j_number.end());
    json j_object_range(j_object.begin(), j_object.find("two"));

    // serialize the values
    std::cout << j_array_range << '\n';
    std::cout << j_number_range << '\n';
    std::cout << j_object_range << '\n';

    // example for an exception
    try
    {
        json j_invalid(j_number.begin() + 1, j_number.end());
    }
    catch (const json::invalid_iterator& e)
    {
        std::cout << e.what() << '\n';
    }
}
```

Output:

```
["bravo","charly"]
42
{"one":"eins"}
[json.exception.invalid_iterator.204] iterators out of range
```

Example: (8) copy constructor

The following code shows an example for the copy constructor.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create a JSON array
    json j1 = {"one", "two", 3, 4.5, false};

    // create a copy
    json j2(j1);

    // serialize the JSON array
    std::cout << j1 << " = " << j2 << '\n';
    std::cout << std::boolalpha << (j1 == j2) << '\n';
}
```

Output:

```
["one","two",3,4.5,false] = ["one","two",3,4.5,false]
true
```

Example: (9) move constructor

The code below shows the move constructor explicitly called via `std::move`.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create a JSON value
    json a = 23;

    // move contents of a to b
    json b(std::move(a));

    // serialize the JSON arrays
    std::cout << a << '\n';
    std::cout << b << '\n';
}
```

Output:

```
null
23
```

## Version history

1. Since version 1.0.0.
1. Since version 1.0.0.
1. Since version 2.1.0.
1. Since version 3.2.0.
1. Since version 1.0.0.
1. Since version 1.0.0.
1. Since version 1.0.0.
1. Since version 1.0.0.
1. Since version 1.0.0.
