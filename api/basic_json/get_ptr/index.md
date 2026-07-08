# nlohmann::basic_json::get_ptr

```
template<typename PointerType>
PointerType get_ptr() noexcept;

template<typename PointerType>
constexpr const PointerType get_ptr() const noexcept;
```

Implicit pointer access to the internally stored JSON value. No copies are made.

## Template parameters

`PointerType` : pointer type; must be a pointer to [`array_t`](https://json.nlohmann.me/api/basic_json/array_t/index.md), [`object_t`](https://json.nlohmann.me/api/basic_json/object_t/index.md), [`string_t`](https://json.nlohmann.me/api/basic_json/string_t/index.md), [`boolean_t`](https://json.nlohmann.me/api/basic_json/boolean_t/index.md), [`number_integer_t`](https://json.nlohmann.me/api/basic_json/number_integer_t/index.md), or [`number_unsigned_t`](https://json.nlohmann.me/api/basic_json/number_unsigned_t/index.md), [`number_float_t`](https://json.nlohmann.me/api/basic_json/number_float_t/index.md), or [`binary_t`](https://json.nlohmann.me/api/basic_json/binary_t/index.md). Other types will not compile.

## Return value

pointer to the internally stored JSON value if the requested pointer type fits to the JSON value; `nullptr` otherwise

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Notes

Undefined behavior

The pointer becomes invalid if the underlying JSON object changes.

Consider the following example code where the pointer `ptr` changes after the array is resized. As a result, reading or writing to `ptr` after the array change would be undefined behavior. The address of the first array element changes, because the underlying `std::vector` is resized after adding a fifth element.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    json j = {1, 2, 3, 4};
    auto* ptr = j[0].get_ptr<std::int64_t*>();
    std::cout << "value at " << ptr << " is " << *ptr << std::endl;

    j.push_back(5);

    ptr = j[0].get_ptr<std::int64_t*>();
    std::cout << "value at " << ptr << " is " << *ptr << std::endl;
}
```

Output:

```
value at 0x6000012fc1c8 is 1
value at 0x6000029fc088 is 1
```

## Examples

Example

The example below shows how pointers to internal values of a JSON value can be requested. Note that no type conversions are made and a `nullptr` is returned if the value and the requested pointer type does not match.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create a JSON number
    json value = 17;

    // explicitly getting pointers
    auto p1 = value.get_ptr<const json::number_integer_t*>();
    auto p2 = value.get_ptr<json::number_integer_t*>();
    auto p3 = value.get_ptr<json::number_integer_t* const>();
    auto p4 = value.get_ptr<const json::number_integer_t* const>();
    auto p5 = value.get_ptr<json::number_float_t*>();

    // print the pointees
    std::cout << *p1 << ' ' << *p2 << ' ' << *p3 << ' ' << *p4 << '\n';
    std::cout << std::boolalpha << (p5 == nullptr) << '\n';
}
```

Output:

```
17 17 17 17
true
```

## See also

- [get_ref()](https://json.nlohmann.me/api/basic_json/get_ref/index.md) get a reference value

## Version history

- Added in version 1.0.0.
- Extended to binary types in version 3.8.0.
