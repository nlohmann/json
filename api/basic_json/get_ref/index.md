# nlohmann::basic_json::get_ref

```
template<typename ReferenceType>
ReferenceType get_ref();

template<typename ReferenceType>
const ReferenceType get_ref() const;
```

Implicit reference access to the internally stored JSON value. No copies are made.

## Template parameters

`ReferenceType` : reference type; must be a reference to [`array_t`](https://json.nlohmann.me/api/basic_json/array_t/index.md), [`object_t`](https://json.nlohmann.me/api/basic_json/object_t/index.md), [`string_t`](https://json.nlohmann.me/api/basic_json/string_t/index.md), [`boolean_t`](https://json.nlohmann.me/api/basic_json/boolean_t/index.md), [`number_integer_t`](https://json.nlohmann.me/api/basic_json/number_integer_t/index.md), or [`number_unsigned_t`](https://json.nlohmann.me/api/basic_json/number_unsigned_t/index.md), [`number_float_t`](https://json.nlohmann.me/api/basic_json/number_float_t/index.md), or [`binary_t`](https://json.nlohmann.me/api/basic_json/binary_t/index.md). Enforced by a static assertion.

## Return value

reference to the internally stored JSON value if the requested reference type fits to the JSON value; throws [`type_error.303`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error303) otherwise

## Exception safety

Strong exception safety: if an exception occurs, the original value stays intact.

## Exceptions

Throws [`type_error.303`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error303) if the requested reference type does not match the stored JSON value type; example: `"incompatible ReferenceType for get_ref, actual type is binary"`.

## Complexity

Constant.

## Notes

Undefined behavior

The reference becomes invalid if the underlying JSON object changes.

## Examples

Example

The example shows several calls to `get_ref()`.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create a JSON number
    json value = 17;

    // explicitly getting references
    auto r1 = value.get_ref<const json::number_integer_t&>();
    auto r2 = value.get_ref<json::number_integer_t&>();

    // print the values
    std::cout << r1 << ' ' << r2 << '\n';

    // incompatible type throws exception
    try
    {
        auto r3 = value.get_ref<json::number_float_t&>();
    }
    catch (const json::type_error& ex)
    {
        std::cout << ex.what() << '\n';
    }
}
```

Output:

```
17 17
[json.exception.type_error.303] incompatible ReferenceType for get_ref, actual type is number
```

## See also

- [get_ptr()](https://json.nlohmann.me/api/basic_json/get_ptr/index.md) get a pointer value

## Version history

- Added in version 1.1.0.
- Extended to binary types in version 3.8.0.
