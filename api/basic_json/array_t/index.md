# nlohmann::basic_json::array_t

```
using array_t = ArrayType<basic_json, AllocatorType<basic_json>>;
```

The type used to store JSON arrays.

[RFC 8259](https://tools.ietf.org/html/rfc8259) describes JSON arrays as follows:

> An array is an ordered sequence of zero or more values.

To store objects in C++, a type is defined by the template parameters explained below.

## Template parameters

`ArrayType` : container type to store arrays (e.g., `std::vector` or `std::list`)

`AllocatorType` : the allocator to use for objects (e.g., `std::allocator`)

## Notes

#### Default type

With the default values for `ArrayType` (`std::vector`) and `AllocatorType` (`std::allocator`), the default value for `array_t` is:

```
std::vector<
  basic_json, // value_type
  std::allocator<basic_json> // allocator_type
>
```

#### Limits

[RFC 8259](https://tools.ietf.org/html/rfc8259) specifies:

> An implementation may set limits on the maximum depth of nesting.

In this class, the array's limit of nesting is not explicitly constrained. However, a maximum depth of nesting may be introduced by the compiler or runtime environment. A theoretical limit can be queried by calling the [`max_size`](https://json.nlohmann.me/api/basic_json/max_size/index.md) function of a JSON array.

#### Storage

Arrays are stored as pointers in a `basic_json` type. That is, for any access to array values, a pointer of type `array_t*` must be dereferenced.

## Examples

Example

The following code shows that `array_t` is by default, a typedef to `std::vector<nlohmann::json>`.

```
#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    std::cout << std::boolalpha << std::is_same<std::vector<json>, json::array_t>::value << std::endl;
}
```

Output:

```
true
```

## Version history

- Added in version 1.0.0.
