# nlohmann::basic_json::as_base_class

```
json_base_class_t& as_base_class() noexcept;
const json_base_class_t& as_base_class() const noexcept;
```

Returns a reference to this object as its custom base class [`json_base_class_t`](https://json.nlohmann.me/api/basic_json/json_base_class_t/index.md). No copy is made.

Since `basic_json` derives from `json_base_class_t`, a member of `basic_json` hides any member of the custom base class with the same name. This function makes such hidden members accessible again.

## Return value

reference to this object as [`json_base_class_t`](https://json.nlohmann.me/api/basic_json/json_base_class_t/index.md)

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Notes

The function is equivalent to `static_cast<json_base_class_t&>(j)` (or `static_cast<const json_base_class_t&>(j)`).

## Examples

Example

The example shows how to use `as_base_class` to access members of the custom base class that are hidden by members of `basic_json`.

```
#include <iostream>
#include <nlohmann/json.hpp>

class base_class_with_hidden_members
{
  public:
    const char* type_name() const noexcept
    {
        return "my_type_name";
    }

    std::size_t size() const noexcept
    {
        return 42;
    }
};

using json = nlohmann::json::with_base_class_t<base_class_with_hidden_members>;

int main()
{
    json j = {1, 2, 3};

    // the members of basic_json hide the members of the base class
    std::cout << j.type_name() << ' ' << j.size() << '\n';

    // access the hidden members of the base class
    std::cout << j.as_base_class().type_name() << ' ' << j.as_base_class().size() << '\n';
}
```

Output:

```
array 3
my_type_name 42
```

## See also

- [json_base_class_t](https://json.nlohmann.me/api/basic_json/json_base_class_t/index.md) - type of the custom base class

## Version history

- Added in version 3.13.0 unreleased.
