# nlohmann::basic_json::default_object_comparator_t

```
using default_object_comparator_t = std::less<StringType>;  // until C++14

using default_object_comparator_t = std::less<>;            // since C++14
```

The default comparator used by [`object_t`](https://json.nlohmann.me/api/basic_json/object_t/index.md).

Since C++14 a transparent comparator is used which prevents unnecessary string construction when looking up a key in an object.

The actual comparator used depends on [`object_t`](https://json.nlohmann.me/api/basic_json/object_t/index.md) and can be obtained via [`object_comparator_t`](https://json.nlohmann.me/api/basic_json/object_comparator_t/index.md).

## Examples

Example

The example below demonstrates the default comparator.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    std::cout << std::boolalpha
              << "one < two : " << json::default_object_comparator_t{}("one", "two") << "\n"
              << "three < four : " << json::default_object_comparator_t{}("three", "four") << std::endl;
}
```

Output:

```
one < two : true
three < four : false
```

## Version history

- Added in version 3.11.0.
