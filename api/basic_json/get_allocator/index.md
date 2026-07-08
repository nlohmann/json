# nlohmann::basic_json::get_allocator

```
static allocator_type get_allocator();
```

Returns the allocator associated with the container.

## Return value

associated allocator

## Examples

Example

The example shows how `get_allocator()` is used to created `json` values.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    auto alloc = json::get_allocator();
    using traits_t = std::allocator_traits<decltype(alloc)>;

    json* j = traits_t::allocate(alloc, 1);
    traits_t::construct(alloc, j, "Hello, world!");

    std::cout << *j << std::endl;

    traits_t::destroy(alloc, j);
    traits_t::deallocate(alloc, j, 1);
}
```

Output:

```
"Hello, world!"
```

## Version history

- Added in version 1.0.0.
