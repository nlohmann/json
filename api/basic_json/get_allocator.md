# <small>nlohmann::basic_json::</small>get_allocator

```cpp
static allocator_type get_allocator();
```

Returns the allocator associated with the container.
    
## Return value

associated allocator

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes to any JSON value.

## Complexity

Constant.

## Examples

??? example

    The example shows how `get_allocator()` is used to created `json` values.
    
    ```cpp
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
    
    ```json
    "Hello, world!"
    
    ```

## See also

- [basic_json](index.md#template-parameters) the class template, with `AllocatorType` as one of its template parameters
- [Template Parameter Requirements](../../features/types/template_parameters.md#allocatortype) - the requirements for `AllocatorType`

## Version history

- Added in version 1.0.0.
