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
    --8<-- "examples/get_allocator.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/get_allocator.output"
    ```

## See also

- [basic_json](index.md#template-parameters) the class template, with `AllocatorType` as one of its template parameters
- [Template Parameter Requirements](../../features/types/template_parameters.md#allocatortype) - the requirements for `AllocatorType`

## Version history

- Added in version 1.0.0.
