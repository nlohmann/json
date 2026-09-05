# <small>nlohmann::basic_json::</small>json_base_class_t

```cpp
using json_base_class_t = detail::json_base_class<CustomBaseClass>;
```

The base class used to inject custom functionality into each instance of `basic_json`.
Examples of such functionality might be metadata, additional member functions (e.g., visitors), or other application-specific code.

## Template parameters

`CustomBaseClass`
:   the base class to be added to `basic_json`

## Notes

#### Default type

The default value for `CustomBaseClass` is `void`. In this case, an
[empty base class](https://en.cppreference.com/w/cpp/language/ebo) is used and no additional functionality is injected.

#### Limitations

The type `CustomBaseClass` has to be a default-constructible, non-`final` class.
`basic_json` only supports copy/move construction/assignment if `CustomBaseClass` does so as well.
A `CustomBaseClass` with non-static data members forfeits `basic_json`'s
[standard layout](https://en.cppreference.com/w/cpp/named_req/StandardLayoutType) guarantee. See
[Template Parameter Requirements](../../features/types/template_parameters.md#custombaseclass).

## Examples

??? example

    The following code shows how to inject custom data and methods for each node.
     
    ```cpp
    --8<-- "examples/json_base_class_t.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/json_base_class_t.output"
    ```

## Version history

- Added in version 3.12.0.
