# <small>nlohmann::basic_json::</small>json_base_class_t

```cpp
using json_base_class_t = detail::json_base_class<CustomBaseClass>;
```

The base class used to inject custom functionality into each instance of `basic_json`.
Examples of such functionality might be metadata, additional member functions (e.g., visitors), or other application-specific code.

!!! warning "Name conflicts when using generic names"

    Tt is possible for name shadowing to occur since `nlohmann::basic_json` is derived from this class.
    If this happens, the correct method or member variable can be accessed by either casting the json object to the base class or calling [as_base_class](as_base_class.md).
    When updating to a new version of this library a previously available member might be shadowed by a new member of `nlohmann::basic_json`.

## Template parameters

`CustomBaseClass`
:   the base class to be added to `basic_json`

## Notes

#### Default type

The default value for `CustomBaseClass` is `void`. In this case an
[empty base class](https://en.cppreference.com/w/cpp/language/ebo) is used and no additional functionality is injected.

#### Limitations

The type `CustomBaseClass` has to be a default-constructible class.
`basic_json` only supports copy/move construction/assignment if `CustomBaseClass` does so as well.

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
