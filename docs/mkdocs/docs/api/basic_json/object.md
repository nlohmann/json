# <small>nlohmann::basic_json::</small>object

```cpp
static basic_json object(initializer_list_t init = {});
```

Creates a JSON object value from a given initializer list. The initializer lists elements must be pairs, and their first
elements must be strings. If the initializer list is empty, the empty object `#!json {}` is created.

## Parameters

`init` (in)
:   initializer list with JSON values to create an object from (optional)

## Return value

JSON object value

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

## Exceptions

Throws [`type_error.301`](../../home/exceptions.md#jsonexceptiontype_error301) if `init` is not a list of pairs whose
first elements are strings. In this case, no object can be created. When such a value is passed to
`basic_json(initializer_list_t, bool, value_t)`, an array would have been created from the passed initializer list
`init`. See example below.

## Complexity

Linear in the size of `init`.

## Notes

This function is only added for symmetry reasons. In contrast to the related function `array(initializer_list_t)`, there
are no cases which can only be expressed by this function. That is, any initializer list `init` can also be passed to
the initializer list constructor `basic_json(initializer_list_t, bool, value_t)`.
    
## Examples

??? example

    The following code shows an example for the `object` function.

    ```cpp
    --8<-- "examples/object.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/object.output"
    ```

## See also

- [`basic_json(initializer_list_t)`](basic_json.md) - create a JSON value from an initializer list
- [`array`](array.md) - create a JSON array value from an initializer list

## Version history

- Added in version 1.0.0.
