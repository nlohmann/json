# <small>nlohmann::basic_json::</small>array

```cpp
static basic_json array(initializer_list_t init = {});
```

Creates a JSON array value from a given initializer list. That is, given a list of values `a, b, c`, creates the JSON
value `#!json [a, b, c]`. If the initializer list is empty, the empty array `#!json []` is created.

## Parameters

`init` (in)
:   initializer list with JSON values to create an array from (optional)

## Return value

JSON array value

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

## Complexity

Linear in the size of `init`.

## Notes

This function is only needed to express two edge cases that cannot be realized with the initializer list constructor
([`basic_json(initializer_list_t, bool, value_t)`](basic_json.md)). These cases are:

1. creating an array whose elements are all pairs whose first element is a string -- in this case, the initializer list
   constructor would create an object, taking the first elements as keys
2. creating an empty array -- passing the empty initializer list to the initializer list constructor yields an empty
   object

## Examples

??? example

    The following code shows an example for the `array` function.

    ```cpp
    --8<-- "examples/array.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/array.output"
    ```

## See also

- [`basic_json(initializer_list_t)`](basic_json.md) - create a JSON value from an initializer list
- [`object`](object.md) - create a JSON object value from an initializer list

## Version history

- Added in version 1.0.0.
