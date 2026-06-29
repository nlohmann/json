# <small>nlohmann::basic_json::</small>update

```cpp
// (1)
void update(const_reference j, bool merge_objects = false);

// (2)
void update(const_iterator first, const_iterator last, bool merge_objects = false);
```

1. Inserts all values from JSON object `j`.
2. Inserts all values from range `[first, last)`

When `merge_objects` is `#!c false` (default), existing keys are overwritten. When `merge_objects` is `#!c true`,
recursively merges objects with common keys.

If the JSON value is `#!json null`, it is implicitly converted to an empty object before the values are inserted.

The function is motivated by Python's [dict.update](https://docs.python.org/3.6/library/stdtypes.html#dict.update)
function.

## Iterator invalidation

For [`ordered_json`](../ordered_json.md), adding a value to an object can yield a reallocation, in which case all
iterators (including the `end()` iterator) and all references to the elements are invalidated.

## Parameters

`j` (in)
:   JSON object to read values from

`merge_objects` (in)
:   when `#!c true`, keys that exist in both objects and whose value in the source is itself an object are merged
    recursively; all other values are overwritten as usual (default: `#!c false`)

`first` (in)
:   the beginning of the range of elements to insert

`last` (in)
:   the end of the range of elements to insert

## Exception safety

Basic guarantee: if an exception is thrown during the operation, the JSON value may be partially modified.

## Exceptions

1. The function can throw the following exceptions:
    - Throws [`type_error.312`](../../home/exceptions.md#jsonexceptiontype_error312) if called on JSON values other than
      objects; example: `"cannot use update() with string"`
2. The function can throw the following exceptions:
    - Throws [`type_error.312`](../../home/exceptions.md#jsonexceptiontype_error312) if called on JSON values other than
      objects; example: `"cannot use update() with string"`
    - Throws [`invalid_iterator.210`](../../home/exceptions.md#jsonexceptioninvalid_iterator210) if `first` and `last`
      do not belong to the same JSON value; example: `"iterators do not fit"`

## Complexity

1. O(N*log(size() + N)), where N is the number of elements to insert.
2. O(N*log(size() + N)), where N is the number of elements to insert.

## Examples

??? example

    The example shows how `update()` is used.
    
    ```cpp
    --8<-- "examples/update.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/update.output"
    ```

??? example

    The example shows how `update()` is used.
    
    ```cpp
    --8<-- "examples/update__range.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/update__range.output"
    ```

??? example

    One common use case for this function is the handling of user settings. Assume your application can be configured in
    some aspects:

    ```json
    {
        "color": "red",
        "active": true,
        "name": {"de": "Maus", "en": "mouse"}
    }
    ```

    The user may override the default settings selectively:

    ```json
    {
        "color": "blue",
        "name": {"es": "ratón"},
    }
    ```

    Then `update` manages the merging of default settings and user settings:
 
    ```cpp
    auto user_settings = json::parse("config.json");
    auto effective_settings = get_default_settings();
    effective_settings.update(user_settings);
    ```
    
    Now `effective_settings` contains the default settings, but those keys set by the user are overwritten:

    ```json
    {
        "color": "blue",
        "active": true,
        "name": {"es": "ratón"}
    }
    ```

    Note existing keys were just overwritten. To merge objects, `merge_objects` setting should be set to `#!c true`:
    
    ```cpp
    auto user_settings = json::parse("config.json");
    auto effective_settings = get_default_settings();
    effective_settings.update(user_settings, true);
    ```

    ```json
    {
        "color": "blue",
        "active": true,
        "name": {"de": "Maus", "en": "mouse", "es": "ratón"}
    }
    ```

## See also

- [insert](insert.md) add values to an array/object
- [merge_patch](merge_patch.md) applies a JSON Merge Patch

## Version history

- Added in version 3.0.0.
- Added `merge_objects` parameter in 3.10.5.
