# <small>nlohmann::basic_json_view::</small>at

```cpp
// (1)
basic_json_view at(string_view_t key) const;
basic_json_view at(const char* key) const;
basic_json_view at(const string_t& key) const;

// (2)
basic_json_view at(size_type idx) const;
basic_json_view at(int idx) const;

// (3)
basic_json_view at(const json_pointer& ptr) const;
```

1. Returns the value of the object member with key `key` -- the first one, should the key occur more than once (see
   [Notes on duplicate keys](operator[].md#notes)).
2. Returns the array element at index `idx`.
3. Returns the value a JSON pointer `ptr` refers to, starting at this value.

## Parameters

`key` (in)
:   object key of the element to access

`idx` (in)
:   index of the element to access

`ptr` (in)
:   JSON pointer to the element to access

## Return value

1. the value of the first member with key `key`
2. the element at index `idx`
3. the value `ptr` resolves to, starting at this value

## Exception safety

Strong exception safety: if an exception is thrown, there are no changes to the view or the document it refers to.

## Exceptions

1. The function can throw the following exceptions, both with the same message as the corresponding call to
   [`BasicJsonType::at`](../basic_json/at.md):
    - Throws [`type_error.304`](../../home/exceptions.md#jsonexceptiontype_error304) if the value is not an object.
    - Throws [`out_of_range.403`](../../home/exceptions.md#jsonexceptionout_of_range403) if no member has key `key`.
2. The function can throw the following exceptions, both with the same message as the corresponding call to
   [`BasicJsonType::at`](../basic_json/at.md):
    - Throws [`type_error.304`](../../home/exceptions.md#jsonexceptiontype_error304) if the value is not an array.
    - Throws [`out_of_range.401`](../../home/exceptions.md#jsonexceptionout_of_range401) if `#!cpp idx >= size()`.
3. The function can throw the following exceptions, all with the same message as the corresponding call to
   [`BasicJsonType::at`](../basic_json/at.md):
    - Throws [`parse_error.106`](../../home/exceptions.md#jsonexceptionparse_error106) if an array index in `ptr`
      begins with `#!cpp '0'`.
    - Throws [`parse_error.109`](../../home/exceptions.md#jsonexceptionparse_error109) if an array index in `ptr` is
      not a number.
    - Throws [`out_of_range.401`](../../home/exceptions.md#jsonexceptionout_of_range401) if an array index in `ptr`
      is out of range.
    - Throws [`out_of_range.402`](../../home/exceptions.md#jsonexceptionout_of_range402) if a reference token is
      `#!cpp "-"` at an array -- `at` never inserts an element, so `#!cpp "-"` is always invalid.
    - Throws [`out_of_range.403`](../../home/exceptions.md#jsonexceptionout_of_range403) if a reference token names
      an object member that does not exist.
    - Throws [`out_of_range.404`](../../home/exceptions.md#jsonexceptionout_of_range404) if `ptr` cannot be resolved
      because a reference token is used on a primitive value.

None of these exceptions carry a [`JSON_DIAGNOSTICS`](../macros/json_diagnostics.md) path: the view has no
`BasicJsonType` value to point at, so the exception is created without one, even if `BasicJsonType` was built with
`JSON_DIAGNOSTICS` enabled.

## Complexity

1. Linear in the number of members: as for [`ordered_json`](../ordered_json.md), members are compared one after
   another, in document order, stopping at the first match. Each comparison first checks the key's length --
   already known from the index, without reading the key bytes -- before comparing its content.
2. Linear in `idx`: elements are skipped one at a time from the first one, since they are not a fixed size in the
   index (unlike `BasicJsonType`'s array, which is random-access).
3. Linear in the number of reference tokens of `ptr` and, for each token, in the number of members of the object at
   that level (as 1.) or the index into the array (as 2.).

## Notes

Unlike [`operator[]`](operator[].md), which returns a [discarded](is_discarded.md) view for a missing key or an
out-of-range index, `at` always throws -- exactly as `BasicJsonType::at` does, and with the same messages, so
existing error handling written against `BasicJsonType::at` keeps working unchanged when switched to a view. This
also holds for overload 3: unlike [`operator[]`](operator[].md) with a JSON pointer, which returns a discarded view
for a missing key or an out-of-range index, `at` throws for those too (`out_of_range.403`/`out_of_range.401`).

## Examples

??? example "Example: (1)/(2) access specified element with bounds checking"

    The example below reads required fields out of a service configuration with `at`, and shows that the exceptions
    it throws -- for a wrong type and for a missing key -- carry the same messages
    [`BasicJsonType::at`](../basic_json/at.md) would produce for the same JSON text.

    ```cpp
    --8<-- "examples/basic_json_view__at.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_view__at.output"
    ```

??? example "Example: (3) access specified element via JSON pointer with bounds checking"

    The example below shows that `at` with a JSON pointer throws exactly the exceptions, with exactly the messages,
    that [`BasicJsonType::at`](../basic_json/at.md) throws for the same pointer and the same document.

    ```cpp
    --8<-- "examples/basic_json_view__at_json_pointer.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_view__at_json_pointer.output"
    ```

## See also

- [operator[]](operator[].md) - access specified element (returns a discarded view instead of throwing)
- [front](front.md), [back](back.md) - access the first or last element
- [`BasicJsonType::at`](../basic_json/at.md) - the corresponding function of `basic_json`
- [`json_pointer`](../json_pointer/index.md) - JSON pointer type used by overload 3

## Version history

- Added in version 3.13.0.
