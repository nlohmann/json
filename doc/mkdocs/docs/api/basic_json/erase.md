# <small>nlohmann::basic_json::</small>erase

```cpp
// (1)
iterator erase(iterator pos);
const_iterator erase(const_iterator pos);

// (2)
iterator erase(iterator first, iterator last);
const_iterator erase(const_iterator first, const_iterator last);

// (3)
size_type erase(const typename object_t::key_type& key);

// (4)
void erase(const size_type idx);
```

1. Removes an element from a JSON value specified by iterator `pos`. The iterator `pos` must be valid and
   dereferenceable. Thus, the `end()` iterator (which is valid, but is not dereferenceable) cannot be used as a value for
   `pos`.
   
    If called on a primitive type other than `#!json null`, the resulting JSON value will be `#!json null`.

2. Remove an element range specified by `[first; last)` from a JSON value. The iterator `first` does not need to be
   dereferenceable if `first == last`: erasing an empty range is a no-op.
   
    If called on a primitive type other than `#!json null`, the resulting JSON value will be `#!json null`.

3. Removes an element from a JSON object by key.

4. Removes an element from a JSON array by index.

## Parameters

`pos` (in)
:   iterator to the element to remove

`first` (in)
:   iterator to the beginning of the range to remove

`last` (in)
:   iterator past the end of the range to remove

`key` (in)
:   object key of the elements to remove
    
`idx` (in)
:   array index of the element to remove
    
## Return value

1. Iterator following the last removed element. If the iterator `pos` refers to the last element, the `end()` iterator
   is returned.
2. Iterator following the last removed element. If the iterator `last` refers to the last element, the `end()` iterator
   is returned.
3. Number of elements removed. If `ObjectType` is the default `std::map` type, the return value will always be `0`
   (`key` was not found) or `1` (`key` was found).
4. /

## Exception safety

Strong exception safety: if an exception occurs, the original value stays intact.

## Exceptions

1. The function can throw the following exceptions:
    - Throws [`type_error.307`](../../home/exceptions.md#jsonexceptiontype_error307) if called on a `null` value;
      example: `"cannot use erase() with null"`
    - Throws [`invalid_iterator.202`](../../home/exceptions.md#jsonexceptioninvalid_iterator202) if called on an
      iterator which does not belong to the current JSON value; example: `"iterator does not fit current value"`
    - Throws [`invalid_iterator.205`](../../home/exceptions.md#jsonexceptioninvalid_iterator205) if called on a
      primitive type with invalid iterator (i.e., any iterator which is not `begin()`); example: `"iterator out of
      range"`
2. The function can throw the following exceptions:
    - Throws [`type_error.307`](../../home/exceptions.md#jsonexceptiontype_error307) if called on a `null` value;
      example: `"cannot use erase() with null"`
    - Throws [`invalid_iterator.203`](../../home/exceptions.md#jsonexceptioninvalid_iterator203) if called on iterators
      which does not belong to the current JSON value; example: `"iterators do not fit current value"`
    - Throws [`invalid_iterator.204`](../../home/exceptions.md#jsonexceptioninvalid_iterator204) if called on a
      primitive type with invalid iterators (i.e., if `first != begin()` and `last != end()`); example: `"iterators out
      of range"`
3. The function can throw the following exceptions:
    - Throws [`type_error.307`](../../home/exceptions.md#jsonexceptiontype_error307) when called on a type other than
      JSON object; example: `"cannot use erase() with null"`
4. The function can throw the following exceptions:
    - Throws [`type_error.307`](../../home/exceptions.md#jsonexceptiontype_error307) when called on a type other than
      JSON object; example: `"cannot use erase() with null"`
    - Throws [`out_of_range.401`](../../home/exceptions.md#jsonexceptionout_of_range401) when `idx >= size()`; example:
      `"array index 17 is out of range"`

## Complexity

1. The complexity depends on the type:
       - objects: amortized constant
       - arrays: linear in distance between `pos` and the end of the container
       - strings and binary: linear in the length of the member
       - other types: constant
2. The complexity depends on the type:
       - objects: `log(size()) + std::distance(first, last)`
       - arrays: linear in the distance between `first` and `last`, plus linear
         in the distance between `last` and end of the container
       - strings and binary: linear in the length of the member
       - other types: constant
3. `log(size()) + count(key)`
4. Linear in distance between `idx` and the end of the container.

## Notes

1. Invalidates iterators and references at or after the point of the `erase`, including the `end()` iterator.
2. /
3. References and iterators to the erased elements are invalidated. Other references and iterators are not affected.
4. /

## Examples

??? example "Example: (1) remove element given an iterator"

    The example shows the effect of `erase()` for different JSON types using an iterator.
    
    ```cpp
    --8<-- "examples/erase__IteratorType.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/erase__IteratorType.output"
    ```

??? example "Example: (2) remove elements given an iterator range"

    The example shows the effect of `erase()` for different JSON types using an iterator range.
    
    ```cpp
    --8<-- "examples/erase__IteratorType_IteratorType.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/erase__IteratorType_IteratorType.output"
    ```

??? example "Example: (3) remove element from a JSON object given a key"

    The example shows the effect of `erase()` for different JSON types using an object key.
    
    ```cpp
    --8<-- "examples/erase__key_type.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/erase__key_type.output"
    ```

??? example "Example: (4) remove element from a JSON array given an index"

    The example shows the effect of `erase()` using an array index.
    
    ```cpp
    --8<-- "examples/erase__size_type.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/erase__size_type.output"
    ```

## Version history

- Added in version 1.0.0.
- Added support for binary types in version 3.8.0.
