# basic_json::insert

```cpp
// (1)
iterator insert(const_iterator pos, const basic_json& val);
iterator insert(const_iterator pos, basic_json&& val);

// (2)
iterator insert(const_iterator pos, size_type cnt, const basic_json& val);

// (3)
iterator insert(const_iterator pos, const_iterator first, const_iterator last);

// (4)
iterator insert(const_iterator pos, initializer_list_t ilist);

// (5)
void insert(const_iterator first, const_iterator last);
```

1. Inserts element `val` to array before iterator `pos`.
2. Inserts `cnt` copies of `val` to array before iterator `pos`.
3. Inserts elements from range `[first, last)` to array before iterator `pos`.
4. Inserts elements from initializer list `ilist` to array before iterator `pos`.
5. Inserts elements from range `[first, last)` to object.

## Parameters

`pos` (in)
:   iterator before which the content will be inserted; may be the `end()` iterator

`val` (in)
:   value to insert

`cnt` (in)
:   number of copies of `val` to insert

`first` (in)
:   begin of the range of elements to insert

`last` (in)
:   end of the range of elements to insert

`ilist` (in)
:   initializer list to insert the values from
    
## Return value

1. iterator pointing to the inserted `val`.
2. iterator pointing to the first element inserted, or `pos` if `#!cpp cnt==0`
3. iterator pointing to the first element inserted, or `pos` if `#!cpp first==last`
4. iterator pointing to the first element inserted, or `pos` if `ilist` is empty
5. /

## Exceptions

1. The function can throw the following exceptions:
    - Throws [`type_error.309`](../../home/exceptions.md#jsonexceptiontype_error309) if called on JSON values other than
      arrays; example: `"cannot use insert() with string"`
    - Throws [`invalid_iterator.202`](../../home/exceptions.md#jsonexceptioninvalid_iterator202) if called on an
      iterator which does not belong to the current JSON value; example: `"iterator does not fit current value"`
2. The function can throw thw following exceptions:
    - Throws [`type_error.309`](../../home/exceptions.md#jsonexceptiontype_error309) if called on JSON values other than
      arrays; example: `"cannot use insert() with string"`
    - Throws [`invalid_iterator.202`](../../home/exceptions.md#jsonexceptioninvalid_iterator202) if called on an
      iterator which does not belong to the current JSON value; example: `"iterator does not fit current value"`
3. The function can throw thw following exceptions:
    - Throws [`type_error.309`](../../home/exceptions.md#jsonexceptiontype_error309) if called on JSON values other than
      arrays; example: `"cannot use insert() with string"`
    - Throws [`invalid_iterator.202`](../../home/exceptions.md#jsonexceptioninvalid_iterator202) if called on an
      iterator which does not belong to the current JSON value; example: `"iterator does not fit current value"`
    - Throws [`invalid_iterator.210`](../../home/exceptions.md#jsonexceptioninvalid_iterator210) if `first` and `last`
      do not belong to the same JSON value; example: `"iterators do not fit"`
    - Throws [`invalid_iterator.211`](../../home/exceptions.md#jsonexceptioninvalid_iterator211) if `first` or `last`
      are iterators into container for which insert is called; example: `"passed iterators may not belong to container"`
4. The function can throw thw following exceptions:
    - Throws [`type_error.309`](../../home/exceptions.md#jsonexceptiontype_error309) if called on JSON values other than
      arrays; example: `"cannot use insert() with string"`
    - Throws [`invalid_iterator.202`](../../home/exceptions.md#jsonexceptioninvalid_iterator202) if called on an
      iterator which does not belong to the current JSON value; example: `"iterator does not fit current value"`
5. The function can throw thw following exceptions:
    - Throws [`type_error.309`](../../home/exceptions.md#jsonexceptiontype_error309) if called on JSON values other than
      objects; example: `"cannot use insert() with string"`
    - Throws [`invalid_iterator.202`](../../home/exceptions.md#jsonexceptioninvalid_iterator202) if called on an
      iterator which does not belong to the current JSON value; example: `"iterator does not fit current value"`
    - Throws [`invalid_iterator.210`](../../home/exceptions.md#jsonexceptioninvalid_iterator210) if `first` and `last`
      do not belong to the same JSON value; example: `"iterators do not fit"`

## Exception safety

Strong exception safety: if an exception occurs, the original value stays intact.

## Complexity

1. Constant plus linear in the distance between `pos` and end of the container.
2. Linear in `cnt` plus linear in the distance between `pos` and end of the container.
3. Linear in `#!cpp std::distance(first, last)` plus linear in the distance between `pos` and end of the container.
4. Linear in `ilist.size()` plus linear in the distance between `pos` and end of the container.
5. Logarithmic: `O(N*log(size() + N))`, where `N` is the number of elements to insert.

## Example

??? example

    The example shows how `insert()` is used.
    
    ```cpp
    --8<-- "examples/insert.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/insert.output"
    ```

??? example

    The example shows how `insert()` is used.
    
    ```cpp
    --8<-- "examples/insert__count.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/insert__count.output"
    ```

??? example

    The example shows how `insert()` is used.
    
    ```cpp
    --8<-- "examples/insert__range.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/insert__range.output"
    ```

??? example

    The example shows how `insert()` is used.
    
    ```cpp
    --8<-- "examples/insert__ilist.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/insert__ilist.output"
    ```

??? example

    The example shows how `insert()` is used.
    
    ```cpp
    --8<-- "examples/insert__range_object.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/insert__range_object.output"
    ```

## Version history

1. Added in version 1.0.0.
2. Added in version 1.0.0.
3. Added in version 1.0.0.
4. Added in version 1.0.0.
5. Added in version 3.0.0.
