# <small>nlohmann::basic_json::</small>swap

```cpp
// (1)
void swap(reference other) noexcept;

// (2)
void swap(reference left, reference right) noexcept;

// (3)
void swap(array_t& other);

// (4)
void swap(object_t& other);

// (5)
void swap(string_t& other);

// (6)
void swap(binary_t& other);

// (7)
void swap(typename binary_t::container_type& other);
```

1. Exchanges the contents of the JSON value with those of `other`. Does not invoke any move, copy, or swap operations on
   individual elements. All iterators and references remain valid. The past-the-end iterator is invalidated. 
2. Exchanges the contents of the JSON value from `left` with those of `right`. Does not invoke any move, copy, or swap
   operations on individual elements. All iterators and references remain valid. The past-the-end iterator is
   invalidated. Implemented as a friend function callable via ADL.
3. Exchanges the contents of a JSON array with those of `other`. Does not invoke any move, copy, or swap operations on
   individual elements. All iterators and references remain valid. The past-the-end iterator is invalidated. 
4. Exchanges the contents of a JSON object with those of `other`. Does not invoke any move, copy, or swap operations on
   individual elements. All iterators and references remain valid. The past-the-end iterator is invalidated.
5. Exchanges the contents of a JSON string with those of `other`. Does not invoke any move, copy, or swap operations on
   individual elements. All iterators and references remain valid. The past-the-end iterator is invalidated.
6. Exchanges the contents of a binary value with those of `other`. Does not invoke any move, copy, or swap operations on
   individual elements. All iterators and references remain valid. The past-the-end iterator is invalidated.
7. Exchanges the contents of a binary value with those of `other`. Does not invoke any move, copy, or swap operations on
   individual elements. All iterators and references remain valid. The past-the-end iterator is invalidated. Unlike
   version (6), no binary subtype is involved.

## Parameters

`other` (in, out)
:   value to exchange the contents with

`left` (in, out)
:   value to exchange the contents with

`right` (in, out)
:   value to exchange the contents with

## Exceptions

1. No-throw guarantee: this function never throws exceptions.
2. No-throw guarantee: this function never throws exceptions.
3. Throws [`type_error.310`](../../home/exceptions.md#jsonexceptiontype_error310) if called on JSON values other than
   arrays; example: `"cannot use swap() with boolean"`
4. Throws [`type_error.310`](../../home/exceptions.md#jsonexceptiontype_error310) if called on JSON values other than
   objects; example: `"cannot use swap() with boolean"`
5. Throws [`type_error.310`](../../home/exceptions.md#jsonexceptiontype_error310) if called on JSON values other than
   strings; example: `"cannot use swap() with boolean"`
6. Throws [`type_error.310`](../../home/exceptions.md#jsonexceptiontype_error310) if called on JSON values other than
   binaries; example: `"cannot use swap() with boolean"`
7. Throws [`type_error.310`](../../home/exceptions.md#jsonexceptiontype_error310) if called on JSON values other than
   binaries; example: `"cannot use swap() with boolean"`

## Complexity

Constant.

## Examples

??? example "Example: Swap JSON value (1, 2)"

    The example below shows how JSON values can be swapped with `swap()`.
    
    ```cpp
    --8<-- "examples/swap__reference.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/swap__reference.output"
    ```

??? example "Example: Swap array (3)"

    The example below shows how arrays can be swapped with `swap()`.
    
    ```cpp
    --8<-- "examples/swap__array_t.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/swap__array_t.output"
    ```

??? example "Example: Swap object (4)"

    The example below shows how objects can be swapped with `swap()`.
    
    ```cpp
    --8<-- "examples/swap__object_t.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/swap__object_t.output"
    ```

??? example "Example: Swap string (5)"

    The example below shows how strings can be swapped with `swap()`.
    
    ```cpp
    --8<-- "examples/swap__string_t.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/swap__string_t.output"
    ```

??? example "Example: Swap string (6)"

    The example below shows how binary values can be swapped with `swap()`.
    
    ```cpp
    --8<-- "examples/swap__binary_t.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/swap__binary_t.output"
    ```

## See also

- [std::swap<basic_json\>](std_swap.md)

## Version history

1. Since version 1.0.0.
2. Since version 1.0.0.
3. Since version 1.0.0.
4. Since version 1.0.0.
5. Since version 1.0.0.
6. Since version 3.8.0.
7. Since version 3.8.0.