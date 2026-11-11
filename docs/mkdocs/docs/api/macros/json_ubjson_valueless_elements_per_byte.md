# JSON_UBJSON_VALUELESS_ELEMENTS_PER_BYTE

```cpp
#define JSON_UBJSON_VALUELESS_ELEMENTS_PER_BYTE /* value */
```

[`from_ubjson`](../basic_json/from_ubjson.md) and [`sax_parse`](../basic_json/sax_parse.md) refuse an input in which the
optimized arrays of type `Z` (null), `T` (true), and `F` (false) together have more than 1,048,576 elements plus
`JSON_UBJSON_VALUELESS_ELEMENTS_PER_BYTE` for every byte read so far, with
[`out_of_range.408`](../../home/exceptions.md#jsonexceptionout_of_range408). The macro sets that number. It is the
elements per byte that the input is allowed to announce without paying for them: an element of such an array is a
single marker that is implied by the array's `$Z#n` header, so a few bytes can announce a million values (see
[Parsing Untrusted Input](../../features/parsing/untrusted_input.md)).

The macro only matters for input that was not written by this library 3.13.0 or later:
[`to_ubjson`](../basic_json/to_ubjson.md) never writes more than the base of 1,048,576 elements in typed arrays of
these types, and a reader accepts at least that many whatever the macro is. Its main use is reading files written by
version 3.12.0 and earlier, which did not limit them (see
[below](#reading-files-written-by-version-3120-and-earlier)).

## Default definition

The default value is `4`.

```cpp
#define JSON_UBJSON_VALUELESS_ELEMENTS_PER_BYTE 4
```

## Notes

!!! info "Allowed values"

    The value must be a **positive integer** (a value of `0` would not allow any element beyond the base, and a negative
    or fractional rate has no meaning). Any other value is a compile-time error with a message that names the macro:

    ```
    error: static assertion failed: JSON_UBJSON_VALUELESS_ELEMENTS_PER_BYTE must be a positive integer
    error: static assertion failed: JSON_UBJSON_VALUELESS_ELEMENTS_PER_BYTE must be an integer (not bool or a character type)
    error: static assertion failed: JSON_UBJSON_VALUELESS_ELEMENTS_PER_BYTE must not be wider than std::uintmax_t
    ```

    The first is reported for `0` and negative values, the second for values such as `4.5`, `1e3`, `true`, or `'a'`, and
    the third for an integer type that is wider than `#!cpp std::uintmax_t` (for example `unsigned __int128`). A value
    that is larger than the largest `#!cpp std::size_t` is treated as that largest value, so that a project can use one
    spelling, for example `0xFFFFFFFFFFFFFFFFu`, for 32-bit and 64-bit targets.

!!! info "Large values: the limit is switched off"

    The limit is the base plus the rate times the bytes read. It saturates at the largest `#!cpp std::size_t` instead of
    overflowing, for any rate and any input size (also with a 32-bit `#!cpp std::size_t`), so a large value never makes
    the limit smaller. A rate of **at least 131,072** (`1048576 / 8`) effectively switches the limit for the whole
    input off: the shortest header of an array of more than 32,767 elements takes 8 bytes (`$Z#l` and four bytes of the
    count, inside an optimized array of arrays; 9 bytes, `[$Z#l`, at the top level), and a shorter header (`$Z#I` and
    two bytes) can announce at most 32,767. No array can then announce more than the rate times the bytes of its own
    header. With a rate of 131,071 that is not so: rows of 1,048,576 elements in 8 bytes each gain 8 elements per row,
    and a table of 278,527 such rows (2.2 MB) is the shortest input that is refused.

!!! info "What the macro does not change"

    - The limit of **one array** stays at 1,048,576 elements
      ([`out_of_range.408`](../../home/exceptions.md#jsonexceptionout_of_range408), "excessive array size"), whatever
      the macro is. A value that switches the whole-input limit off does not allow a single array of 1,048,577
      elements.
    - The **base** of 1,048,576 elements is a fixed constant, the same as the limit of one array. An array that was
      accepted on its own before the whole-input limit existed is therefore still accepted at the start of an input.
    - The **writer** is not affected. [`to_ubjson`](../basic_json/to_ubjson.md) follows the base only: it writes a typed
      array of `Z`, `T`, or `F` only while the arrays written so far and this one stay within 1,048,576 elements, and
      writes the elements one by one otherwise. That is within the limit of every reader, because the limit is never
      below the base.
    - **Objects** and arrays of other types are not counted: every member of an object has a key, and every element of
      another type takes at least a byte of input.
    - [`from_bjdata`](../basic_json/from_bjdata.md) is not affected: BJData has no optimized arrays of these types.

!!! info "Memory"

    A value takes 16 bytes in a DOM, so every element that the limit lets pass costs memory. Beyond the first 1,048,576
    elements (about 33 MB: 16 bytes per element, and a vector that grows by reallocation needs the old and the new
    storage at once), a malicious input of `n` bytes can take **about `20 * K * n` bytes** of memory in a DOM, where `K`
    is the value of the macro. The measurements below read inputs that are at the limit, with containers of `9 * K`
    elements (`[$Z#l` and a count, 9 bytes each), with `from_ubjson` on macOS, arm64, compiled with `-O2`. The numbers
    on other systems differ by the allocator; the 16 bytes per element are the lower bound.

    | `K`   | bytes of memory per byte of input | memory for 1 MB of input |
    |------:|----------------------------------:|-------------------------:|
    |     1 |                                25 |                    25 MB |
    |     4 |                                81 |                    81 MB |
    |    16 |                               312 |                   312 MB |
    |    64 |                             1,226 |                   1.2 GB |
    |   256 |                             5,493 |                   5.5 GB |

    A SAX handler receives the same number of events, and no memory beyond what it keeps. Choose the smallest value that
    accepts your files, not a large one, if the input comes from an untrusted source: a value of 131,072 or more
    switches the limit of the whole input off, so that every 8 bytes of input can announce another 1,048,576 values,
    the limit of one array.

!!! warning "Define it before the include, in every translation unit"

    This macro must be defined **before** including `<nlohmann/json.hpp>`. Defining it after the include has no effect.

    The value is compiled into the member functions of the binary reader, which are inline, but it is **not**
    encoded in the [namespace](../../features/namespace.md) of the library (there is no ABI tag for it). It must
    have the same value in every translation unit of a program (for example by defining it on the command line or in
    a common header); translation units with different values violate the One Definition Rule, which is undefined
    behavior (no diagnostic is required; in practice the linker keeps one definition of each function, so some
    inputs are read with one value and some with the other).

### Reading files written by version 3.12.0 and earlier

Version 3.12.0 wrote an array of `Z`, `T`, or `F` of any length in the optimized form, and a table of equal rows as an
optimized array of optimized arrays: a header of `[$[#` and the number of rows (`i` or `U` and 1 byte, `I` and 2 bytes, or
`l` and 4 bytes: `h` = 6, 7, or 9 bytes in all for up to 255, 32,767, or more rows), then for every row `$Z#` and its count:
5 bytes for up to 255 elements (`U`), 6 bytes for up to 32,767 (`I`), and 8 bytes above (`l`). Every row announces `N`
elements for the `b` bytes of its header, so the limit grows by `K * b` and the number of elements by `N` per row.

- A table is never refused if its rows have at most `K * b` elements each: at most 5 `K` for rows of up to 255
  elements (20 at the default of `K = 4`), at most 6 `K` for rows of 256 to 32,767 (rows of 1,000 need `K >= 167`),
  and at most 8 `K` above.
- Otherwise the first `(1,048,576 + h * K) / (N - K * b)` rows are accepted, rounded down (`h` as above; 7 for the
  numbers here). For the default, a table of rows of 1,000 `null` values is read up to row 1,074 (the input of the first
  example below has 1,100); for `K = 1`, up to row 1,054; for `K = 16`, up to row 1,160.
- In general, the smallest value that accepts an input is the largest of
  `(the elements of the arrays so far - 1,048,576) / (the bytes read when the header of the last of them has been
  read)` over all arrays, rounded up. For 1,100 rows of 1,000 elements that is
  `(1,100,000 - 1,048,576) / 6,607 = 7.8`, so `K = 8`.

To read such a file, define the macro to the smallest value that accepts it before the include (or with
`-DJSON_UBJSON_VALUELESS_ELEMENTS_PER_BYTE=8`), and see the table above for what that value allows an untrusted input to
cost. A file can be converted once: read it with the larger value and write it again with `to_ubjson`, which writes no
typed array that a reader with the default value would refuse, so that the result does not need the macro.

## Examples

??? example "Example: default limit"

    The table of 1,100 rows of 1,000 `null` values (6,607 bytes) that version 3.12.0 wrote announces 1,100,000 values,
    which is more than 1,048,576 plus 4 for every byte read.

    ```cpp
    --8<-- "examples/ubjson_valueless_elements_per_byte.cpp"
    ```

    Output:

    ```
    --8<-- "examples/ubjson_valueless_elements_per_byte.output"
    ```

??? example "Example: raised limit"

    With 16 elements per byte the same table is read. The limit of one array still applies.

    ```cpp
    --8<-- "examples/ubjson_valueless_elements_per_byte_raised.cpp"
    ```

    Output:

    ```
    --8<-- "examples/ubjson_valueless_elements_per_byte_raised.output"
    ```

## See also

- [`from_ubjson`](../basic_json/from_ubjson.md) - create a JSON value from a UBJSON serialization
- [`to_ubjson`](../basic_json/to_ubjson.md) - create a UBJSON serialization of a JSON value
- [`sax_parse`](../basic_json/sax_parse.md) - generate SAX events
- [UBJSON](../../features/binary_formats/ubjson.md) - the format and its limits in the library
- [Parsing Untrusted Input](../../features/parsing/untrusted_input.md) - limits and checks for input you do not control
- [`out_of_range.408`](../../home/exceptions.md#jsonexceptionout_of_range408) - the exception that reports the limit

## Version history

- Added in version 3.13.0.
