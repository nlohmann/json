# <small>nlohmann::basic_json::</small>number_integer_t

```cpp
using number_integer_t = NumberIntegerType;
```

The type used to store JSON numbers (integers).

[RFC 8259](https://tools.ietf.org/html/rfc8259) describes numbers as follows:
> The representation of numbers is similar to that used in most programming languages. A number is represented in base
> 10 using decimal digits. It contains an integer component that may be prefixed with an optional minus sign, which may
> be followed by a fraction part and/or an exponent part. Leading zeros are not allowed. (...) Numeric values that
> cannot be represented in the grammar below (such as Infinity and NaN) are not permitted.

This description includes both integer and floating-point numbers. However, C++ allows more precise storage if it is
known whether the number is a signed integer, an unsigned integer or a floating-point number. Therefore, three different
types, `number_integer_t`,  [`number_unsigned_t`](number_unsigned_t.md) and [`number_float_t`](number_float_t.md) are
used.

To store integer numbers in C++, a type is defined by the template parameter `NumberIntegerType` which chooses the type
to use.

## Notes

#### Default type

With the default values for `NumberIntegerType` (`std::int64_t`), the default value for `number_integer_t` is
`#!cpp std::int64_t`.

#### Default behavior

- The restrictions about leading zeros is not enforced in C++. Instead, leading zeros in integer literals lead to an
  interpretation as octal number. Internally, the value will be stored as decimal number. For instance, the C++ integer
  literal `010` will be serialized to `8`. During deserialization, leading zeros yield an error.
- Not-a-number (NaN) values will be serialized to `null`.

#### Limits

[RFC 8259](https://tools.ietf.org/html/rfc8259) specifies:
> An implementation may set limits on the range and precision of numbers.

When the default type is used, the maximal integer number that can be stored is `9223372036854775807` (INT64_MAX) and
the minimal integer number that can be stored is `-9223372036854775808` (INT64_MIN). Integer numbers that are out of
range will yield over/underflow when used in a constructor. During deserialization, too large or small integer numbers
will be automatically be stored as [`number_unsigned_t`](number_unsigned_t.md) or [`number_float_t`](number_float_t.md).

[RFC 8259](https://tools.ietf.org/html/rfc8259) further states:
> Note that when such software is used, numbers that are integers and are in the range $[-2^{53}+1, 2^{53}-1]$ are
> interoperable in the sense that implementations will agree exactly on their numeric values.

As this range is a subrange of the exactly supported range [INT64_MIN, INT64_MAX], this class's integer type is
interoperable.

#### Storage

Integer number values are stored directly inside a `basic_json` type.

## Examples

??? example

    The following code shows that `number_integer_t` is by default, a typedef to `#!cpp std::int64_t`.
     
    ```cpp
    --8<-- "examples/number_integer_t.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/number_integer_t.output"
    ```

## Version history

- Added in version 1.0.0.
