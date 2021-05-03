# basic_json::number_unsigned_t

```cpp
using number_unsigned_t = NumberUnsignedType;
```

The type used to store JSON numbers (unsigned).

[RFC 8259](https://tools.ietf.org/html/rfc8259) describes numbers as follows:
> The representation of numbers is similar to that used in most programming languages. A number is represented in base
> 10 using decimal digits. It contains an integer component that may be prefixed with an optional minus sign, which may
> be followed by a fraction part and/or an exponent part. Leading zeros are not allowed. (...) Numeric values that
> cannot be represented in the grammar below (such as Infinity and NaN) are not permitted.

This description includes both integer and floating-point numbers. However, C++ allows more precise storage if it is
known whether the number is a signed integer, an unsigned integer or a floating-point number. Therefore, three different
types, [`number_integer_t`](number_integer_t.md), `number_unsigned_t` and [`number_float_t`](number_float_t.md) are
used.

To store unsigned integer numbers in C++, a type is defined by the template parameter `NumberUnsignedType` which chooses
the type to use.

## Notes

#### Default type

With the default values for `NumberUnsignedType` (`std::uint64_t`), the default value for `number_unsigned_t` is
`#!cpp std::uint64_t`.

#### Default behavior

- The restrictions about leading zeros is not enforced in C++. Instead, leading zeros in integer literals lead to an
  interpretation as octal number. Internally, the value will be stored as decimal number. For instance, the C++ integer 
  literal `010` will be serialized to `8`. During deserialization, leading zeros yield an error.
- Not-a-number (NaN) values will be serialized to `null`.

#### Limits

[RFC 8259](https://tools.ietf.org/html/rfc8259) specifies:
> An implementation may set limits on the range and precision of numbers.

When the default type is used, the maximal integer number that can be stored is `18446744073709551615` (UINT64_MAX) and
the minimal integer number that can be stored is `0`. Integer numbers that are out of range will yield over/underflow
when used in a constructor. During deserialization, too large or small integer numbers will be automatically be stored
as [`number_integer_t`](number_integer_t.md) or [`number_float_t`](number_float_t.md).

[RFC 8259](https://tools.ietf.org/html/rfc8259) further states:
> Note that when such software is used, numbers that are integers and are in the range \f$[-2^{53}+1, 2^{53}-1]\f$ are
> interoperable in the sense that implementations will agree exactly on their numeric values.

As this range is a subrange (when considered in conjunction with the `number_integer_t` type) of the exactly supported
range [0, UINT64_MAX], this class's integer type is interoperable.

#### Storage

Integer number values are stored directly inside a `basic_json` type.

## Version history

- Added in version 2.0.0.
