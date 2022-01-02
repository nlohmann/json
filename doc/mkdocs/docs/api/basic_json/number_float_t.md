# <small>nlohmann::basic_json::</small>number_float_t

```cpp
using number_float_t = NumberFloatType;
```

The type used to store JSON numbers (floating-point).

[RFC 8259](https://tools.ietf.org/html/rfc8259) describes numbers as follows:
> The representation of numbers is similar to that used in most programming languages. A number is represented in base
> 10 using decimal digits. It contains an integer component that may be prefixed with an optional minus sign, which may
> be followed by a fraction part and/or an exponent part. Leading zeros are not allowed. (...) Numeric values that
> cannot be represented in the grammar below (such as Infinity and NaN) are not permitted.

This description includes both integer and floating-point numbers. However, C++ allows more precise storage if it is
known whether the number is a signed integer, an unsigned integer or a floating-point number. Therefore, three different
types, [`number_integer_t`](number_integer_t.md), [`number_unsigned_t`](number_unsigned_t.md) and `number_float_t` are
used.

To store floating-point numbers in C++, a type is defined by the template parameter `NumberFloatType` which chooses the
type to use.

## Notes

#### Default type

With the default values for `NumberFloatType` (`double`), the default value for `number_float_t` is `#!cpp double`.

#### Default behavior

- The restrictions about leading zeros is not enforced in C++. Instead, leading zeros in floating-point literals will be
  ignored. Internally, the value will be stored as decimal number. For instance, the C++ floating-point literal `01.2`
  will be serialized to `1.2`. During deserialization, leading zeros yield an error.
- Not-a-number (NaN) values will be serialized to `null`.

#### Limits

[RFC 8259](https://tools.ietf.org/html/rfc8259) states:
> This specification allows implementations to set limits on the range and precision of numbers accepted. Since software
> that implements IEEE 754-2008 binary64 (double precision) numbers is generally available and widely used, good
> interoperability can be achieved by implementations that expect no more precision or range than these provide, in the
> sense that implementations will approximate JSON numbers within the expected precision.

This implementation does exactly follow this approach, as it uses double precision floating-point numbers. Note values
smaller than `-1.79769313486232e+308` and values greater than `1.79769313486232e+308` will be stored as NaN internally
and be serialized to `null`.

#### Storage

Floating-point number values are stored directly inside a `basic_json` type.

## Examples

??? example

    The following code shows that `number_float_t` is by default, a typedef to `#!cpp double`.
     
    ```cpp
    --8<-- "examples/number_float_t.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/number_float_t.output"
    ```

## Version history

- Added in version 1.0.0.
