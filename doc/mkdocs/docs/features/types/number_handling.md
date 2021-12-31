# Number Handling

This document describes how the library is handling numbers.

## Background

This section briefly summarizes how the JSON specification describes how numbers should be handled.

### JSON number syntax

JSON defines the syntax of numbers as follows:

!!! quote "[RFC 8259](https://tools.ietf.org/html/rfc8259#section-6), Section 6"

    The representation of numbers is similar to that used in most
    programming languages.  A number is represented in base 10 using
    decimal digits.  It contains an integer component that may be
    prefixed with an optional minus sign, which may be followed by a
    fraction part and/or an exponent part.  Leading zeros are not
    allowed.

    A fraction part is a decimal point followed by one or more digits.
    
    An exponent part begins with the letter E in uppercase or lowercase,
    which may be followed by a plus or minus sign.  The E and optional
    sign are followed by one or more digits.

The following railroad diagram from [json.org](https://json.org) visualizes the number syntax:

![Syntax for JSON numbers](../../images/json_syntax_number.png)

### Number interoperability

On number interoperability, the following remarks are made:

!!! quote "[RFC 8259](https://tools.ietf.org/html/rfc8259#section-6), Section 6"

    This specification allows implementations to set limits on the range
    and precision of numbers accepted.  Since software that implements
    IEEE 754 binary64 (double precision) numbers [IEEE754] is generally
    available and widely used, good interoperability can be achieved by
    implementations that expect no more precision or range than these
    provide, in the sense that implementations will approximate JSON
    numbers within the expected precision.  A JSON number such as 1E400
    or 3.141592653589793238462643383279 may indicate potential
    interoperability problems, since it suggests that the software that
    created it expects receiving software to have greater capabilities
    for numeric magnitude and precision than is widely available.
    
    Note that when such software is used, numbers that are integers and
    are in the range $[-2^{53}+1, 2^{53}-1]$ are interoperable in the
    sense that implementations will agree exactly on their numeric
    values.

## Library implementation

This section describes how the above number specification is implemented by this library.

### Number storage

In the default [`json`](../../api/json.md) type, numbers are stored as `#!c std::uint64_t`, `#!c std::int64_t`, and
`#!c double`,  respectively. Thereby, `#!c std::uint64_t` and `#!c std::int64_t` are used only if they can store the 
number without loss of  precision. If this is impossible (e.g., if the number is too large), the number is stored as
`#!c double`.

!!! info "Notes"

    - Numbers with a decimal digit or scientific notation are always stored as `#!c double`.
    - The number types can be changed, see [Template number types](#template-number-types). 
    - As of version 3.9.1, the conversion is realized by
      [`std::strtoull`](https://en.cppreference.com/w/cpp/string/byte/strtoul),
      [`std::strtoll`](https://en.cppreference.com/w/cpp/string/byte/strtol), and
      [`std::strtod`](https://en.cppreference.com/w/cpp/string/byte/strtof), respectively.

!!! example "Examples"

    - Integer `#!c -12345678912345789123456789` is smaller than `#!c INT64_MIN` and will be stored as floating-point
      number `#!c -1.2345678912345788e+25`.
    - Integer `#!c 1E3` will be stored as floating-point number `#!c 1000.0`.

### Number limits

- Any 64-bit signed or unsigned integer can be stored without loss of precision.
- Numbers exceeding the limits of `#!c double` (i.e., numbers that after conversion via
[`std::strtod`](https://en.cppreference.com/w/cpp/string/byte/strtof) are not satisfying
[`std::isfinite`](https://en.cppreference.com/w/cpp/numeric/math/isfinite) such as `#!c 1E400`) will throw exception
[`json.exception.out_of_range.406`](../../home/exceptions.md#jsonexceptionout_of_range406) during parsing.
- Floating-point numbers are rounded to the next number representable as `double`. For instance
`#!c 3.141592653589793238462643383279` is stored as [`0x400921fb54442d18`](https://float.exposed/0x400921fb54442d18).
This is the same behavior as the code `#!c double x = 3.141592653589793238462643383279;`.

!!! success "Interoperability"

    - The library interoperable with respect to the specification, because its supported range $[-2^{63}, 2^{64}-1]$ is
      larger than the described range $[-2^{53}+1, 2^{53}-1]$.
    - All integers outside the range $[-2^{63}, 2^{64}-1]$, as well as floating-point numbers are stored as `double`.
      This also concurs with the specification above.

### Zeros

The JSON number grammar allows for different ways to express zero, and this library will store zeros differently:

| Literal | Stored value and type  | Serialization |
|---------|------------------------|---------------|
| `0`     | `#!c std::uint64_t(0)` | `0`           |
| `-0`    | `#!c std::int64_t(0)`  | `0`           |
| `0.0`   | `#!c double(0.0)`      | `0.0`         |
| `-0.0`  | `#!c double(-0.0)`     | `-0.0`        |
| `0E0`   | `#!c double(0.0)`      | `0.0`         |
| `-0E0`  | `#!c double(-0.0)`     | `-0.0`        |

That is, `-0` is stored as a signed integer, but the serialization does not reproduce the `-`.

### Number serialization

- Integer numbers are serialized as is; that is, no scientific notation is used.
- Floating-point numbers are serialized as specified by the `#!c %g` printf modifier with 
  [`std::numeric_limits<double>::max_digits10`](https://en.cppreference.com/w/cpp/types/numeric_limits/max_digits10)
  significant digits. The rationale is to use the shortest representation while still allow round-tripping.

!!! hint "Notes regarding precision of floating-point numbers"

    As described above, floating-point numbers are rounded to the nearest double and serialized with the shortest
    representation to allow round-tripping. This can yield confusing examples:

    - The serialization can have fewer decimal places than the input: `#!c 2555.5599999999999` will be serialized as
      `#!c 2555.56`. The reverse can also be true.
    - The serialization can be in scientific notation even if the input is not: `#!c 0.0000972439793401814` will be 
      serialized as `#!c 9.72439793401814e-05`. The reverse can also be true: `#!c 12345E-5` will be serialized as
      `#!c 0.12345`.
    - Conversions from `#!c float` to `#!c double` can also introduce rounding errors:
        ```cpp
        float f = 0.3;
        json j = f;
        std::cout << j << '\n';
        ```
        yields `#!c 0.30000001192092896`.

    All examples here can be reproduced by passing the original double value to

    ```cpp
    std::printf("%.*g\n", std::numeric_limits<double>::max_digits10, double_value);
    ```

#### NaN handling

NaN (not-a-number) cannot be expressed with the number syntax described above and are in fact explicitly excluded:

!!! quote "[RFC 8259](https://tools.ietf.org/html/rfc8259#section-6), Section 6"

    Numeric values that cannot be represented in the grammar below (such
    as Infinity and NaN) are not permitted.

That is, there is no way to *parse* a NaN value. However, NaN values can be stored in a JSON value by assignment.

This library serializes NaN values  as `#!js null`. This corresponds to the behavior of JavaScript's
[`JSON.stringify`](https://www.w3schools.com/js/js_json_stringify.asp) function.

!!! example

    The following example shows how a NaN value is stored in a `json` value.

    ```cpp
    int main()
    {
        double val = std::numeric_limits<double>::quiet_NaN();
        std::cout << "val=" << val << std::endl;
        json j = val;
        std::cout << "j=" << j.dump() << std::endl;
        val = j;
        std::cout << "val=" << val << std::endl;
    }
    ```
    
    output:
    
    ```
    val=nan
    j=null
    val=nan
    ```

### Number comparison

Floating-point inside JSON values numbers are compared with `#!c json::number_float_t::operator==` which is
`#!c double::operator==` by default.

!!! example "Alternative comparison functions"

    To compare floating-point while respecting an epsilon, an alternative
    [comparison function](https://github.com/mariokonrad/marnav/blob/master/include/marnav/math/floatingpoint.hpp#L34-#L39)
    could be used, for instance
    
    ```cpp
    template<typename T, typename = typename std::enable_if<std::is_floating_point<T>::value, T>::type>
    inline bool is_same(T a, T b, T epsilon = std::numeric_limits<T>::epsilon()) noexcept
    {
        return std::abs(a - b) <= epsilon;
    }
    ```
    Or you can self-define an operator equal function like this:
    
    ```cpp
    bool my_equal(const_reference lhs, const_reference rhs)
    {
        const auto lhs_type lhs.type();
        const auto rhs_type rhs.type();
        if (lhs_type == rhs_type)
        {
            switch(lhs_type)
            {
                // self_defined case
                case value_t::number_float:
                    return std::abs(lhs - rhs) <= std::numeric_limits<float>::epsilon();
        
                // other cases remain the same with the original
                ...
            }
        }
        ...
    }
    ```
    
    (see [#703](https://github.com/nlohmann/json/issues/703) for more information.)
    
!!! note

    NaN values never compare equal to themselves or to other NaN values. See [#514](https://github.com/nlohmann/json/issues/514).

### Number conversion

Just like the C++ language itself, the `get` family of functions allows conversions between unsigned and signed
integers, and  between integers and floating-point values to integers. This behavior may be surprising.

!!! warning "Unconditional number conversions"

    ```cpp hl_lines="3"
    double d = 42.3;                          // non-integer double value 42.3
    json jd = d;                              // stores double value 42.3
    std::int64_t i = jd.get<std::int64_t>();  // now i==42; no warning or error is produced
    ```

    Note the last line with throw a [`json.exception.type_error.302`](../../home/exceptions.md#jsonexceptiontype_error302)
    exception if `jd` is not a numerical type, for instance a string.

The rationale is twofold:

1. JSON does not define a number type or precision (see [#json-specification](above)).
2. C++ also allows to silently convert between number types.

!!! success "Conditional number conversion"

    The code above can be solved by explicitly checking the nature of the value with members such as
    [`is_number_integer()`](../../api/basic_json/is_number_integer.md) or
    [`is_number_unsigned()`](../../api/basic_json/is_number_unsigned.md):

    ```cpp hl_lines="2"
    // check if jd is really integer-valued
    if (jd.is_number_integer())
    {
        // if so, do the conversion and use i
        std::int64_t i = jd.get<std::int64_t>();
        // ...
    }
    else
    {
        // otherwise, take appropriate action
        // ...
    }
    ```

    Note this approach also has the advantage that it can react on non-numerical JSON value types such as strings.

    (Example taken from [#777](https://github.com/nlohmann/json/issues/777#issuecomment-459968458).)

### Determine number types

As the example in [Number conversion](#number_conversion) shows, there are different functions to determine the type of
the stored number:

- [`is_number()`](../../api/basic_json/is_number.md) returns `#!c true` for any number type
- [`is_number_integer()`](../../api/basic_json/is_number_integer.md) returns `#!c true` for signed and unsigned integers
- [`is_number_unsigned()`](../../api/basic_json/is_number_unsigned.md) returns `#!c true` for unsigned integers only
- [`is_number_float()`](../../api/basic_json/is_number_float.md) returns `#!c true` for floating-point numbers
- [`type_name()`](../../api/basic_json/type_name.md) returns `#!c "number"` for any number type
- [`type()`](../../api/basic_json/type.md) returns a different enumerator of
  [`value_t`](../../api/basic_json/value_t.md) for all number types

| function                                                             | unsigned integer  | signed integer   | floating-point | string         |
|----------------------------------------------------------------------|-------------------|------------------|----------------|----------------|
| [`is_number()`](../../api/basic_json/is_number.md)                   | `#!c true`        | `#!c true`       | `#!c true`     | `#!c false`    |
| [`is_number_integer()`](../../api/basic_json/is_number_integer.md)   | `#!c true`        | `#!c true`       | `#!c false`    | `#!c false`    |
| [`is_number_unsigned()`](../../api/basic_json/is_number_unsigned.md) | `#!c true`        | `#!c false`      | `#!c false`    | `#!c false`    |
| [`is_number_float()`](../../api/basic_json/is_number_float.md)       | `#!c false`       | `#!c false`      | `#!c true`     | `#!c false`    |
| [`type_name()`](../../api/basic_json/type_name.md)                   | `#!c "number"`    | `#!c "number"`   | `#!c "number"` | `#!c "string"` |
| [`type()`](../../api/basic_json/type.md)                             | `number_unsigned` | `number_integer` | `number_float` | `string`       |

### Template number types

The number types can be changed with template parameters.

| position | number type       | default type        | possible values                                |
|----------|-------------------|---------------------|------------------------------------------------|
| 5        | signed integers   | `#!c std::int64_t`  | `#!c std::int32_t`, `#!c std::int16_t`, etc.   |
| 6        | unsigned integers | `#!c std::uint64_t` | `#!c std::uint32_t`, `#!c std::uint16_t`, etc. |
| 7        | floating-point    | `#!c double`        | `#!c float`, `#!c long double`                 |

!!! info "Constraints on number types"

    - The type for signed integers must be convertible from `#!c long long`. The type for floating-point numbers is used
      in case of overflow.
    - The type for unsigned integers must be convertible from `#!c unsigned long long`.  The type for floating-point
      numbers is used in case of overflow.
    - The types for signed and unsigned integers must be distinct, see
      [#2573](https://github.com/nlohmann/json/issues/2573).
    - Only `#!c double`, `#!c float`, and `#!c long double` are supported for floating-point numbers.

!!! example

    A `basic_json` type that uses `#!c long double` as floating-point type.

    ```cpp hl_lines="2"
    using json_ld = nlohmann::basic_json<std::map, std::vector, std::string, bool,
                                         std::int64_t, std::uint64_t, long double>;
    ```

    Note values should then be parsed with `json_ld::parse` rather than `json::parse` as the latter would parse
    floating-point values to `#!c double` before then converting them to `#!c long double`.
