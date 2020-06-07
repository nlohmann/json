# Frequently Asked Questions (FAQ)

## Limitations

### Comments

!!! question "Questions"

	- Why does the library not support comments?
	- Can you add support for JSON5/JSONC/HOCON so that comments are supported?

This library does not support comments. It does so for three reasons:

1. Comments are not part of the [JSON specification](https://tools.ietf.org/html/rfc8259). You may argue that `//` or `/* */` are allowed in JavaScript, but JSON is not JavaScript.
2. This was not an oversight: Douglas Crockford [wrote on this](https://plus.google.com/118095276221607585885/posts/RK8qyGVaGSr) in May 2012:

	> 	I removed comments from JSON because I saw people were using them to hold parsing directives, a practice which would have destroyed interoperability.  I know that the lack of comments makes some people sad, but it shouldn't. 

	> 	Suppose you are using JSON to keep configuration files, which you would like to annotate. Go ahead and insert all the comments you like. Then pipe it through JSMin before handing it to your JSON parser.

3. It is dangerous for interoperability if some libraries would add comment support while others don't. Please check [The Harmful Consequences of the Robustness Principle](https://tools.ietf.org/html/draft-iab-protocol-maintenance-01) on this.

This library will not support comments in the future. If you wish to use comments, I see three options:

1. Strip comments before using this library.
2. Use a different JSON library with comment support.
3. Use a format that natively supports comments (e.g., YAML or JSON5).


### Relaxed parsing

!!! question

	- Can you add an option to ignore trailing commas?

For the same reason this library does not support [comments](#comments), this library also does not support any feature which would jeopardize interoperability.


### Parse errors reading non-ASCII characters

!!! question "Questions"

	- Why is the parser complaining about a Chinese character?
	- Does the library support Unicode?
	- I get an exception `[json.exception.parse_error.101] parse error at line 1, column 53: syntax error while parsing value - invalid string: ill-formed UTF-8 byte; last read: '"Testé$')"`

The library supports **Unicode input** as follows:

- Only **UTF-8** encoded input is supported which is the default encoding for JSON according to [RFC 8259](https://tools.ietf.org/html/rfc8259.html#section-8.1).
- `std::u16string` and `std::u32string` can be parsed, assuming UTF-16 and UTF-32 encoding, respectively. These encodings are not supported when reading from files or other input containers.
- Other encodings such as Latin-1 or ISO 8859-1 are **not** supported and will yield parse or serialization errors.
- [Unicode noncharacters](http://www.unicode.org/faq/private_use.html#nonchar1) will not be replaced by the library.
- Invalid surrogates (e.g., incomplete pairs such as `\uDEAD`) will yield parse errors.
- The strings stored in the library are UTF-8 encoded. When using the default string type (`std::string`), note that its length/size functions return the number of stored bytes rather than the number of characters or glyphs.
- When you store strings with different encodings in the library, calling [`dump()`](https://nlohmann.github.io/json/classnlohmann_1_1basic__json_a50ec80b02d0f3f51130d4abb5d1cfdc5.html#a50ec80b02d0f3f51130d4abb5d1cfdc5) may throw an exception unless `json::error_handler_t::replace` or `json::error_handler_t::ignore` are used as error handlers.

In most cases, the parser is right to complain, because the input is not UTF-8 encoded. This is especially true for Microsoft Windows where Latin-1 or ISO 8859-1 is often the standard encoding.


### Key name in exceptions

!!! question

	Can I get the key of the object item that caused an exception?

No, this is not possible. See <https://github.com/nlohmann/json/issues/932> for a longer discussion.


## Serialization issues


### Order of object keys

!!! question "Questions"

	- Why are object keys sorted?
	- Why is the insertion order of object keys not preserved?

By default, the library does not preserve the **insertion order of object elements**. This is standards-compliant, as the [JSON standard](https://tools.ietf.org/html/rfc8259.html) defines objects as "an unordered collection of zero or more name/value pairs".

If you do want to preserve the insertion order, you can specialize the object type with containers like [`tsl::ordered_map`](https://github.com/Tessil/ordered-map) ([integration](https://github.com/nlohmann/json/issues/546#issuecomment-304447518)) or [`nlohmann::fifo_map`](https://github.com/nlohmann/fifo_map) ([integration](https://github.com/nlohmann/json/issues/485#issuecomment-333652309)).


### Number precision

!!! question

	- It seems that precision is lost when serializing a double.
	- Can I change the precision for floating-point serialization?

The library uses `std::numeric_limits<number_float_t>::digits10` (15 for IEEE `double`s) digits for serialization. This value is sufficient to guarantee roundtripping. If one uses more than this number of digits of precision, then string -> value -> string is not guaranteed to round-trip.

!!! quote "[cppreference.com](https://en.cppreference.com/w/cpp/types/numeric_limits/digits10)"

	The value of `std::numeric_limits<T>::digits10` is the number of base-10 digits that can be represented by the type T without change, that is, any number with this many significant decimal digits can be converted to a value of type T and back to decimal form, without change due to rounding or overflow. 

!!! tip

	The website https://float.exposed gives a good insight into the internal storage of floating-point numbers.


## Compilation issues

### Android SDK

!!! question

	Why does the code not compile with Android SDK?

Android defaults to using very old compilers and C++ libraries. To fix this, add the following to your `Application.mk`. This will switch to the LLVM C++ library, the Clang compiler, and enable C++11 and other features disabled by default.

```ini
APP_STL := c++_shared
NDK_TOOLCHAIN_VERSION := clang3.6
APP_CPPFLAGS += -frtti -fexceptions
```

The code compiles successfully with [Android NDK](https://developer.android.com/ndk/index.html?hl=ml), Revision 9 - 11 (and possibly later) and [CrystaX's Android NDK](https://www.crystax.net/en/android/ndk) version 10.


### Missing STL function

!!! question "Questions"

	- Why do I get a compilation error `'to_string' is not a member of 'std'` (or similarly, for `strtod` or `strtof`)?
	- Why does the code not compile with MinGW or Android SDK?

This is not an issue with the code,  but rather with the compiler itself. On Android, see above to build with a newer environment.  For MinGW, please refer to [this site](http://tehsausage.com/mingw-to-string) and [this discussion](https://github.com/nlohmann/json/issues/136) for information on how to fix this bug. For Android NDK using `APP_STL := gnustl_static`, please refer to [this discussion](https://github.com/nlohmann/json/issues/219).
