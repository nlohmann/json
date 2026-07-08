# nlohmann::json_pointer::json_pointer

```
explicit json_pointer(const string_t& s = "");
```

Create a JSON pointer according to the syntax described in [Section 3 of RFC6901](https://tools.ietf.org/html/rfc6901#section-3).

## Parameters

`s` (in) : string representing the JSON pointer; if omitted, the empty string is assumed which references the whole JSON value

## Exceptions

- Throws [parse_error.107](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error107) if the given JSON pointer `s` is nonempty and does not begin with a slash (`/`); see example below.
- Throws [parse_error.108](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error108) if a tilde (`~`) in the given JSON pointer `s` is not followed by `0` (representing `~`) or `1` (representing `/`); see example below.

## Examples

Example

The example shows the construction several valid JSON pointers as well as the exceptional behavior.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // correct JSON pointers
    json::json_pointer p1;
    json::json_pointer p2("");
    json::json_pointer p3("/");
    json::json_pointer p4("//");
    json::json_pointer p5("/foo/bar");
    json::json_pointer p6("/foo/bar/-");
    json::json_pointer p7("/foo/~0");
    json::json_pointer p8("/foo/~1");

    // error: JSON pointer does not begin with a slash
    try
    {
        json::json_pointer p9("foo");
    }
    catch (const json::parse_error& e)
    {
        std::cout << e.what() << '\n';
    }

    // error: JSON pointer uses escape symbol ~ not followed by 0 or 1
    try
    {
        json::json_pointer p10("/foo/~");
    }
    catch (const json::parse_error& e)
    {
        std::cout << e.what() << '\n';
    }

    // error: JSON pointer uses escape symbol ~ not followed by 0 or 1
    try
    {
        json::json_pointer p11("/foo/~3");
    }
    catch (const json::parse_error& e)
    {
        std::cout << e.what() << '\n';
    }
}
```

Output:

```
[json.exception.parse_error.107] parse error at byte 1: JSON pointer must be empty or begin with '/' - was: 'foo'
[json.exception.parse_error.108] parse error: escape character '~' must be followed with '0' or '1'
[json.exception.parse_error.108] parse error: escape character '~' must be followed with '0' or '1'
```

## Version history

- Added in version 2.0.0.
- Changed type of `s` to `string_t` in version 3.11.0.
