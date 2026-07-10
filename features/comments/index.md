# Comments

This library does not support comments *by default*. It does so for three reasons:

1. Comments are not part of the [JSON specification](https://tools.ietf.org/html/rfc8259). You may argue that `//` or `/* */` are allowed in JavaScript, but JSON is not JavaScript.

1. This was not an oversight: Douglas Crockford [wrote on this](https://news.ycombinator.com/item?id=3912149) in May 2012:

   > I removed comments from JSON because I saw people were using them to hold parsing directives, a practice which would have destroyed interoperability. I know that the lack of comments makes some people sad, but it shouldn't.
   >
   > Suppose you are using JSON to keep configuration files, which you would like to annotate. Go ahead and insert all the comments you like. Then pipe it through JSMin before handing it to your JSON parser.

1. It is dangerous for interoperability if some libraries add comment support while others do not. Please check [The Harmful Consequences of the Robustness Principle](https://tools.ietf.org/html/draft-iab-protocol-maintenance-01) on this.

However, you can set parameter `ignore_comments` to `true` in the [`parse`](https://json.nlohmann.me/api/basic_json/parse/index.md) function to ignore `//` or `/* */` comments. Comments will then be treated as whitespace. Combined with `ignore_trailing_commas` (also a `parse` parameter), this covers what is commonly referred to as **JSONC** (JSON with Comments, as used e.g. by Visual Studio Code's `.jsonc` files) -- comments and trailing commas, nothing more. This is a different, smaller extension than [JSON5](https://json5.org), which additionally allows unquoted keys, single-quoted strings, and other syntax changes that this library does not support.

For more information, see [JSON With Commas and Comments (JWCC)](https://nigeltao.github.io/blog/2021/json-with-commas-comments.html).

Example

Consider the following JSON with comments.

```
{
    // update in 2006: removed Pluto
    "planets": ["Mercury", "Venus", "Earth", "Mars",
                "Jupiter", "Uranus", "Neptune" /*, "Pluto" */]
}
```

When calling `parse` without additional argument, a parse error exception is thrown. If `ignore_comments` is set to `true`, the comments are ignored during parsing:

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    std::string s = R"(
    {
        // update in 2006: removed Pluto
        "planets": ["Mercury", "Venus", "Earth", "Mars",
                    "Jupiter", "Uranus", "Neptune" /*, "Pluto" */]
    }
    )";

    try
    {
        json j = json::parse(s);
    }
    catch (json::exception& e)
    {
        std::cout << e.what() << std::endl;
    }

    json j = json::parse(s,
                         /* callback */ nullptr,
                         /* allow exceptions */ true,
                         /* ignore_comments */ true);
    std::cout << j.dump(2) << '\n';
}
```

Output:

```
[json.exception.parse_error.101] parse error at line 3, column 9: syntax error while parsing object key - invalid literal; last read: '<U+000A>    {<U+000A>        /'; expected string literal
{
  "planets": [
    "Mercury",
    "Venus",
    "Earth",
    "Mars",
    "Jupiter",
    "Uranus",
    "Neptune"
  ]
}
```
