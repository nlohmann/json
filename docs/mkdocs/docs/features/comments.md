# Comments

This library does not support comments *by default*. It does so for three reasons:

1. Comments are not part of the [JSON specification](https://tools.ietf.org/html/rfc8259). You may argue that `//` or `/* */` are allowed in JavaScript, but JSON is not JavaScript.
2. This was not an oversight: Douglas Crockford [wrote on this](https://plus.google.com/118095276221607585885/posts/RK8qyGVaGSr) in May 2012:

    > I removed comments from JSON because I saw people were using them to hold parsing directives, a practice which would have destroyed interoperability.  I know that the lack of comments makes some people sad, but it shouldn't. 

    > Suppose you are using JSON to keep configuration files, which you would like to annotate. Go ahead and insert all the comments you like. Then pipe it through JSMin before handing it to your JSON parser.

3. It is dangerous for interoperability if some libraries add comment support while others do not. Please check [The Harmful Consequences of the Robustness Principle](https://tools.ietf.org/html/draft-iab-protocol-maintenance-01) on this.

However, you can set parameter `ignore_comments` to `#!cpp true` in the [`parse`](../api/basic_json/parse.md) function to ignore `//` or `/* */` comments. Comments will then be treated as whitespace.

For more information, see [JSON With Commas and Comments (JWCC)](https://nigeltao.github.io/blog/2021/json-with-commas-comments.html).

!!! example

    Consider the following JSON with comments.

    ```json
    {
        // update in 2006: removed Pluto
        "planets": ["Mercury", "Venus", "Earth", "Mars",
                    "Jupiter", "Uranus", "Neptune" /*, "Pluto" */]
    }
    ```
    
    When calling `parse` without additional argument, a parse error exception is thrown. If `ignore_comments` is set to `#! true`, the comments are ignored during parsing:

    ```cpp
    --8<-- "examples/comments.cpp"
    ```

    Output:
    
    ```
    --8<-- "examples/comments.output"
    ```
