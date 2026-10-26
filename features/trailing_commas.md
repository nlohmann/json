# Trailing Commas

Like [comments](comments.md), this library does not support trailing commas in arrays and objects *by default*.

You can set parameter `ignore_trailing_commas` to `#!cpp true` in the [`parse`](../api/basic_json/parse.md) function to allow trailing commas in arrays and objects. Note that a single comma as the only content of the array or object (`[,]` or `{,}`) is not allowed, and multiple trailing commas (`[1,,]`) are not allowed either.

This library does not add trailing commas when serializing JSON data.

For more information, see [JSON With Commas and Comments (JWCC)](https://nigeltao.github.io/blog/2021/json-with-commas-comments.html).

!!! example

    Consider the following JSON with trailing commas.

    ```json
    {
        "planets": [
            "Mercury",
            "Venus",
            "Earth",
            "Mars",
            "Jupiter",
            "Uranus",
            "Neptune",
        ]
    }
    ```
    
    When calling `parse` without additional argument, a parse error exception is thrown. If `ignore_trailing_commas` is set to `#!cpp true`, the trailing commas are ignored during parsing:

    ```cpp
    #include <iostream>
    #include <nlohmann/json.hpp>
    
    using nlohmann::json;
    
    int main()
    {
        std::string s = R"(
        {
            "planets": [
                "Mercury",
                "Venus",
                "Earth",
                "Mars",
                "Jupiter",
                "Uranus",
                "Neptune",
            ]
        }
        )";
    
        try
        {
            json j = json::parse(s);
        }
        catch (json::exception& e)
        {
            std::cout << e.what() << '\n';
        }
    
        json j = json::parse(s,
                             /* callback */ nullptr,
                             /* allow exceptions */ true,
                             /* ignore_comments */ false,
                             /* ignore_trailing_commas */ true);
        std::cout << j.dump(2) << '\n';
    }
    
    ```

    Output:
    
    ```
    [json.exception.parse_error.101] parse error at line 11, column 9: syntax error while parsing value - unexpected ']'; expected '[', '{', or a literal
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
