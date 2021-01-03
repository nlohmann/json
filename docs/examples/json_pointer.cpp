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
