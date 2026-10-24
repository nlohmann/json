#include <iostream>
#include <utility>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// line and column (both starting at 1) of a byte index in a text
std::pair<std::size_t, std::size_t> line_column(const std::string& input, std::size_t byte)
{
    std::size_t line = 1;
    std::size_t column = 1;
    for (std::size_t i = 0; i + 1 < byte && i < input.size(); ++i)
    {
        if (input[i] == '\n')
        {
            ++line;
            column = 1;
        }
        else
        {
            ++column;
        }
    }
    return {line, column};
}

int main()
{
    const std::string input = "{\n  \"a\": 1,\n  \"b\": ]\n}";

    try
    {
        const json j = json::parse(input);
        std::cout << j << '\n';
    }
    catch (const json::parse_error& e)
    {
        const auto position = line_column(input, e.byte);
        std::cout << e.what() << '\n';
        std::cout << "byte " << e.byte << " = line " << position.first << ", column " << position.second << '\n';
    }
}
