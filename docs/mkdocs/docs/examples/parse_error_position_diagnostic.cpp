#define JSON_DIAGNOSTIC_POSITIONS 1
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
    const std::string input = "{\n  \"name\": \"Mary\",\n  \"age\": \"forty-two\"\n}";
    const json j = json::parse(input); // the input is valid JSON ...

    try
    {
        const int age = j["age"]; // ... but the value has the wrong type
        std::cout << age << '\n';
    }
    catch (const json::exception& e)
    {
        std::cout << e.what() << '\n';

        // start_pos() is a 0-based index into the input; the helper expects a 1-based byte index
        const auto position = line_column(input, j["age"].start_pos() + 1);
        std::cout << "the value starts at line " << position.first << ", column " << position.second << '\n';
    }
}
