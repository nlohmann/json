#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

std::string buffer;

// call for every chunk; returns true and sets `value` once the buffer holds one complete JSON value
bool push(const std::string& chunk, json& value)
{
    buffer += chunk;
    try
    {
        value = json::parse(buffer);
        buffer.clear();
        return true;
    }
    catch (const json::parse_error& e)
    {
        if (e.byte == buffer.size() + 1)
        {
            return false; // the input ends prematurely: wait for more data
        }
        throw; // a real syntax error
    }
}

int main()
{
    json value;
    for (const std::string chunk : {"{\"na", "me\": \"Ma", "ry\", \"l", "ist\": [1, 2", ", 3]}"})
    {
        std::cout << "chunk " << chunk << " -> " << (push(chunk, value) ? "complete" : "incomplete") << '\n';
    }
    std::cout << value << '\n';

    // a syntax error in the middle is not mistaken for missing data
    try
    {
        push("[1, ]", value);
    }
    catch (const json::parse_error& e)
    {
        std::cout << e.what() << '\n';
    }
}
