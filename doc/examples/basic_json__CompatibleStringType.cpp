#include <json.hpp>

using json = nlohmann::json;

int main()
{
    // create a string value
    std::string s = "The quick brown fox jumps over the lazy dog.";

    // create a JSON string value
    json j = s;

    // serialize the JSON string
    std::cout << j << '\n';
}
