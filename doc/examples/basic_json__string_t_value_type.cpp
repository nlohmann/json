#include <json.hpp>

using namespace nlohmann;

int main()
{
    // create a JSON string directly from a string literal
    json j("The quick brown fox jumps over the lazy doc");

    // serialize the JSON array
    std::cout << j << '\n';
}
