#include <json.hpp>

using namespace nlohmann;

int main()
{
    // create a JSON object
    const json object =
    {
        {"one", 1}, {"two", 2}, {"three", 2.9}
    };

    // output element with key "two"
    std::cout << object["two"] << '\n';
}
