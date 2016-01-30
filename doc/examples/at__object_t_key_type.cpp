#include <json.hpp>

using json = nlohmann::json;

int main()
{
    // create JSON object
    json object =
    {
        {"the good", "il buono"},
        {"the bad", "il cativo"},
        {"the ugly", "il brutto"}
    };

    // output element with key "the ugly"
    std::cout << object.at("the ugly") << '\n';

    // change element with key "the bad"
    object.at("the bad") = "il cattivo";

    // output changed array
    std::cout << object << '\n';

    // try to write at a nonexisting key
    try
    {
        object.at("the fast") = "il rapido";
    }
    catch (std::out_of_range& e)
    {
        std::cout << "out of range: " << e.what() << '\n';
    }
}
