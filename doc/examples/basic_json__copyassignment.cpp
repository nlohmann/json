#include <json.hpp>

using namespace nlohmann;

int main()
{
    // create JSON values
    json a = 23;
    json b = 42;

    // copy-assign a to b
    b = a;

    // serialize the JSON arrays
    std::cout << a << '\n';
    std::cout << b << '\n';
}
