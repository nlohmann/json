#include <json.hpp>

using json = nlohmann::json;

int main()
{
    // create values of different integer types
    short n42 = 42;
    int n23 = 23;
    long n1024 = 1024;
    int_least32_t n17 = 17;
    uint8_t n8 = 8;

    // create JSON numbers
    json j42(n42);
    json j23(n23);
    json j1024(n1024);
    json j17(n17);
    json j8(n8);

    // serialize the JSON numbers
    std::cout << j42 << '\n';
    std::cout << j23 << '\n';
    std::cout << j1024 << '\n';
    std::cout << j17 << '\n';
    std::cout << j8 << '\n';
}
