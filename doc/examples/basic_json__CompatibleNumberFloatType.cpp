#include <json.hpp>

using json = nlohmann::json;

int main()
{
    // create values of different floating-point types
    float f42 = 42.23;
    float f_nan = 1.0f / 0.0f;
    double f23 = 23.42;

    // create JSON numbers
    json j42(f42);
    json j_nan(f_nan);
    json j23(f23);

    // serialize the JSON numbers
    std::cout << j42 << '\n';
    std::cout << j_nan << '\n';
    std::cout << j23 << '\n';
}
