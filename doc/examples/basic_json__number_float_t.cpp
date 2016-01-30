#include <json.hpp>

using json = nlohmann::json;

int main()
{
    // create values of different floating-point types
    json::number_float_t v_ok = 3.141592653589793;
    json::number_float_t v_nan = NAN;
    json::number_float_t v_infinity = INFINITY;

    // create JSON numbers
    json j_ok(v_ok);
    json j_nan(v_nan);
    json j_infinity(v_infinity);

    // serialize the JSON numbers
    std::cout << j_ok << '\n';
    std::cout << j_nan << '\n';
    std::cout << j_infinity << '\n';
}
