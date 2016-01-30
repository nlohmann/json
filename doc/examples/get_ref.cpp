#include <json.hpp>

using json = nlohmann::json;

int main()
{
    // create a JSON number
    json value = 17;

    // explicitly getting references
    auto r1 = value.get_ref<const json::number_integer_t&>();
    auto r2 = value.get_ref<json::number_integer_t&>();

    // print the values
    std::cout << r1 << ' ' << r2 << '\n';

    // incompatible type throws exception
    try
    {
        auto r3 = value.get_ref<json::number_float_t&>();
    }
    catch (std::domain_error& ex)
    {
        std::cout << ex.what() << '\n';
    }
}
