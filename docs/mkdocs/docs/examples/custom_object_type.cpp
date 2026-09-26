#include <iostream>
#include <type_traits>
#include <vector>

#include <nlohmann/json.hpp>

#include "custom_object_type.hpp"

using custom_json = nlohmann::basic_json<custom_object_type, std::vector>;

int main()
{
    custom_json j;
    j["pi"] = 3.141;
    j["happy"] = true;
    j["list"] = {1, 2, 3};

    std::cout << j.dump(2) << std::endl;
    std::cout << std::boolalpha << (custom_json::parse(j.dump()) == j) << std::endl;

    // custom_object_type has no key_compare member, so object_comparator_t
    // falls back to its default
    std::cout << std::boolalpha
              << std::is_same<custom_json::object_comparator_t, custom_json::default_object_comparator_t>::value
              << std::endl;
}
