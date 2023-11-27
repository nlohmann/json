#include <iostream>
#include <nlohmann/json.hpp>

class base_class_with_shadowed_members
{
  public:

    int m_value = 43;

    const char* type_name() const noexcept
    {
        return "my_name";
    }
};

using json = nlohmann::basic_json <
             std::map,
             std::vector,
             std::string,
             bool,
             std::int64_t,
             std::uint64_t,
             double,
             std::allocator,
             nlohmann::adl_serializer,
             std::vector<std::uint8_t>,
             base_class_with_shadowed_members
             >;

int main()
{
    json j;

    //access the shadowing method
    std::cout << j.type_name() << "\n";

    //access the shadowed method and member variable
    std::cout << j.as_base_class().type_name() << "\n";
    std::cout << j.as_base_class().m_value << "\n";
}
