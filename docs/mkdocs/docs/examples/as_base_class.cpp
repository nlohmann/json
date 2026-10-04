#include <iostream>
#include <nlohmann/json.hpp>

class base_class_with_hidden_members
{
  public:
    const char* type_name() const noexcept
    {
        return "my_type_name";
    }

    std::size_t size() const noexcept
    {
        return 42;
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
             base_class_with_hidden_members
             >;

int main()
{
    json j = {1, 2, 3};

    // the members of basic_json hide the members of the base class
    std::cout << j.type_name() << ' ' << j.size() << '\n';

    // access the hidden members of the base class
    std::cout << j.as_base_class().type_name() << ' ' << j.as_base_class().size() << '\n';
}
