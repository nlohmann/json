#include <iostream>
#include <nlohmann/json.hpp>

class visitor_adaptor_with_metadata
{
  public:
    template <class Fnc>
    void visit(const Fnc& fnc) const;

    int metadata = 42;
  private:
    template <class Ptr, class Fnc>
    void do_visit(const Ptr& ptr, const Fnc& fnc) const;
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
             visitor_adaptor_with_metadata
             >;

template <class Fnc>
void visitor_adaptor_with_metadata::visit(const Fnc& fnc) const
{
    do_visit(json::json_pointer{}, fnc);
}

template <class Ptr, class Fnc>
void visitor_adaptor_with_metadata::do_visit(const Ptr& ptr, const Fnc& fnc) const
{
    using value_t = nlohmann::detail::value_t;
    const json& j = *static_cast<const json*>(this);
    switch (j.type())
    {
        case value_t::object:
            fnc(ptr, j);
            for (const auto& entry : j.items())
            {
                entry.value().do_visit(ptr / entry.key(), fnc);
            }
            break;
        case value_t::array:
            fnc(ptr, j);
            for (std::size_t i = 0; i < j.size(); ++i)
            {
                j.at(i).do_visit(ptr / std::to_string(i), fnc);
            }
            break;
        case value_t::null:
        case value_t::string:
        case value_t::boolean:
        case value_t::number_integer:
        case value_t::number_unsigned:
        case value_t::number_float:
        case value_t::binary:
            fnc(ptr, j);
            break;
        case value_t::discarded:
        default:
            break;
    }
}

int main()
{
    // create a json object
    json j;
    j["null"];
    j["object"]["uint"] = 1U;
    j["object"].metadata = 21;

    // visit and output
    j.visit(
        [&](const json::json_pointer & p,
            const json & j)
    {
        std::cout << (p.empty() ? std::string{"/"} : p.to_string())
                  << " - metadata = " << j.metadata << " -> " << j.dump() << '\n';
    });
}
