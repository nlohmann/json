#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// a DOM parser that reports parse errors instead of throwing
class sax_no_exception : public nlohmann::detail::json_sax_dom_parser<json, nlohmann::detail::string_input_adapter_type>
{
  public:
    explicit sax_no_exception(json& j)
        : nlohmann::detail::json_sax_dom_parser<json, nlohmann::detail::string_input_adapter_type>(j, false)
    {}

    bool parse_error(std::size_t position,
                     const std::string& last_token,
                     const json::exception& ex)
    {
        std::cout << "parse error at input byte " << position << "\n"
                  << ex.what() << "\n"
                  << "last read: \"" << last_token << "\""
                  << std::endl;
        return false;
    }
};

int main()
{
    std::string myinput = "[1,2,3,]";

    json result;
    sax_no_exception sax(result);

    bool parse_result = json::sax_parse(myinput, &sax);
    if (!parse_result)
    {
        std::cout << "parsing unsuccessful!" << std::endl;
    }

    std::cout << "parsed value: " << result << std::endl;
}
