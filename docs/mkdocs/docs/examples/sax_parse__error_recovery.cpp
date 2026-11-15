#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// a SAX parser that creates a JSON value like json::parse does, but that
// recovers from parse errors instead of stopping at the first one
class recovering_parser : public nlohmann::detail::json_sax_dom_parser<json>
{
  public:
    explicit recovering_parser(json& result)
        : nlohmann::detail::json_sax_dom_parser<json>(result, false)
    {}

    bool parse_error(std::size_t position,
                     const std::string& /*last_token*/,
                     const json::exception& ex)
    {
        std::cout << "byte " << position << ": " << ex.what() << '\n';

        // repair the input and continue
        return true;
    }
};

int main()
{
    // JSON text with several mistakes that ends too early
    const std::string text = R"({
    "name": "Hello World",
    "tags": ["a" "b",],
    "valid": tru,
    "size": 1.,
    "nested": {"x": 1)";

    json result;
    recovering_parser sax(result);
    const bool valid = json::sax_parse(text, &sax);

    std::cout << "\nvalid JSON: " << std::boolalpha << valid << '\n'
              << std::setw(4) << result << std::endl;
}
