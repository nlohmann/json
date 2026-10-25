#include <cstdint>
#include <iostream>
#include <vector>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// None of the calls below throws, so this example also works with -fno-exceptions.
int main()
{
    const std::string invalid = R"({"name": "Mary", "age": )";

    // parse() with allow_exceptions = false returns a discarded value
    json j = json::parse(invalid, nullptr, false);
    std::cout << std::boolalpha << "parse: discarded = " << j.is_discarded() << '\n';

    // accept() only tells whether the input is valid JSON
    std::cout << "accept: " << json::accept(invalid) << '\n';

    // the binary formats have the same parameter
    const std::vector<std::uint8_t> truncated_cbor = {0x83, 0x01};
    json c = json::from_cbor(truncated_cbor, true, false);
    std::cout << "from_cbor: discarded = " << c.is_discarded() << '\n';

    // valid input is parsed as usual
    json valid = json::parse(R"({"name": "Mary"})", nullptr, false);
    std::cout << "valid input: " << valid << '\n';
}
