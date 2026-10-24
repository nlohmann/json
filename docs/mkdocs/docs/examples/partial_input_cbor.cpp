#include <iostream>
#include <sstream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // a CBOR value followed by other data
    const std::vector<std::uint8_t> cbor = json::to_cbor(json{1, 2, 3});
    std::string data(cbor.begin(), cbor.end());
    data += "TRAILING";

    std::istringstream input(data);
    json j = json::from_cbor(input, false); // strict = false: stop after the first value

    std::cout << "value: " << j << '\n';
    std::cout << "bytes used: " << input.tellg() << '\n';

    std::string rest;
    input >> rest;
    std::cout << "remaining input: " << rest << '\n';
}
