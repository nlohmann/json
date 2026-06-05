#include <iostream>

#define JSON_DIAGNOSTIC_POSITIONS 1
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    std::string json_string = R"(
    {
        "address": {
            "street": "Fake Street",
            "housenumber": 1
        }
    }
    )";
    json j = json::parse(json_string);

    std::cout << "Root diagnostic positions: \n";
    std::cout << "\tstart_pos: " << j.start_pos() << '\n';
    std::cout << "\tend_pos:" << j.end_pos() << "\n";
    std::cout << "Original string: \n";
    std::cout << "{\n        \"address\": {\n            \"street\": \"Fake Street\",\n            \"housenumber\": 1\n        }\n    }" << "\n";
    std::cout << "Parsed string: \n";
    std::cout << json_string.substr(j.start_pos(), j.end_pos() - j.start_pos()) << "\n\n";

    std::cout << "address diagnostic positions: \n";
    std::cout << "\tstart_pos:" << j["address"].start_pos() << '\n';
    std::cout << "\tend_pos:" << j["address"].end_pos() << "\n\n";
    std::cout << "Original string: \n";
    std::cout << "{            \"street\": \"Fake Street\",\n            \"housenumber\": 1\n        }" << "\n";
    std::cout << "Parsed string: \n";
    std::cout << json_string.substr(j["address"].start_pos(), j["address"].end_pos() - j["address"].start_pos()) << "\n\n";

    std::cout << "street diagnostic positions: \n";
    std::cout << "\tstart_pos:" << j["address"]["street"].start_pos() << '\n';
    std::cout << "\tend_pos:" << j["address"]["street"].end_pos() << "\n\n";
    std::cout << "Original string: \n";
    std::cout << "\"Fake Street\"" << "\n";
    std::cout << "Parsed string: \n";
    std::cout << json_string.substr(j["address"]["street"].start_pos(), j["address"]["street"].end_pos() - j["address"]["street"].start_pos()) << "\n\n";

    std::cout << "housenumber diagnostic positions: \n";
    std::cout << "\tstart_pos:" << j["address"]["housenumber"].start_pos() << '\n';
    std::cout << "\tend_pos:" << j["address"]["housenumber"].end_pos() << "\n\n";
    std::cout << "Original string: \n";
    std::cout << "1" << "\n";
    std::cout << "Parsed string: \n";
    std::cout << json_string.substr(j["address"]["housenumber"].start_pos(), j["address"]["housenumber"].end_pos() - j["address"]["housenumber"].start_pos()) << "\n\n";
}
