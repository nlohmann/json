#include <iostream>
#include <string>

#include <nlohmann/json.hpp>

int main()
{
    nlohmann::json j;
    j["pi"] = 3.141;
    j["happy"] = true;
    j["name"] = "Niels";
    j["nothing"] = nullptr;
    j["answer"]["everything"] = 42;
    j["list"] = {1, 0, 2};
    j["object"] = {{"currency", "USD"}, {"value", 42.99}};

    std::string s = j.dump();
    if (s != R"({"answer":{"everything":42},"happy":true,"list":[1,0,2],"name":"Niels","nothing":null,"object":{"currency":"USD","value":42.99},"pi":3.141})")
    {
        std::cerr << "Unexpected JSON serialization: " << s << std::endl;
        return 1;
    }
    return 0;
}
