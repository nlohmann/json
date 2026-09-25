#include <iostream>
#include <nlohmann/json.hpp>

int main()
{
    nlohmann::ordered_map<std::string, int> m;
    m["one"] = 1;
    m["two"] = 2;

    // access an existing element
    std::cout << "m.at(\"one\") = " << m.at("one") << std::endl;

    // modify through the reference returned by at()
    m.at("two") = 22;
    std::cout << "m.at(\"two\") = " << m.at("two") << std::endl;

    // accessing a missing key throws
    try
    {
        m.at("three");
    }
    catch (const std::out_of_range& e)
    {
        std::cout << "exception: " << e.what() << std::endl;
    }
}
