#include <iostream>
#include <nlohmann/json.hpp>

int main()
{
    nlohmann::ordered_map<std::string, int> m;
    m["one"] = 1;

    std::cout << std::boolalpha
              << "m.count(\"one\") = " << m.count("one") << '\n'
              << "m.count(\"two\") = " << m.count("two") << std::endl;
}
