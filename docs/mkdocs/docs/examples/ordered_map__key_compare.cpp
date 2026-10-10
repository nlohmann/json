#include <iostream>
#include <nlohmann/json.hpp>

int main()
{
    using Map = nlohmann::ordered_map<std::string, int>;
    Map::key_compare compare{};

    std::cout << std::boolalpha
              << "compare(\"a\", \"a\") = " << compare("a", "a") << '\n'
              << "compare(\"a\", \"b\") = " << compare("a", "b") << std::endl;
}
