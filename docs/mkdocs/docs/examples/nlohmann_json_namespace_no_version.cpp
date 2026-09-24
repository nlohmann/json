#include <iostream>

#define NLOHMANN_JSON_NAMESPACE_NO_VERSION 1
#include <nlohmann/json.hpp>

// macro needed to output the NLOHMANN_JSON_NAMESPACE as string literal
#define Q(x) #x
#define QUOTE(x) Q(x)

int main()
{
    std::cout << QUOTE(NLOHMANN_JSON_NAMESPACE) << std::endl;
}
