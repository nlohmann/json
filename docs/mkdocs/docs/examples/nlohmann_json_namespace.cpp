#include <iostream>
#include <nlohmann/json.hpp>

// possible use case: use NLOHMANN_JSON_NAMESPACE instead of nlohmann
using json = NLOHMANN_JSON_NAMESPACE::json;

// macro needed to output the NLOHMANN_JSON_NAMESPACE as string literal
#define Q(x) #x
#define QUOTE(x) Q(x)

int main()
{
    std::cout << QUOTE(NLOHMANN_JSON_NAMESPACE) << std::endl;
}
