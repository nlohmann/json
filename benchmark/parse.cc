#include "json.h"

int main()
{
    nlohmann::json j;
    j << std::cin;
    return 0;
}
