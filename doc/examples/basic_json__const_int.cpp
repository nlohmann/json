#include <json.hpp>

using namespace nlohmann;

int main()
{
    // an anonymous enum
    enum { t = 17 };

    // create a JSON number from the enum
    json j(t);

    // serialize the JSON numbers
    std::cout << j << '\n';
}
