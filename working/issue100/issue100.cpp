#include "../../src/json.hpp"
using nlohmann::json;
#include <iostream>
using namespace std;

int main()
{
    json config = {
        { "111", 111 },
        { "112", 112 },
        { "113", 113 }
    };

    cout << config << endl;
    for (auto it = config.begin(); it != config.end(); ++it)
    {
        cout << it.key() << ": " << it.value() << endl;
    }

    for (auto it = config.rbegin(); it != config.rend(); ++it)
    {
        cout << it.key() << ": " << it.value() << endl;
    }

    return 0;
}
