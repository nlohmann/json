#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // an empty binary value is encoded differently by the two drafts:
    // draft2 omits the optimized type marker for an empty byte array,
    // while draft3 always writes it
    json j = json::binary({});

    // encode using BJData draft2 (the default)
    auto v_draft2 = json::to_bjdata(j, true, true, json::bjdata_version_t::draft2);

    // encode using BJData draft3
    auto v_draft3 = json::to_bjdata(j, true, true, json::bjdata_version_t::draft3);

    std::cout << "draft2 size: " << v_draft2.size() << '\n'
              << "draft3 size: " << v_draft3.size() << std::endl;
}
