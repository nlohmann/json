#include <json.hpp>
#include <fstream>
#include <iostream>

using json = nlohmann::json;

int main()
{
    std::vector<std::string> files = {
        "files/jeopardy/jeopardy.json",
        "files/nativejson-benchmark/canada.json",
        "files/nativejson-benchmark/citm_catalog.json",
        "files/nativejson-benchmark/twitter.json",
        "files/numbers/floats.json",
        "files/numbers/signed_ints.json",
        "files/numbers/unsigned_ints.json"
    };

    for (const auto& file: files)
    {
        std::ifstream f(file);
        json j = json::parse(f);
        auto v_cbor = json::to_cbor(j);
        auto v_msgpack = json::to_msgpack(j);
        auto v_ubjson = json::to_ubjson(j, true, true);

        double baseline = j.dump().size();

        std::cout << file << ", JSON:               " << j.dump(2).size() << " " << j.dump(2).size()/baseline << std::endl;
        std::cout << file << ", JSON (minified):    " << j.dump().size() << std::endl;
        std::cout << file << ", CBOR:               " << v_cbor.size() << " " << v_cbor.size()/baseline << std::endl;
        std::cout << file << ", MessagePack:        " << v_msgpack.size() << " " << v_msgpack.size()/baseline << std::endl;
        std::cout << file << ", UBJSON (optimized): " << v_ubjson.size() << " " << v_ubjson.size()/baseline << std::endl;
    }
}
