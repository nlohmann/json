#include <iostream>
#include <sstream>
#include <string>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;

int main()
{
    std::cout << std::boolalpha;

    // build a large array (many nodes), then read a small one into the same
    // document: the index grown for the large input is still allocated
    std::ostringstream big;
    big << '[';
    for (int i = 0; i < 500; ++i)
    {
        if (i != 0)
        {
            big << ',';
        }
        big << i;
    }
    big << ']';

    json_document doc;
    doc.read(big.str());
    const std::size_t big_nodes = doc.node_count();

    doc.read(std::string("[1]"));
    std::cout << (doc.node_count() < big_nodes) << '\n'; // far fewer live nodes now
    const std::size_t before = doc.memory_usage();

    // shrink_to_fit() moves the index into a block sized for what is actually
    // used. This INVALIDATES every view taken from this document before the
    // call (they point into the old, now-freed block) -- take fresh ones from
    // root() afterward.
    doc.shrink_to_fit();
    const std::size_t after = doc.memory_usage();
    std::cout << (after <= before) << '\n';

    // a freshly taken view is valid and correct
    std::cout << doc.root().is_array() << ' ' << doc.root().size() << '\n';
}
