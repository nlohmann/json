#include <iostream>
#include <vector>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;

int main()
{
    std::cout << std::boolalpha;

    // a JSON value embedded in a larger, non-null-terminated buffer (e.g. a
    // slice received over the network)
    std::vector<char> buffer = {'[', '1', ',', '2', ']', 'j', 'u', 'n', 'k'};

    // a pointer pair is BORROWED, exactly like a byte container lvalue: the
    // document points into the buffer. (From C++20 on, std::vector<char>
    // iterators are borrowed as well; before, they are copied.)
    const char* first = buffer.data();
    json_document doc = json_document::parse(first, first + 5);
    std::cout << doc.root().is_array() << ' ' << doc.root().size() << '\n';
    std::cout << doc.owns_source() << '\n'; // false: borrowed
}
