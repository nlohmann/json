#include <iostream>
#include <string>
#include <nlohmann/json.hpp>

using nlohmann::json;

int main()
{
    // the same JSON text, given in different encodings
    const std::string utf8 = "{\"name\":\"\u00e9\"}";
    const std::u16string utf16 = u"{\"name\":\"\u00e9\"}";
    const std::u32string utf32 = U"{\"name\":\"\u00e9\"}";
    const std::wstring wide = L"{\"name\":\"\u00e9\"}";

    // the encoding is deduced from the character type of the input, and all
    // of them yield the same value
    std::cout << json::parse(utf8) << '\n'
              << json::parse(utf16) << '\n'
              << json::parse(utf32) << '\n'
              << json::parse(wide) << '\n';

    // a wide string literal works as well: u"..." is UTF-16, U"..." is UTF-32
    std::cout << json::parse(u"[1, 2, 3]") << '\n';

    // iterators over wide characters work as well
    std::cout << json::parse(utf16.begin(), utf16.end()) << '\n';
}
