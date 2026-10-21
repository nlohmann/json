#include <iostream>
#include <nlohmann/json_view.hpp>
#include <string>

using json_document = nlohmann::json_document;
using json_view = nlohmann::json_view;

int main()
{
    json_document doc = json_document::parse(R"({"host": "db.example.com", "port": 5432, "ssl": true})");
    const json_view config = doc.root();

    // get_to() writes directly into existing variables -- handy for filling
    // in the members of a struct one field at a time, without an
    // intermediate value from get<T>() for each one
    std::string host;
    int port = 0;
    bool ssl = false;
    config["host"].get_to(host);
    config["port"].get_to(port);
    config["ssl"].get_to(ssl);
    std::cout << host << ':' << port << (ssl ? " (tls)" : "") << '\n';

    // the return value is a reference to the argument, so a call can be
    // used directly in a larger expression
    std::string other_host;
    std::cout << config["host"].get_to(other_host).size() << '\n';
}
