#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    json j = json::parse(R"({"name": "Mary", "age": 42})");

    // look up the key, then test the type: neither step throws
    for (const char* key : {"name", "age", "city"})
    {
        const auto it = j.find(key);
        if (it == j.end())
        {
            std::cout << key << ": missing\n";
        }
        else if (it->is_string())
        {
            std::cout << key << ": string \"" << it->get_ref<const std::string&>() << "\"\n";
        }
        else
        {
            std::cout << key << ": not a string, but " << it->type_name() << '\n';
        }
    }

    // get_ptr returns a null pointer if the value has another type
    const std::string* name = j["name"].get_ptr<const std::string*>();
    const std::string* age = j["age"].get_ptr<const std::string*>();
    std::cout << "get_ptr<string*>: name = " << (name != nullptr) << ", age = " << (age != nullptr) << '\n';

    // value() is NOT exception-free: it throws if the key exists with a different type
    try
    {
        std::cout << j.value("name", 0) << '\n';
    }
    catch (const json::type_error& e)
    {
        std::cout << e.what() << '\n';
    }
}
