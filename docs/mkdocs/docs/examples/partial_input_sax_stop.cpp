#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

struct find_id : nlohmann::json_sax<json>
{
    bool next_is_id = false;
    json::number_unsigned_t id = 0;

    bool key(std::string& name) override
    {
        next_is_id = (name == "id");
        return true;
    }

    bool number_unsigned(json::number_unsigned_t value) override
    {
        if (next_is_id)
        {
            id = value;
            return false; // found: stop parsing
        }
        return true;
    }

    bool null() override
    {
        return true;
    }
    bool boolean(bool /*val*/) override
    {
        return true;
    }
    bool number_integer(json::number_integer_t /*val*/) override
    {
        return true;
    }
    bool number_float(json::number_float_t /*val*/, const std::string& /*s*/) override
    {
        return true;
    }
    bool string(std::string& /*val*/) override
    {
        return true;
    }
    bool binary(json::binary_t& /*val*/) override
    {
        return true;
    }
    bool start_object(std::size_t /*elements*/) override
    {
        return true;
    }
    bool end_object() override
    {
        return true;
    }
    bool start_array(std::size_t /*elements*/) override
    {
        return true;
    }
    bool end_array() override
    {
        return true;
    }
    bool parse_error(std::size_t /*position*/, const std::string& /*last_token*/, const json::exception& /*ex*/) override
    {
        return false;
    }
};

int main()
{
    find_id handler;
    const bool completed = json::sax_parse(R"({"x": [1, 2, 3], "id": 42, "rest": [4, 5, 6]})", &handler);

    std::cout << std::boolalpha;
    std::cout << "parse completed: " << completed << '\n';
    std::cout << "id: " << handler.id << '\n';
}
