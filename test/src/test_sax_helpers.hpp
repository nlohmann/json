#pragma once

#include <nlohmann/json.hpp>

using nlohmann::json;

class SaxEventLogger : public nlohmann::sax_interface<nlohmann::json>
{
  public:

    std::vector<std::string> events {};
    bool errored = false;

    bool null() override
    {
        events.emplace_back("null()");
        return true;
    }

    bool boolean(bool val) override
    {
        events.emplace_back(val ? "boolean(true)" : "boolean(false)");
        return true;
    }

    bool number_integer(json::number_integer_t val) override
    {
        events.push_back("number_integer(" + std::to_string(val) + ")");
        return true;
    }

    bool number_unsigned(json::number_unsigned_t val) override
    {
        events.push_back("number_unsigned(" + std::to_string(val) + ")");
        return true;
    }

    bool number_float(json::number_float_t /*unused*/, const std::string& s)  override
    {
        events.push_back("number_float(" + s + ")");
        return true;
    }

    bool string(std::string& val)  override
    {
        events.push_back("string(" + val + ")");
        return true;
    }

    bool binary(json::binary_t& val)  override
    {
        std::string binary_contents = "binary(";
        std::string comma_space;
        for (auto b : val)
        {
            binary_contents.append(comma_space);
            binary_contents.append(std::to_string(static_cast<int>(b)));
            comma_space = ", ";
        }
        binary_contents.append(")");
        events.push_back(binary_contents);
        return true;
    }

    bool start_object(std::size_t elements)  override
    {
        if (elements == static_cast<std::size_t>(-1))
        {
            events.emplace_back("start_object()");
        }
        else
        {
            events.push_back("start_object(" + std::to_string(elements) + ")");
        }
        return true;
    }

    bool key(std::string& val)  override
    {
        events.push_back("key(" + val + ")");
        return true;
    }

    virtual bool key_null()  override
    {
        events.push_back("key_null");
        return true;
    }

    virtual bool key_boolean(bool val)  override
    {
        events.push_back("key_bool(" + std::to_string(val) + ")");
        return true;
    }

    virtual bool key_integer(json::number_integer_t val) override
    {
        events.push_back("key_integer(" + std::to_string(val) + ")");
        return true;
    }

    virtual bool key_unsigned(json::number_unsigned_t val) override
    {
        events.push_back("key_unsigned(" + std::to_string(val) + ")");
        return true;
    }

    virtual bool key_float(json::number_float_t val, const json::string_t& s) override
    {
        events.push_back("key_float(" + s + ")");
        return true;
    }

    bool end_object() override
    {
        events.emplace_back("end_object()");
        return true;
    }

    bool start_array(std::size_t elements) override
    {
        if (elements == static_cast<std::size_t>(-1))
        {
            events.emplace_back("start_array()");
        }
        else
        {
            events.push_back("start_array(" + std::to_string(elements) + ")");
        }
        return true;
    }

    bool end_array() override
    {
        events.emplace_back("end_array()");
        return true;
    }

    bool parse_error(std::size_t position, const std::string& /*unused*/, const json::exception& /*unused*/)  override
    {
        errored = true;
        events.push_back("parse_error(" + std::to_string(position) + ")");
        return false;
    }

};


class SaxCountdown : public nlohmann::sax_interface<nlohmann::json>
{

  protected:
    int events_left = 0;

  public:
    explicit SaxCountdown(const int count) : events_left(count)
    {}

    bool null() override
    {
        return events_left-- > 0;
    }

    bool boolean(bool /*val*/) override
    {
        return events_left-- > 0;
    }

    bool number_integer(json::number_integer_t /*val*/) override
    {
        return events_left-- > 0;
    }

    bool number_unsigned(json::number_unsigned_t /*val*/) override
    {
        return events_left-- > 0;
    }

    bool number_float(json::number_float_t /*val*/, const std::string& /*s*/) override
    {
        return events_left-- > 0;
    }

    bool string(std::string& /*val*/) override
    {
        return events_left-- > 0;
    }

    bool binary(json::binary_t& /*val*/) override
    {
        return events_left-- > 0;
    }

    bool start_object(std::size_t /*elements*/) override
    {
        return events_left-- > 0;
    }

    bool key(std::string& /*val*/) override
    {
        return events_left-- > 0;
    }

    bool key_null() override
    {
        return events_left-- > 0;
    }

    bool key_boolean(bool /*val*/)  override
    {
        return events_left-- > 0;
    }

    bool key_integer(number_integer_t /*val*/) override
    {
        return events_left-- > 0;
    }

    bool key_unsigned(number_unsigned_t /*val*/) override
    {
        return events_left-- > 0;
    }

    bool key_float(number_float_t /*val*/, const string_t& /*val*/) override
    {
        return events_left-- > 0;
    }

    bool end_object() override
    {
        return events_left-- > 0;
    }

    bool start_array(std::size_t /*elements*/) override
    {
        return events_left-- > 0;
    }

    bool end_array() override
    {
        return events_left-- > 0;
    }

    bool parse_error(std::size_t /*position*/, const std::string& /*last_token*/, const json::exception& /*ex*/) override
    {
        return false;
    }

};

class sax_no_exception : public nlohmann::detail::json_sax_dom_parser<json>
{
  public:
    explicit sax_no_exception(json& j)
        : nlohmann::detail::json_sax_dom_parser<json>(j, false)
    {}

    bool parse_error(std::size_t /*position*/, const std::string& /*last_token*/, const json::exception& ex) override
    {
        error_string = new std::string(ex.what());  // NOLINT(cppcoreguidelines-owning-memory)
        return false;
    }

    static std::string* error_string;
};