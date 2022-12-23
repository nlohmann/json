#include <iomanip>
#include <iostream>
#include <nlohmann/json.hpp>
#include <sstream>

using json = nlohmann::json;

// custom base class for the json node.
// allows us to store metadata and add custom methods to each node
struct token_start_stop
{
    nlohmann::position_t start{};
    nlohmann::position_t stop{};

    std::string start_pos_str() const
    {
        return "{l=" + std::to_string(start.lines_read) + ":c="
               + std::to_string(start.chars_read_current_line) + "}";
    }
    std::string stop_pos_str() const
    {
        return "{l=" + std::to_string(stop.lines_read) + ":c=" + std::to_string(stop.chars_read_current_line) + "}";
    }
    std::string location_str() const
    {
        return "[" + start_pos_str() + ", " + stop_pos_str() + ")";
    }
};

//json type using token_start_stop as base class
using json_with_token_start_stop =
    nlohmann::basic_json <
    std::map,
    std::vector,
    std::string,
    bool,
    std::int64_t,
    std::uint64_t,
    double,
    std::allocator,
    nlohmann::adl_serializer,
    std::vector<std::uint8_t>,
    token_start_stop >;

// a parser storing the lexer information for each node
class sax_with_token_start_stop_metadata
{
  public:
    using json = json_with_token_start_stop;
    using number_integer_t = typename json::number_integer_t;
    using number_unsigned_t = typename json::number_unsigned_t;
    using number_float_t = typename json::number_float_t;
    using string_t = typename json::string_t;
    using binary_t = typename json::binary_t;

    /*!
    @param[in,out] r  reference to a JSON value that is manipulated while
                       parsing
    @param[in] allow_exceptions_  whether parse errors yield exceptions
    */
    explicit sax_with_token_start_stop_metadata(json& r, const bool allow_exceptions_ = true)
        : root(r)
        , ref_stack{}
        , object_element{nullptr}
        , errored{false}
        , allow_exceptions(allow_exceptions_)
        , start_stop{}
    {}

    void next_token_start(const nlohmann::position_t&  p)
    {
        start_stop.start = p;
    }

    void next_token_end(const nlohmann::position_t&  p)
    {
        start_stop.stop = p;
    }

    bool null()
    {
        handle_value(nullptr);
        return true;
    }

    bool boolean(bool val)
    {
        handle_value(val);
        return true;
    }

    bool number_integer(number_integer_t val)
    {
        handle_value(val);
        return true;
    }

    bool number_unsigned(number_unsigned_t val)
    {
        handle_value(val);
        return true;
    }

    bool number_float(number_float_t val, const string_t& /*unused*/)
    {
        handle_value(val);
        return true;
    }

    bool string(string_t& val)
    {
        handle_value(val);
        return true;
    }

    bool binary(binary_t& val)
    {
        handle_value(std::move(val));
        return true;
    }

    bool start_object(std::size_t len)
    {
        ref_stack.push_back(handle_value(json::value_t::object));
        ref_stack.back()->start = start_stop.start;

        if (len != static_cast<std::size_t>(-1) && len > ref_stack.back()->max_size())
        {
            throw nlohmann::detail::out_of_range::create(408, nlohmann::detail::concat("excessive object size: ", std::to_string(len)), ref_stack.back());
        }

        return true;
    }

    bool key(string_t& val)
    {
        assert(!ref_stack.empty());
        assert(ref_stack.back()->is_object());

        // add null at given key and store the reference for later
        object_element = &(*ref_stack.back())[val];
        return true;
    }

    bool end_object()
    {
        assert(!ref_stack.empty());
        assert(ref_stack.back()->is_object());

        ref_stack.back()->stop = start_stop.stop;
        ref_stack.pop_back();
        return true;
    }

    bool start_array(std::size_t len)
    {
        ref_stack.push_back(handle_value(json::value_t::array));
        ref_stack.back()->start = start_stop.start;

        if (len != static_cast<std::size_t>(-1) && len > ref_stack.back()->max_size())
        {
            throw nlohmann::detail::out_of_range::create(408, nlohmann::detail::concat("excessive array size: ", std::to_string(len)), ref_stack.back());
        }

        return true;
    }

    bool end_array()
    {
        assert(!ref_stack.empty());
        assert(ref_stack.back()->is_array());

        ref_stack.back()->stop = start_stop.stop;
        ref_stack.pop_back();
        return true;
    }

    template<class Exception>
    bool parse_error(std::size_t /*unused*/, const std::string& /*unused*/, const Exception& ex)
    {
        errored = true;
        static_cast<void>(ex);
        if (allow_exceptions)
        {
            throw ex;
        }
        return false;
    }

    constexpr bool is_errored() const
    {
        return errored;
    }

  private:
    /*!
    @invariant If the ref stack is empty, then the passed value will be the new
               root.
    @invariant If the ref stack contains a value, then it is an array or an
               object to which we can add elements
    */
    template<typename Value>
    json*
    handle_value(Value&& v)
    {
        if (ref_stack.empty())
        {
            root = json(std::forward<Value>(v));
            root.start = start_stop.start;
            root.stop = start_stop.stop;
            return &root;
        }

        assert(ref_stack.back()->is_array() || ref_stack.back()->is_object());

        if (ref_stack.back()->is_array())
        {
            auto& array_element = ref_stack.back()->emplace_back(std::forward<Value>(v));
            array_element.start = start_stop.start;
            array_element.stop = start_stop.stop;
            return &array_element;
        }

        assert(ref_stack.back()->is_object());
        assert(object_element);
        *object_element = json(std::forward<Value>(v));
        object_element->start = start_stop.start;
        object_element->stop = start_stop.stop;
        return object_element;
    }

    /// the parsed JSON value
    json& root;
    /// stack to model hierarchy of values
    std::vector<json*> ref_stack{};
    /// helper to hold the reference for the next object element
    json* object_element = nullptr;
    /// whether a syntax error occurred
    bool errored = false;
    /// whether to throw exceptions in case of errors
    const bool allow_exceptions = true;
    /// start / stop information for the current token
    token_start_stop start_stop{};
};

void dump(const json_with_token_start_stop& j, std::size_t indentlvl = 0)
{
    const std::string indent(indentlvl * 4, ' ');
    switch (j.type())
    {
        case nlohmann::json::value_t::null:
        {
            std::cout << indent << "null(at=" << j.location_str() << ")\n";
        }
        break;
        case nlohmann::json::value_t::object:
        {
            std::cout << indent << "object(size=" << j.size() << ", at=" << j.location_str() << ")\n";
            for (const auto& elem : j.items())
            {
                dump(elem.value(), indentlvl + 1);
            }
        }
        break;
        case nlohmann::json::value_t::array:
        {
            std::cout << indent << "array(size=" << j.size() << ", at=" << j.location_str() << ")\n";
            for (const auto& elem : j)
            {
                dump(elem, indentlvl + 1);
            }
        }
        break;
        case nlohmann::json::value_t::string:
        {
            std::cout << indent << "string(val=" << j.get<std::string>() << ", at=" << j.location_str() << ")\n";
        }
        break;
        case nlohmann::json::value_t::boolean:
        {
            std::cout << indent << "boolean(val=" << j.get<bool>() << ", at=" << j.location_str() << ")\n";
        }
        break;
        case nlohmann::json::value_t::number_integer:
        {
            std::cout << indent << "number_integer(val=" << j.get<std::int64_t>() << ", at=" << j.location_str() << ")\n";
        }
        break;
        case nlohmann::json::value_t::number_unsigned:
        {
            std::cout << indent << "number_unsigned(val=" << j.get<std::uint64_t>() << ", at=" << j.location_str() << ")\n";
        }
        break;
        case nlohmann::json::value_t::number_float:
        {
            std::cout << indent << "number_float(val=" << j.get<double>() << ", at=" << j.location_str() << ")\n";
        }
        break;
        default:
            throw std::runtime_error{"unexpected input"};
    }
}

int main()
{
    // a JSON text
    auto text = R"({
        "Image": {
            "Width":  800,
            "Height": 600,
            "Title":  "View from 15th Floor",
            "Thumbnail": {
                "Url":    "http://www.example.com/image/481989943",
                "Height": 125,
                "Width":  100
            },
            "Animated" : false,
            "IDs": [116, 943, 234, -38793],
            "DeletionDate": null,
            "Distance": 12.723374634
        }
})";

    // create a SAX parser object
    json_with_token_start_stop parsed;
    sax_with_token_start_stop_metadata sax{parsed};

    // parse JSON
    bool result = json::sax_parse(text, &sax);

    // output the json data
    dump(parsed);

    // output the result of sax_parse
    std::cout << "\nresult: " << std::boolalpha << result << std::endl;
}
