#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include <nlohmann/detail/exceptions.hpp>

namespace nlohmann
{

/*!
@brief SAX interface
*/
template<typename BasicJsonType>
struct json_sax
{
    /// type for (signed) integers
    using number_integer_t = typename BasicJsonType::number_integer_t;
    /// type for unsigned integers
    using number_unsigned_t = typename BasicJsonType::number_unsigned_t;
    /// type for floating-point numbers
    using number_float_t = typename BasicJsonType::number_float_t;
    /// type for strings
    using string_t = typename BasicJsonType::string_t;

    /// constant to indicate that no size limit is given for array or object
    static constexpr auto no_limit = std::size_t(-1);

    /*!
    @brief a null value was read
    @return whether parsing should proceed
    */
    virtual bool null() = 0;

    /*!
    @brief a boolean value was read
    @param[in] val  boolean value
    @return whether parsing should proceed
    */
    virtual bool boolean(bool val) = 0;

    /*!
    @brief an integer number was read
    @param[in] val  integer value
    @return whether parsing should proceed
    */
    virtual bool number_integer(number_integer_t val) = 0;

    /*!
    @brief an unsigned integer number was read
    @param[in] val  unsigned integer value
    @return whether parsing should proceed
    */
    virtual bool number_unsigned(number_unsigned_t val) = 0;

    /*!
    @brief an floating-point number was read
    @param[in] val  floating-point value
    @param[in] s    raw token value
    @return whether parsing should proceed
    */
    virtual bool number_float(number_float_t val, const string_t& s) = 0;

    /*!
    @brief a string was read
    @param[in] val  string value
    @return whether parsing should proceed
    */
    virtual bool string(string_t&& val) = 0;

    /*!
    @brief the beginning of an object was read
    @param[in] elements  number of object elements or no_limit if unknown
    @return whether parsing should proceed
    @note binary formats may report the number of elements
    */
    virtual bool start_object(std::size_t elements = no_limit) = 0;

    /*!
    @brief an object key was read
    @param[in] val  object key
    @return whether parsing should proceed
    */
    virtual bool key(string_t&& val) = 0;

    /*!
    @brief the end of an object was read
    @return whether parsing should proceed
    */
    virtual bool end_object() = 0;

    /*!
    @brief the beginning of an array was read
    @param[in] elements  number of array elements or no_limit if unknown
    @return whether parsing should proceed
    @note binary formats may report the number of elements
    */
    virtual bool start_array(std::size_t elements = no_limit) = 0;

    /*!
    @brief the end of an array was read
    @return whether parsing should proceed
    */
    virtual bool end_array() = 0;

    /*!
    @brief a binary value was read
    @param[in] val  byte vector
    @return whether parsing should proceed
    @note examples are CBOR type 2 strings, MessagePack bin, and maybe UBJSON
          array<uint8t>
    */
    virtual bool binary(const std::vector<uint8_t>& val) = 0;

    /*!
    @brief a parse error occurred
    @param[in] position    the position in the input where the error occurs
    @param[in] last_token  the last read token
    @param[in] error_msg   a detailed error message
    @return whether parsing should proceed
    */
    virtual bool parse_error(std::size_t position,
                             const std::string& last_token,
                             const detail::exception& ex) = 0;

    virtual ~json_sax() = default;
};


namespace detail
{
template<typename BasicJsonType>
class json_sax_dom_parser : public json_sax<BasicJsonType>
{
  public:
    using number_integer_t = typename BasicJsonType::number_integer_t;
    using number_unsigned_t = typename BasicJsonType::number_unsigned_t;
    using number_float_t = typename BasicJsonType::number_float_t;
    using string_t = typename BasicJsonType::string_t;

    json_sax_dom_parser(BasicJsonType& r, const bool allow_exceptions_ = true)
        : root(r), allow_exceptions(allow_exceptions_)
    {}

    bool null() override
    {
        handle_value(nullptr);
        return true;
    }

    bool boolean(bool val) override
    {
        handle_value(val);
        return true;
    }

    bool number_integer(number_integer_t val) override
    {
        handle_value(val);
        return true;
    }

    bool number_unsigned(number_unsigned_t val) override
    {
        handle_value(val);
        return true;
    }

    bool number_float(number_float_t val, const string_t&) override
    {
        handle_value(val);
        return true;
    }

    bool string(string_t&& val) override
    {
        handle_value(val);
        return true;
    }

    bool start_object(std::size_t len) override
    {
        ref_stack.push_back(handle_value(BasicJsonType::value_t::object));

        if (JSON_UNLIKELY(len != json_sax<BasicJsonType>::no_limit and len > ref_stack.back()->max_size()))
        {
            JSON_THROW(out_of_range::create(408,
                                            "excessive object size: " + std::to_string(len)));
        }

        return true;
    }

    bool key(string_t&& val) override
    {
        // add null at given key and store the reference for later
        object_element = &(ref_stack.back()->m_value.object->operator[](val));
        return true;
    }

    bool end_object() override
    {
        ref_stack.pop_back();
        return true;
    }

    bool start_array(std::size_t len) override
    {
        ref_stack.push_back(handle_value(BasicJsonType::value_t::array));

        if (JSON_UNLIKELY(len != json_sax<BasicJsonType>::no_limit and len > ref_stack.back()->max_size()))
        {
            JSON_THROW(out_of_range::create(408,
                                            "excessive array size: " + std::to_string(len)));
        }

        return true;
    }

    bool end_array() override
    {
        ref_stack.pop_back();
        return true;
    }

    bool binary(const std::vector<uint8_t>&) override
    {
        return true;
    }

    bool parse_error(std::size_t, const std::string&,
                     const detail::exception& ex) override
    {
        errored = true;
        if (allow_exceptions)
        {
            // determine the proper exception type from the id
            switch ((ex.id / 100) % 100)
            {
                case 1:
                    JSON_THROW(*reinterpret_cast<const detail::parse_error*>(&ex));
                case 2:
                    JSON_THROW(*reinterpret_cast<const detail::invalid_iterator*>(&ex));  // LCOV_EXCL_LINE
                case 3:
                    JSON_THROW(*reinterpret_cast<const detail::type_error*>(&ex));  // LCOV_EXCL_LINE
                case 4:
                    JSON_THROW(*reinterpret_cast<const detail::out_of_range*>(&ex));
                case 5:
                    JSON_THROW(*reinterpret_cast<const detail::other_error*>(&ex));  // LCOV_EXCL_LINE
                default:
                    assert(false);  // LCOV_EXCL_LINE
            }
        }
        return false;
    }

    bool is_errored() const
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
    BasicJsonType* handle_value(Value&& v)
    {
        if (ref_stack.empty())
        {
            root = BasicJsonType(std::forward<Value>(v));
            return &root;
        }
        else
        {
            assert(ref_stack.back()->is_array() or ref_stack.back()->is_object());
            if (ref_stack.back()->is_array())
            {
                ref_stack.back()->m_value.array->push_back(BasicJsonType(std::forward<Value>(v)));
                return &(ref_stack.back()->m_value.array->back());
            }
            else
            {
                assert(object_element);
                *object_element = BasicJsonType(std::forward<Value>(v));
                return object_element;
            }
        }
    }

    /// the parsed JSON value
    BasicJsonType& root;
    /// stack to model hierarchy of values
    std::vector<BasicJsonType*> ref_stack;
    /// helper to hold the reference for the next object element
    BasicJsonType* object_element = nullptr;
    /// whether a syntax error occurred
    bool errored = false;
    /// whether to throw exceptions in case of errors
    const bool allow_exceptions = true;
};

template<typename BasicJsonType>
class json_sax_acceptor : public json_sax<BasicJsonType>
{
  public:
    using number_integer_t = typename BasicJsonType::number_integer_t;
    using number_unsigned_t = typename BasicJsonType::number_unsigned_t;
    using number_float_t = typename BasicJsonType::number_float_t;
    using string_t = typename BasicJsonType::string_t;

    bool null() override
    {
        return true;
    }

    bool boolean(bool) override
    {
        return true;
    }

    bool number_integer(number_integer_t) override
    {
        return true;
    }

    bool number_unsigned(number_unsigned_t) override
    {
        return true;
    }

    bool number_float(number_float_t, const string_t&) override
    {
        return true;
    }

    bool string(string_t&&) override
    {
        return true;
    }

    bool start_object(std::size_t) override
    {
        return true;
    }

    bool key(string_t&&) override
    {
        return true;
    }

    bool end_object() override
    {
        return true;
    }

    bool start_array(std::size_t) override
    {
        return true;
    }

    bool end_array() override
    {
        return true;
    }

    bool binary(const std::vector<uint8_t>&) override
    {
        return true;
    }

    bool parse_error(std::size_t, const std::string&, const detail::exception&) override
    {
        return false;
    }
};
}

}

