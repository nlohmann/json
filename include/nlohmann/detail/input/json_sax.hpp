#pragma once

#include <cstddef>
#include <string>
#include <vector>

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
    virtual bool number_float(number_float_t val, const std::string& s) = 0;

    /*!
    @brief a string was read
    @param[in] val  string value
    @return whether parsing should proceed
    */
    virtual bool string(std::string&& val) = 0;

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
    virtual bool key(std::string&& val) = 0;

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
                             const std::string& error_msg) = 0;

    virtual ~json_sax() = default;
};
}

