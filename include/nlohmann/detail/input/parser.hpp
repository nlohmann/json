#pragma once

#include <cassert> // assert
#include <cmath> // isfinite
#include <cstdint> // uint8_t
#include <functional> // function
#include <string> // string
#include <utility> // move

#include <nlohmann/detail/exceptions.hpp>
#include <nlohmann/detail/macro_scope.hpp>
#include <nlohmann/detail/input/input_adapters.hpp>
#include <nlohmann/detail/input/lexer.hpp>
#include <nlohmann/detail/value_t.hpp>

namespace nlohmann
{
namespace detail
{
////////////
// parser //
////////////

/*!
@brief syntax analysis

This class implements a recursive decent parser.
*/
template<typename BasicJsonType>
class parser
{
    using number_integer_t = typename BasicJsonType::number_integer_t;
    using number_unsigned_t = typename BasicJsonType::number_unsigned_t;
    using number_float_t = typename BasicJsonType::number_float_t;
    using string_t = typename BasicJsonType::string_t;
    using lexer_t = lexer<BasicJsonType>;
    using token_type = typename lexer_t::token_type;

  public:
    enum class parse_event_t : uint8_t
    {
        /// the parser read `{` and started to process a JSON object
        object_start,
        /// the parser read `}` and finished processing a JSON object
        object_end,
        /// the parser read `[` and started to process a JSON array
        array_start,
        /// the parser read `]` and finished processing a JSON array
        array_end,
        /// the parser read a key of a value in an object
        key,
        /// the parser finished reading a JSON value
        value
    };

    using parser_callback_t =
        std::function<bool(int depth, parse_event_t event, BasicJsonType& parsed)>;

    /// a parser reading from an input adapter
    explicit parser(detail::input_adapter_t adapter,
                    const parser_callback_t cb = nullptr,
                    const bool allow_exceptions_ = true)
        : callback(cb), m_lexer(adapter), allow_exceptions(allow_exceptions_)
    {}

    /*!
    @brief public parser interface

    @param[in] strict      whether to expect the last token to be EOF
    @param[in,out] result  parsed JSON value

    @throw parse_error.101 in case of an unexpected token
    @throw parse_error.102 if to_unicode fails or surrogate error
    @throw parse_error.103 if to_unicode fails
    */
    void parse(const bool strict, BasicJsonType& result)
    {
        // read first token
        get_token();

        parse_internal(true, result);
        result.assert_invariant();

        // in strict mode, input must be completely read
        if (strict)
        {
            get_token();
            expect(token_type::end_of_input);
        }

        // in case of an error, return discarded value
        if (errored)
        {
            result = value_t::discarded;
            return;
        }

        // set top-level value to null if it was discarded by the callback
        // function
        if (result.is_discarded())
        {
            result = nullptr;
        }
    }

    /*!
    @brief public accept interface

    @param[in] strict  whether to expect the last token to be EOF
    @return whether the input is a proper JSON text
    */
    bool accept(const bool strict = true)
    {
        // read first token
        get_token();

        if (not accept_internal())
        {
            return false;
        }

        // strict => last token must be EOF
        return not strict or (get_token() == token_type::end_of_input);
    }

  private:
    /*!
    @brief the actual parser
    @throw parse_error.101 in case of an unexpected token
    @throw parse_error.102 if to_unicode fails or surrogate error
    @throw parse_error.103 if to_unicode fails
    */
    void parse_internal(bool keep, BasicJsonType& result)
    {
        // never parse after a parse error was detected
        assert(not errored);

        // start with a discarded value
        if (not result.is_discarded())
        {
            result.m_value.destroy(result.m_type);
            result.m_type = value_t::discarded;
        }

        switch (last_token)
        {
            case token_type::begin_object:
            {
                if (keep)
                {
                    if (callback)
                    {
                        keep = callback(depth++, parse_event_t::object_start, result);
                    }

                    if (not callback or keep)
                    {
                        // explicitly set result to object to cope with {}
                        result.m_type = value_t::object;
                        result.m_value = value_t::object;
                    }
                }

                // read next token
                get_token();

                // closing } -> we are done
                if (last_token == token_type::end_object)
                {
                    if (keep and callback and not callback(--depth, parse_event_t::object_end, result))
                    {
                        result.m_value.destroy(result.m_type);
                        result.m_type = value_t::discarded;
                    }
                    break;
                }

                // parse values
                string_t key;
                BasicJsonType value;
                while (true)
                {
                    // store key
                    if (not expect(token_type::value_string))
                    {
                        return;
                    }
                    key = m_lexer.move_string();

                    bool keep_tag = false;
                    if (keep)
                    {
                        if (callback)
                        {
                            BasicJsonType k(key);
                            keep_tag = callback(depth, parse_event_t::key, k);
                        }
                        else
                        {
                            keep_tag = true;
                        }
                    }

                    // parse separator (:)
                    get_token();
                    if (not expect(token_type::name_separator))
                    {
                        return;
                    }

                    // parse and add value
                    get_token();
                    value.m_value.destroy(value.m_type);
                    value.m_type = value_t::discarded;
                    parse_internal(keep, value);

                    if (JSON_UNLIKELY(errored))
                    {
                        return;
                    }

                    if (keep and keep_tag and not value.is_discarded())
                    {
                        result.m_value.object->emplace(std::move(key), std::move(value));
                    }

                    // comma -> next value
                    get_token();
                    if (last_token == token_type::value_separator)
                    {
                        get_token();
                        continue;
                    }

                    // closing }
                    if (not expect(token_type::end_object))
                    {
                        return;
                    }
                    break;
                }

                if (keep and callback and not callback(--depth, parse_event_t::object_end, result))
                {
                    result.m_value.destroy(result.m_type);
                    result.m_type = value_t::discarded;
                }
                break;
            }

            case token_type::begin_array:
            {
                if (keep)
                {
                    if (callback)
                    {
                        keep = callback(depth++, parse_event_t::array_start, result);
                    }

                    if (not callback or keep)
                    {
                        // explicitly set result to array to cope with []
                        result.m_type = value_t::array;
                        result.m_value = value_t::array;
                    }
                }

                // read next token
                get_token();

                // closing ] -> we are done
                if (last_token == token_type::end_array)
                {
                    if (callback and not callback(--depth, parse_event_t::array_end, result))
                    {
                        result.m_value.destroy(result.m_type);
                        result.m_type = value_t::discarded;
                    }
                    break;
                }

                // parse values
                BasicJsonType value;
                while (true)
                {
                    // parse value
                    value.m_value.destroy(value.m_type);
                    value.m_type = value_t::discarded;
                    parse_internal(keep, value);

                    if (JSON_UNLIKELY(errored))
                    {
                        return;
                    }

                    if (keep and not value.is_discarded())
                    {
                        result.m_value.array->push_back(std::move(value));
                    }

                    // comma -> next value
                    get_token();
                    if (last_token == token_type::value_separator)
                    {
                        get_token();
                        continue;
                    }

                    // closing ]
                    if (not expect(token_type::end_array))
                    {
                        return;
                    }
                    break;
                }

                if (keep and callback and not callback(--depth, parse_event_t::array_end, result))
                {
                    result.m_value.destroy(result.m_type);
                    result.m_type = value_t::discarded;
                }
                break;
            }

            case token_type::literal_null:
            {
                result.m_type = value_t::null;
                break;
            }

            case token_type::value_string:
            {
                result.m_type = value_t::string;
                result.m_value = m_lexer.move_string();
                break;
            }

            case token_type::literal_true:
            {
                result.m_type = value_t::boolean;
                result.m_value = true;
                break;
            }

            case token_type::literal_false:
            {
                result.m_type = value_t::boolean;
                result.m_value = false;
                break;
            }

            case token_type::value_unsigned:
            {
                result.m_type = value_t::number_unsigned;
                result.m_value = m_lexer.get_number_unsigned();
                break;
            }

            case token_type::value_integer:
            {
                result.m_type = value_t::number_integer;
                result.m_value = m_lexer.get_number_integer();
                break;
            }

            case token_type::value_float:
            {
                result.m_type = value_t::number_float;
                result.m_value = m_lexer.get_number_float();

                // throw in case of infinity or NAN
                if (JSON_UNLIKELY(not std::isfinite(result.m_value.number_float)))
                {
                    if (allow_exceptions)
                    {
                        JSON_THROW(out_of_range::create(406, "number overflow parsing '" +
                                                        m_lexer.get_token_string() + "'"));
                    }
                    expect(token_type::uninitialized);
                }
                break;
            }

            case token_type::parse_error:
            {
                // using "uninitialized" to avoid "expected" message
                if (not expect(token_type::uninitialized))
                {
                    return;
                }
                break; // LCOV_EXCL_LINE
            }

            default:
            {
                // the last token was unexpected; we expected a value
                if (not expect(token_type::literal_or_value))
                {
                    return;
                }
                break; // LCOV_EXCL_LINE
            }
        }

        if (keep and callback and not callback(depth, parse_event_t::value, result))
        {
            result.m_value.destroy(result.m_type);
            result.m_type = value_t::discarded;
        }
    }

    /*!
    @brief the actual acceptor

    @invariant 1. The last token is not yet processed. Therefore, the caller
                  of this function must make sure a token has been read.
               2. When this function returns, the last token is processed.
                  That is, the last read character was already considered.

    This invariant makes sure that no token needs to be "unput".
    */
    bool accept_internal()
    {
        switch (last_token)
        {
            case token_type::begin_object:
            {
                // read next token
                get_token();

                // closing } -> we are done
                if (last_token == token_type::end_object)
                {
                    return true;
                }

                // parse values
                while (true)
                {
                    // parse key
                    if (last_token != token_type::value_string)
                    {
                        return false;
                    }

                    // parse separator (:)
                    get_token();
                    if (last_token != token_type::name_separator)
                    {
                        return false;
                    }

                    // parse value
                    get_token();
                    if (not accept_internal())
                    {
                        return false;
                    }

                    // comma -> next value
                    get_token();
                    if (last_token == token_type::value_separator)
                    {
                        get_token();
                        continue;
                    }

                    // closing }
                    return (last_token == token_type::end_object);
                }
            }

            case token_type::begin_array:
            {
                // read next token
                get_token();

                // closing ] -> we are done
                if (last_token == token_type::end_array)
                {
                    return true;
                }

                // parse values
                while (true)
                {
                    // parse value
                    if (not accept_internal())
                    {
                        return false;
                    }

                    // comma -> next value
                    get_token();
                    if (last_token == token_type::value_separator)
                    {
                        get_token();
                        continue;
                    }

                    // closing ]
                    return (last_token == token_type::end_array);
                }
            }

            case token_type::value_float:
            {
                // reject infinity or NAN
                return std::isfinite(m_lexer.get_number_float());
            }

            case token_type::literal_false:
            case token_type::literal_null:
            case token_type::literal_true:
            case token_type::value_integer:
            case token_type::value_string:
            case token_type::value_unsigned:
                return true;

            default: // the last token was unexpected
                return false;
        }
    }

    /// get next token from lexer
    token_type get_token()
    {
        return (last_token = m_lexer.scan());
    }

    /*!
    @throw parse_error.101 if expected token did not occur
    */
    bool expect(token_type t)
    {
        if (JSON_UNLIKELY(t != last_token))
        {
            errored = true;
            expected = t;
            if (allow_exceptions)
            {
                throw_exception();
            }
            else
            {
                return false;
            }
        }

        return true;
    }

    [[noreturn]] void throw_exception() const
    {
        std::string error_msg = "syntax error - ";
        if (last_token == token_type::parse_error)
        {
            error_msg += std::string(m_lexer.get_error_message()) + "; last read: '" +
                         m_lexer.get_token_string() + "'";
        }
        else
        {
            error_msg += "unexpected " + std::string(lexer_t::token_type_name(last_token));
        }

        if (expected != token_type::uninitialized)
        {
            error_msg += "; expected " + std::string(lexer_t::token_type_name(expected));
        }

        JSON_THROW(parse_error::create(101, m_lexer.get_position(), error_msg));
    }

  private:
    /// current level of recursion
    int depth = 0;
    /// callback function
    const parser_callback_t callback = nullptr;
    /// the type of the last read token
    token_type last_token = token_type::uninitialized;
    /// the lexer
    lexer_t m_lexer;
    /// whether a syntax error occurred
    bool errored = false;
    /// possible reason for the syntax error
    token_type expected = token_type::uninitialized;
    /// whether to throw exceptions in case of errors
    const bool allow_exceptions = true;
};
}
}
