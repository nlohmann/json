//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <cmath> // isfinite
#include <cstdint> // uint8_t
#include <functional> // function
#include <string> // string
#include <utility> // move
#include <vector> // vector

#include <nlohmann/detail/exceptions.hpp>
#include <nlohmann/detail/input/input_adapters.hpp>
#include <nlohmann/detail/input/json_sax.hpp>
#include <nlohmann/detail/input/lexer.hpp>
#include <nlohmann/detail/macro_scope.hpp>
#include <nlohmann/detail/meta/is_sax.hpp>
#include <nlohmann/detail/string_concat.hpp>
#include <nlohmann/detail/value_t.hpp>

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{
////////////
// parser //
////////////

enum class parse_event_t : std::uint8_t
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

template<typename BasicJsonType>
using parser_callback_t =
    std::function<bool(int /*depth*/, parse_event_t /*event*/, BasicJsonType& /*parsed*/)>;

/*!
@brief syntax analysis

This class implements a parser for JSON text. Nested arrays and objects are tracked with an explicit
stack instead of recursion, so deeply nested input does not exhaust the call stack, and what is read
is reported as SAX events.
*/
template<typename BasicJsonType, typename InputAdapterType>
class parser
{
    using number_integer_t = typename BasicJsonType::number_integer_t;
    using number_unsigned_t = typename BasicJsonType::number_unsigned_t;
    using number_float_t = typename BasicJsonType::number_float_t;
    using string_t = typename BasicJsonType::string_t;
    using lexer_t = lexer<BasicJsonType, InputAdapterType>;
    using token_type = typename lexer_t::token_type;

  public:
    /// a parser reading from an input adapter
    explicit parser(InputAdapterType&& adapter,
                    parser_callback_t<BasicJsonType> cb = nullptr,
                    const bool allow_exceptions_ = true,
                    const bool ignore_comments = false,
                    const bool ignore_trailing_commas_ = false,
                    const bool discard_number_values_ = false)
        : callback(std::move(cb))
        , m_lexer(std::move(adapter), ignore_comments, discard_number_values_)
        , allow_exceptions(allow_exceptions_)
        , ignore_trailing_commas(ignore_trailing_commas_)
    {
        // read first token
        get_token();
    }

    /*!
    @brief public parser interface

    @param[in] strict      whether to expect the last token to be EOF
    @param[in,out] result  parsed JSON value

    @throw parse_error.101 in case of an unexpected token (including invalid
           unicode escapes and surrogate errors, which are reported with a
           detailed message)
    */
    void parse(const bool strict, BasicJsonType& result)
    {
        if (callback)
        {
            json_sax_dom_callback_parser<BasicJsonType, InputAdapterType> sdp(result, callback, allow_exceptions, &m_lexer);

            // in case of an error, return a discarded value
            if (!parse_dom(sdp, strict))
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
        else
        {
            json_sax_dom_parser<BasicJsonType, InputAdapterType> sdp(result, allow_exceptions, &m_lexer);

            // in case of an error, return a discarded value
            if (!parse_dom(sdp, strict))
            {
                result = value_t::discarded;
                return;
            }
        }

        result.assert_invariant();
    }

    /*!
    @brief public accept interface

    @param[in] strict  whether to expect the last token to be EOF
    @return whether the input is a proper JSON text
    */
    bool accept(const bool strict = true)
    {
        json_sax_acceptor<BasicJsonType> sax_acceptor;
        return sax_parse_impl<false>(&sax_acceptor, strict);
    }

    /*!
    @brief public SAX interface

    If the SAX parser's parse_error() returns true, the parser recovers from
    the error: it repairs the input and continues (see #3989).

    @param[in] sax     the SAX parser
    @param[in] strict  whether to expect the last token to be EOF
    @return whether the input was parsed without errors and no SAX event
            returned false
    */
    template<typename SAX>
    JSON_HEDLEY_NON_NULL(2)
    bool sax_parse(SAX* sax, const bool strict = true)
    {
        return sax_parse_impl<true>(sax, strict);
    }

  private:
    /// what sax_parse_internal() does after an object key was expected
    enum class next_step : std::uint8_t
    {
        /// stop parsing
        stop,
        /// parse a value that begins with last_token
        parse_value,
        /// evaluate the state of the innermost container, which reads
        /// last_token again
        evaluate_state
    };

    template<bool AllowRecovery, typename SAX>
    JSON_HEDLEY_NON_NULL(2)
    bool sax_parse_impl(SAX* sax, const bool strict)
    {
        (void)detail::is_sax_static_asserts<SAX, BasicJsonType> {};
        const bool result = sax_parse_internal<AllowRecovery>(sax);

        if (result)
        {
            if (strict)
            {
                // strict mode: next byte must be EOF; after recovering from an
                // error, the end of the input may already have been read
                if (last_token != token_type::end_of_input && get_token() != token_type::end_of_input)
                {
                    // the value is complete, so there is nothing to recover
                    static_cast<void>(report_error(sax, parse_error::create(101, m_lexer.get_position(), exception_message(token_type::end_of_input, "value"), nullptr),
                                                   std::integral_constant<bool, AllowRecovery> {}));
                    return false;
                }
            }
            else
            {
                // the caller keeps using the input: position it right after
                // the value by leaving the character that terminated it
                m_lexer.release_lookahead();
            }
        }

        return result && !error_reported;
    }

    /*!
    @brief run a DOM SAX parser to completion and position the lexer

    Shared by both branches of @ref parse(): builds no SAX parser itself,
    but drives an already-constructed @a json_sax_dom_parser or
    @ref json_sax_dom_callback_parser through @ref sax_parse_internal(),
    then applies the strict-EOF check (reporting parse_error.101 through
    @a sdp on failure) or, in non-strict mode, releases the lookahead so
    the caller can keep reading the input right after the parsed value.

    @param[in,out] sdp     the DOM SAX parser to run
    @param[in] strict      whether to expect the last token to be EOF
    @return whether @a sdp did not report an error
    */
    template<typename DomSax>
    bool parse_dom(DomSax& sdp, const bool strict)
    {
        sax_parse_internal<false>(&sdp);

        if (strict)
        {
            // in strict mode, input must be completely read
            if (get_token() != token_type::end_of_input)
            {
                sdp.parse_error(m_lexer.get_position(),
                                m_lexer.get_token_string(),
                                parse_error::create(101, m_lexer.get_position(),
                                                    exception_message(token_type::end_of_input, "value"), nullptr));
            }
        }
        else
        {
            // the caller keeps using the input: position it right after
            // the value by leaving the character that terminated it
            m_lexer.release_lookahead();
        }

        return !sdp.is_errored();
    }

    /*!
    @brief parse a JSON value and pass it to a SAX parser

    @tparam AllowRecovery  whether to recover from an error if the SAX parser's
                           parse_error() returns true; false for the SAX parsers
                           of parse() and accept(), which never do, so that no
                           code for recovering is generated for them
    */
    template<bool AllowRecovery, typename SAX>
    JSON_HEDLEY_NON_NULL(2)
    bool sax_parse_internal(SAX* sax)
    {
        const std::integral_constant<bool, AllowRecovery> allow_recovery{};

        // stack to remember the hierarchy of structured values we are parsing
        // true = array; false = object
        std::vector<bool> states;
        // value to avoid a goto (see comment where set to true)
        bool skip_to_state_evaluation = false;

        while (true)
        {
            if (!skip_to_state_evaluation)
            {
                // invariant: get_token() was called before each iteration
                switch (last_token)
                {
                    case token_type::begin_object:
                    {
                        if (JSON_HEDLEY_UNLIKELY(!sax->start_object(detail::unknown_size())))
                        {
                            return false;
                        }

                        // closing } -> we are done
                        if (get_token() == token_type::end_object)
                        {
                            if (JSON_HEDLEY_UNLIKELY(!sax->end_object()))
                            {
                                return false;
                            }
                            break;
                        }

                        // remember we are now inside an object
                        states.push_back(false);

                        // parse key (the steps of parse_key(), which are
                        // repeated here and below for speed)
                        if (JSON_HEDLEY_UNLIKELY(last_token != token_type::value_string))
                        {
                            if (!continue_after(key_error(sax, allow_recovery, false), skip_to_state_evaluation))
                            {
                                return false;
                            }
                            continue;
                        }
                        if (JSON_HEDLEY_UNLIKELY(!sax->key(m_lexer.get_string())))
                        {
                            return false;
                        }

                        // parse separator (:)
                        if (JSON_HEDLEY_UNLIKELY(get_token() != token_type::name_separator))
                        {
                            if (!continue_after(key_error(sax, allow_recovery, true), skip_to_state_evaluation))
                            {
                                return false;
                            }
                            continue;
                        }

                        // parse values
                        get_token();
                        continue;
                    }

                    case token_type::begin_array:
                    {
                        if (JSON_HEDLEY_UNLIKELY(!sax->start_array(detail::unknown_size())))
                        {
                            return false;
                        }

                        // closing ] -> we are done
                        if (get_token() == token_type::end_array)
                        {
                            if (JSON_HEDLEY_UNLIKELY(!sax->end_array()))
                            {
                                return false;
                            }
                            break;
                        }

                        // remember we are now inside an array
                        states.push_back(true);

                        // parse values (no need to call get_token)
                        continue;
                    }

                    case token_type::value_float:
                    {
                        const auto res = m_lexer.get_number_float();

                        if (JSON_HEDLEY_UNLIKELY(!std::isfinite(res)))
                        {
                            if (!overflow_error(sax, res, allow_recovery))
                            {
                                return false;
                            }
                            break;
                        }

                        if (JSON_HEDLEY_UNLIKELY(!sax->number_float(res, m_lexer.get_string())))
                        {
                            return false;
                        }

                        break;
                    }

                    case token_type::literal_false:
                    {
                        if (JSON_HEDLEY_UNLIKELY(!sax->boolean(false)))
                        {
                            return false;
                        }
                        break;
                    }

                    case token_type::literal_null:
                    {
                        if (JSON_HEDLEY_UNLIKELY(!sax->null()))
                        {
                            return false;
                        }
                        break;
                    }

                    case token_type::literal_true:
                    {
                        if (JSON_HEDLEY_UNLIKELY(!sax->boolean(true)))
                        {
                            return false;
                        }
                        break;
                    }

                    case token_type::value_integer:
                    {
                        if (JSON_HEDLEY_UNLIKELY(!sax->number_integer(m_lexer.get_number_integer())))
                        {
                            return false;
                        }
                        break;
                    }

                    case token_type::value_string:
                    {
                        if (JSON_HEDLEY_UNLIKELY(!sax->string(m_lexer.get_string())))
                        {
                            return false;
                        }
                        break;
                    }

                    case token_type::value_unsigned:
                    {
                        if (JSON_HEDLEY_UNLIKELY(!sax->number_unsigned(m_lexer.get_number_unsigned())))
                        {
                            return false;
                        }
                        break;
                    }

                    case token_type::parse_error:
                    {
                        // using "uninitialized" to avoid an "expected" message
                        if (!report_error(sax, parse_error::create(101, m_lexer.get_position(), exception_message(token_type::uninitialized, "value"), nullptr), allow_recovery))
                        {
                            return false;
                        }

                        // recover: keep what can be read of the token
                        recover_token();
                        if (last_token != token_type::uninitialized)
                        {
                            // a string or a number
                            continue;
                        }
                        if (states.empty())
                        {
                            // look for the value after the garbage
                            if (!skip_to_value())
                            {
                                return false;
                            }
                            continue;
                        }
                        // nothing could be read
                        if (JSON_HEDLEY_UNLIKELY(!sax->null()))
                        {
                            return false;
                        }
                        break;
                    }
                    case token_type::end_of_input:
                    {
                        if (JSON_HEDLEY_UNLIKELY(m_lexer.get_position().chars_read_total == 1))
                        {
                            // there is nothing to recover
                            static_cast<void>(report_error(sax, parse_error::create(101, m_lexer.get_position(),
                                                           "attempting to parse an empty input; check that your input string or stream contains the expected JSON", nullptr), allow_recovery));
                            return false;
                        }

                        if (!report_error(sax, parse_error::create(101, m_lexer.get_position(), exception_message(token_type::literal_or_value, "value"), nullptr), allow_recovery))
                        {
                            return false;
                        }

                        // recover: the input ends where a value is missing
                        if (states.empty())
                        {
                            // there is no value
                            return false;
                        }
                        if (!recover_missing_value(sax, states))
                        {
                            return false;
                        }
                        // the state evaluation reads the token again
                        m_lexer.unget_token();
                        skip_to_state_evaluation = true;
                        continue;
                    }
                    case token_type::uninitialized:
                    case token_type::end_array:
                    case token_type::end_object:
                    case token_type::name_separator:
                    case token_type::value_separator:
                    case token_type::literal_or_value:
                    default: // the last token was unexpected
                    {
                        if (!report_error(sax, parse_error::create(101, m_lexer.get_position(), exception_message(token_type::literal_or_value, "value"), nullptr), allow_recovery))
                        {
                            return false;
                        }

                        // recover
                        if (states.empty())
                        {
                            // look for the value after the garbage
                            if (!skip_to_value())
                            {
                                return false;
                            }
                            continue;
                        }
                        if (last_token == token_type::name_separator)
                        {
                            // a stray ':'; the value may follow
                            get_token();
                            continue;
                        }
                        if (!recover_missing_value(sax, states))
                        {
                            return false;
                        }
                        // the state evaluation reads the token again
                        m_lexer.unget_token();
                        skip_to_state_evaluation = true;
                        continue;
                    }
                }
            }
            else
            {
                skip_to_state_evaluation = false;
            }

            // we reached this line after we successfully parsed a value
            if (states.empty())
            {
                // empty stack: we reached the end of the hierarchy: done
                return true;
            }

            if (states.back())  // array
            {
                // comma -> next value
                // or end of array (ignore_trailing_commas = true)
                if (get_token() == token_type::value_separator)
                {
                    // parse a new value
                    get_token();

                    // if ignore_trailing_commas and last_token is ], we can continue to "closing ]"
                    if (!(ignore_trailing_commas && last_token == token_type::end_array))
                    {
                        continue;
                    }
                }

                // closing ]
                if (JSON_HEDLEY_LIKELY(last_token == token_type::end_array))
                {
                    if (JSON_HEDLEY_UNLIKELY(!sax->end_array()))
                    {
                        return false;
                    }

                    // We are done with this array. Before we can parse a
                    // new value, we need to evaluate the new state first.
                    // By setting skip_to_state_evaluation to true, the next
                    // iteration skips parsing a value and evaluates the
                    // enclosing state directly.
                    JSON_ASSERT(!states.empty());
                    states.pop_back();
                    skip_to_state_evaluation = true;
                    continue;
                }

                if (!report_error(sax, parse_error::create(101, m_lexer.get_position(), exception_message(token_type::end_array, "array"), nullptr), allow_recovery))
                {
                    return false;
                }

                // recover
                if (last_token == token_type::end_of_input)
                {
                    // the input ends inside the array
                    return close_containers(sax, states);
                }
                if (last_token == token_type::end_object)
                {
                    // a wrong closing bracket closes the innermost container
                    if (JSON_HEDLEY_UNLIKELY(!sax->end_array()))
                    {
                        return false;
                    }
                    states.pop_back();
                    skip_to_state_evaluation = true;
                }
                // otherwise, a missing ',' (or a stray ':', which value
                // parsing drops): the next value begins here
                continue;
            }

            // states.back() is false -> object

            // comma -> next value
            // or end of object (ignore_trailing_commas = true)
            if (get_token() == token_type::value_separator)
            {
                get_token();

                // if ignore_trailing_commas and last_token is }, we can continue to "closing }"
                if (!(ignore_trailing_commas && last_token == token_type::end_object))
                {
                    // parse key
                    if (JSON_HEDLEY_UNLIKELY(last_token != token_type::value_string))
                    {
                        if (!continue_after(key_error(sax, allow_recovery, false), skip_to_state_evaluation))
                        {
                            return false;
                        }
                        continue;
                    }
                    if (JSON_HEDLEY_UNLIKELY(!sax->key(m_lexer.get_string())))
                    {
                        return false;
                    }

                    // parse separator (:)
                    if (JSON_HEDLEY_UNLIKELY(get_token() != token_type::name_separator))
                    {
                        if (!continue_after(key_error(sax, allow_recovery, true), skip_to_state_evaluation))
                        {
                            return false;
                        }
                        continue;
                    }

                    // parse values
                    get_token();
                    continue;
                }
            }

            // closing }
            if (JSON_HEDLEY_LIKELY(last_token == token_type::end_object))
            {
                if (JSON_HEDLEY_UNLIKELY(!sax->end_object()))
                {
                    return false;
                }

                // We are done with this object. Before we can parse a
                // new value, we need to evaluate the new state first.
                // By setting skip_to_state_evaluation to true, the next
                // iteration skips parsing a value and evaluates the
                // enclosing state directly.
                JSON_ASSERT(!states.empty());
                states.pop_back();
                skip_to_state_evaluation = true;
                continue;
            }

            if (!report_error(sax, parse_error::create(101, m_lexer.get_position(), exception_message(token_type::end_object, "object"), nullptr), allow_recovery))
            {
                return false;
            }

            // recover
            if (last_token == token_type::end_of_input)
            {
                // the input ends inside the object
                return close_containers(sax, states);
            }
            if (last_token == token_type::end_array)
            {
                // a wrong closing bracket closes the innermost container
                if (JSON_HEDLEY_UNLIKELY(!sax->end_object()))
                {
                    return false;
                }
                states.pop_back();
                skip_to_state_evaluation = true;
                continue;
            }
            if (!continue_after(recover_member(sax, allow_recovery), skip_to_state_evaluation))
            {
                return false;
            }
        }
    }

    /*!
    @brief continue sax_parse_internal() after a recovery
    @return whether to continue parsing
    */
    bool continue_after(const next_step step, bool& skip_to_state_evaluation)
    {
        if (step == next_step::evaluate_state)
        {
            // the state evaluation reads the token again
            m_lexer.unget_token();
            skip_to_state_evaluation = true;
        }
        return step != next_step::stop;
    }

    /// the parser for parse() and accept() never recovers: stop parsing
    static std::false_type continue_after(std::false_type /*step*/, bool& /*skip_to_state_evaluation*/) noexcept
    {
        return {};
    }

    /*!
    @brief parse an object key and the name separator (:) after it

    last_token is the token where the key is expected. sax_parse_internal()
    repeats these steps rather than calling this function, which is used
    when recovering from an error.

    @return next_step::parse_value if the value follows, with last_token its
            first token; next_step::evaluate_state if the object's state is
            to be evaluated after recovering from an error; next_step::stop
            to stop parsing
    */
    template<typename SAX>
    next_step parse_key(SAX* sax)
    {
        const std::true_type allow_recovery{};

        if (JSON_HEDLEY_UNLIKELY(last_token != token_type::value_string))
        {
            return key_error(sax, allow_recovery, false);
        }

        if (JSON_HEDLEY_UNLIKELY(!sax->key(m_lexer.get_string())))
        {
            return next_step::stop;
        }

        // parse separator (:)
        if (JSON_HEDLEY_UNLIKELY(get_token() != token_type::name_separator))
        {
            return key_error(sax, allow_recovery, true);
        }

        // the value begins with the next token
        get_token();
        return next_step::parse_value;
    }

    /*!
    @brief report a number that is too large for number_float_t, and recover
           from the error by passing the value on; the SAX parser gets the
           number's text as well

    This is a separate function, as reading other numbers is measurably
    slower if the error is handled where they are read.

    @param[in] sax    the SAX parser
    @param[in] value  the value that is not finite
    @return whether to continue parsing
    */
    template<typename SAX, typename AllowRecovery>
    bool overflow_error(SAX* sax, const number_float_t value, AllowRecovery allow_recovery)
    {
        if (!report_error(sax, out_of_range::create(406, concat("number overflow parsing '", m_lexer.get_token_string(), '\''), nullptr), allow_recovery))
        {
            return false;
        }
        return sax->number_float(value, m_lexer.get_string());
    }

    /*!
    @brief report a missing key, or a missing name separator (:) after the
           key; the parser for parse() and accept() never recovers

    @param[in] key_read  whether the key was read, so that the name separator
                         is missing
    @return std::false_type, see report_error()
    */
    template<typename SAX>
    std::false_type key_error(SAX* sax, std::false_type allow_recovery, const bool key_read)
    {
        return report_error(sax, parse_error::create(101, m_lexer.get_position(), key_read
                            ? exception_message(token_type::name_separator, "object separator")
                            : exception_message(token_type::value_string, "object key"), nullptr), allow_recovery);
    }

    /*!
    @brief report a missing key, or a missing name separator (:) after the
           key, and recover from it

    @param[in] key_read  whether the key was read, so that the name separator
                         is missing
    */
    template<typename SAX>
    next_step key_error(SAX* sax, std::true_type allow_recovery, const bool key_read)
    {
        if (!key_read)
        {
            if (!report_error(sax, parse_error::create(101, m_lexer.get_position(), exception_message(token_type::value_string, "object key"), nullptr), allow_recovery))
            {
                return next_step::stop;
            }
            return recover_key(sax);
        }

        if (!report_error(sax, parse_error::create(101, m_lexer.get_position(), exception_message(token_type::name_separator, "object separator"), nullptr), allow_recovery))
        {
            return next_step::stop;
        }
        return recover_name_separator(sax);
    }

    /////////////////////
    // error recovery
    /////////////////////

    /*
    The functions below repair an error after the SAX parser's parse_error()
    returned true (see #3989). Each mistake is repaired by the smallest local
    edit: a missing ',' or ':' is inserted, a stray token is removed, what can
    be read of an invalid string or number is kept (see
    lexer::recover_token()), a missing value becomes null, a wrong closing
    bracket closes the innermost container, and the end of the input closes
    all of them. The events stay balanced, and every key() is followed by
    exactly one value.

    A repair hands a token to the state evaluation, by returning it to the
    lexer (lexer::unget_token()) so that the state evaluation reads it again,
    only if it is ',', ']', '}', or the end of the input. The state evaluation
    hands a token to value or key parsing only if it is none of them, so a
    token is never handed back and forth. Every other step reads a token or
    closes a container, so parsing always ends.
    */

    /*!
    @brief report an error to the SAX parser; the parser for parse() and
           accept() never recovers

    @return std::false_type rather than false: its value is known where the
            function is called even if the call is not inlined, so the code
            for recovering is not generated
    */
    template<typename SAX, typename Exception>
    std::false_type report_error(SAX* sax, const Exception& ex, std::false_type /*allow_recovery*/)
    {
        error_reported = true;
        static_cast<void>(sax->parse_error(m_lexer.get_position(), m_lexer.get_token_string(), ex));
        return {};
    }

    /*!
    @brief report an error to the SAX parser
    @return whether to recover from the error
    */
    template<typename SAX, typename Exception>
    bool report_error(SAX* sax, const Exception& ex, std::true_type /*allow_recovery*/)
    {
        const std::size_t position = m_lexer.get_position().chars_read_total;
        if (error_reported && position == last_error_position && last_token == last_error_token)
        {
            // a repair handed on the token of the error it repaired; the
            // token was reported already, and the SAX parser asked to recover
            return true;
        }

        error_reported = true;
        last_error_position = position;
        last_error_token = last_token;

        if (!sax->parse_error(m_lexer.get_position(), m_lexer.get_token_string(), ex))
        {
            return false;
        }

        // the token string of the next error begins here
        m_lexer.restart_token_string();
        return true;
    }

    /*!
    @brief keep what can be read of the token that the lexer rejected

    The error was reported for the rejected token, so it is not reported again
    for the token it is repaired to (see lexer::recover_token()).
    */
    token_type recover_token()
    {
        last_token = m_lexer.recover_token();
        last_error_position = m_lexer.get_position().chars_read_total;
        last_error_token = last_token;
        return last_token;
    }

    /// pass the end events of all open containers
    template<typename SAX>
    bool close_containers(SAX* sax, std::vector<bool>& states)
    {
        while (!states.empty())
        {
            const bool is_array = states.back();
            states.pop_back();
            if (JSON_HEDLEY_UNLIKELY(is_array ? !sax->end_array() : !sax->end_object()))
            {
                return false;
            }
        }
        return true;
    }

    /*!
    @brief read tokens until one begins a value, skipping everything before
           the top-level value
    @return whether a value begins with last_token
    */
    bool skip_to_value()
    {
        while (true)
        {
            switch (get_token())
            {
                case token_type::begin_array:
                case token_type::begin_object:
                case token_type::literal_false:
                case token_type::literal_null:
                case token_type::literal_true:
                case token_type::value_float:
                case token_type::value_integer:
                case token_type::value_string:
                case token_type::value_unsigned:
                    return true;

                case token_type::end_of_input:
                    return false;

                case token_type::parse_error:
                    recover_token();
                    if (last_token != token_type::uninitialized)
                    {
                        return true;
                    }
                    break;

                case token_type::uninitialized:
                case token_type::end_array:
                case token_type::end_object:
                case token_type::name_separator:
                case token_type::value_separator:
                case token_type::literal_or_value:
                default:
                    break;
            }
        }
    }

    /*!
    @brief skip the rest of an object member that cannot be read

    Reads tokens, beginning with last_token, until a ',', '}', or ']' that is
    not inside a container that begins in the skipped tokens, or the end of
    the input.
    */
    void skip_member()
    {
        std::size_t depth = 0;
        while (true)
        {
            switch (last_token)
            {
                case token_type::begin_array:
                case token_type::begin_object:
                    ++depth;
                    break;

                case token_type::end_array:
                case token_type::end_object:
                    if (depth == 0)
                    {
                        return;
                    }
                    --depth;
                    break;

                case token_type::value_separator:
                    if (depth == 0)
                    {
                        return;
                    }
                    break;

                case token_type::end_of_input:
                    return;

                case token_type::parse_error:
                    recover_token();
                    break;

                case token_type::uninitialized:
                case token_type::literal_true:
                case token_type::literal_false:
                case token_type::literal_null:
                case token_type::value_string:
                case token_type::value_unsigned:
                case token_type::value_integer:
                case token_type::value_float:
                case token_type::name_separator:
                case token_type::literal_or_value:
                default:
                    break;
            }
            get_token();
        }
    }

    /*!
    @brief pass a value where it is missing

    last_token is ',', ']', '}', or the end of the input, where a value was
    expected. In an object, the key gets null; in an array, a ',' where a
    value is missing stands for null (as in JavaScript), while an array that
    ends there just ends.
    */
    template<typename SAX>
    bool recover_missing_value(SAX* sax, const std::vector<bool>& states)
    {
        JSON_ASSERT(!states.empty());
        if (!states.back() || last_token == token_type::value_separator)
        {
            return sax->null();
        }
        return true;
    }

    /// recover from a missing key; last_token is where it was expected
    template<typename SAX>
    next_step recover_key(SAX* sax)
    {
        switch (last_token)
        {
            case token_type::value_separator:
            case token_type::end_object:
            case token_type::end_array:
            case token_type::end_of_input:
                // no member: the object's state handles the token
                return next_step::evaluate_state;

            case token_type::parse_error:
                recover_token();
                if (last_token == token_type::value_string)
                {
                    // a key that could be repaired
                    return parse_key(sax);
                }
                skip_member();
                return next_step::evaluate_state;

            case token_type::uninitialized:
            case token_type::literal_true:
            case token_type::literal_false:
            case token_type::literal_null:
            case token_type::value_string:
            case token_type::value_unsigned:
            case token_type::value_integer:
            case token_type::value_float:
            case token_type::begin_array:
            case token_type::begin_object:
            case token_type::name_separator:
            case token_type::literal_or_value:
            default:
                // a member without a key
                skip_member();
                return next_step::evaluate_state;
        }
    }

    /// recover from a missing name separator (:) after the key; last_token
    /// is where it was expected
    template<typename SAX>
    next_step recover_name_separator(SAX* sax)
    {
        switch (last_token)
        {
            case token_type::value_separator:
            case token_type::end_object:
            case token_type::end_array:
            case token_type::end_of_input:
                // the value is missing as well
                return sax->null() ? next_step::evaluate_state : next_step::stop;

            case token_type::uninitialized:
            case token_type::literal_true:
            case token_type::literal_false:
            case token_type::literal_null:
            case token_type::value_string:
            case token_type::value_unsigned:
            case token_type::value_integer:
            case token_type::value_float:
            case token_type::begin_array:
            case token_type::begin_object:
            case token_type::name_separator:
            case token_type::parse_error:
            case token_type::literal_or_value:
            default:
                // a missing ':'; the value begins here
                return next_step::parse_value;
        }
    }

    /// recover from a token after an object member that is neither ',' nor
    /// '}' (nor ']' or the end of the input, which the caller handles)
    template<typename SAX>
    next_step recover_member(SAX* sax, std::true_type /*allow_recovery*/)
    {
        if (last_token == token_type::parse_error)
        {
            recover_token();
        }
        if (last_token == token_type::value_string)
        {
            // a missing ','; the next key begins here
            return parse_key(sax);
        }
        skip_member();
        return next_step::evaluate_state;
    }

    /// the parser for parse() and accept() never recovers (and does not come
    /// here, as report_error() returned false)
    template<typename SAX>
    std::false_type recover_member(SAX* /*sax*/, std::false_type /*allow_recovery*/) const noexcept
    {
        return {};
    }

    /// get next token from lexer
    token_type get_token()
    {
        return last_token = m_lexer.scan();
    }

    std::string exception_message(const token_type expected, const std::string& context)
    {
        std::string error_msg = "syntax error ";

        if (!context.empty())
        {
            error_msg += concat("while parsing ", context, ' ');
        }

        error_msg += "- ";

        if (last_token == token_type::parse_error)
        {
            error_msg += concat(m_lexer.get_error_message(), "; last read: '",
                                m_lexer.get_token_string(), '\'');
        }
        else
        {
            error_msg += concat("unexpected ", lexer_t::token_type_name(last_token));
        }

        if (expected != token_type::uninitialized)
        {
            error_msg += concat("; expected ", lexer_t::token_type_name(expected));
        }

        return error_msg;
    }

  private:
    /// callback function
    const parser_callback_t<BasicJsonType> callback = nullptr;
    /// the type of the last read token
    token_type last_token = token_type::uninitialized;
    /// the lexer
    lexer_t m_lexer;
    /// whether to throw exceptions in case of errors
    const bool allow_exceptions = true;
    /// whether trailing commas in objects and arrays should be ignored (true) or signaled as errors (false)
    const bool ignore_trailing_commas = false;
    /// whether an error was reported to the SAX parser
    bool error_reported = false;
    /// the position of the last reported error
    std::size_t last_error_position = 0;
    /// the token of the last reported error
    token_type last_error_token = token_type::uninitialized;
};

}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
