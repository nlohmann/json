//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <algorithm> // copy, find_if, min
#include <array> // array
#include <cstddef>
#include <functional> // hash
#include <limits> // numeric_limits
#include <memory> // unique_ptr
#include <new> // operator new
#include <string> // string
#include <type_traits> // enable_if_t
#include <utility> // move, pair
#include <vector> // vector

#include <nlohmann/detail/exceptions.hpp>
#include <nlohmann/detail/input/lexer.hpp>
#include <nlohmann/detail/json_custom_base_class.hpp>
#include <nlohmann/detail/macro_scope.hpp>
#include <nlohmann/detail/meta/cpp_future.hpp>
#include <nlohmann/detail/meta/detected.hpp>
#include <nlohmann/detail/string_concat.hpp>
NLOHMANN_JSON_NAMESPACE_BEGIN

/*!
@brief SAX interface

This class describes the SAX interface used by @ref nlohmann::json::sax_parse.
Each function is called in different situations while the input is parsed. The
boolean return value informs the parser whether to continue processing the
input.
*/
template<typename BasicJsonType>
struct json_sax
{
    using number_integer_t = typename BasicJsonType::number_integer_t;
    using number_unsigned_t = typename BasicJsonType::number_unsigned_t;
    using number_float_t = typename BasicJsonType::number_float_t;
    using string_t = typename BasicJsonType::string_t;
    using binary_t = typename BasicJsonType::binary_t;

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
    @brief a floating-point number was read
    @param[in] val  floating-point value
    @param[in] s    raw token value
    @return whether parsing should proceed
    */
    virtual bool number_float(number_float_t val, const string_t& s) = 0;

    /*!
    @brief a string value was read
    @param[in] val  string value
    @return whether parsing should proceed
    @note It is safe to move the passed string value.
    */
    virtual bool string(string_t& val) = 0;

    /*!
    @brief a binary value was read
    @param[in] val  binary value
    @return whether parsing should proceed
    @note It is safe to move the passed binary value.
    */
    virtual bool binary(binary_t& val) = 0;

    /*!
    @brief the beginning of an object was read
    @param[in] elements  number of object elements or -1 if unknown
    @return whether parsing should proceed
    @note binary formats may report the number of elements
    */
    virtual bool start_object(std::size_t elements) = 0;

    /*!
    @brief an object key was read
    @param[in] val  object key
    @return whether parsing should proceed
    @note It is safe to move the passed string.
    */
    virtual bool key(string_t& val) = 0;

    /*!
    @brief the end of an object was read
    @return whether parsing should proceed
    */
    virtual bool end_object() = 0;

    /*!
    @brief the beginning of an array was read
    @param[in] elements  number of array elements or -1 if unknown
    @return whether parsing should proceed
    @note binary formats may report the number of elements
    */
    virtual bool start_array(std::size_t elements) = 0;

    /*!
    @brief the end of an array was read
    @return whether parsing should proceed
    */
    virtual bool end_array() = 0;

    /*!
    @brief a parse error occurred
    @param[in] position    the position in the input where the error occurs
    @param[in] last_token  the last read token
    @param[in] ex          an exception object describing the error
    @return whether parsing should proceed (must return false)
    */
    virtual bool parse_error(std::size_t position,
                             const std::string& last_token,
                             const detail::exception& ex) = 0;

    json_sax() = default;
    json_sax(const json_sax&) = default;
    json_sax(json_sax&&) noexcept = default;
    json_sax& operator=(const json_sax&) = default;
    json_sax& operator=(json_sax&&) noexcept = default;
    virtual ~json_sax() = default;
};

namespace detail
{
constexpr std::size_t unknown_size()
{
    return (std::numeric_limits<std::size_t>::max)();
}

/*!
@brief reserve capacity for @a len elements in array @a arr

Reserving upfront avoids repeated reallocations while the elements are added,
but the reservation is capped so a bogus/hostile length (which is not bounded
by max_size(), unlike e.g. std::vector) cannot trigger an oversized allocation
for a small or truncated input.

The overload below is selected for array types without reserve() (e.g.,
std::deque), which are then left untouched.
*/
template<typename ArrayType>
auto reserve_array(ArrayType& arr, std::size_t len, priority_tag<1> /*unused*/)
-> decltype(arr.reserve(len), void())
{
    constexpr std::size_t reserve_cap = 16384;
    arr.reserve((std::min)(len, reserve_cap));
}

template<typename ArrayType>
inline void reserve_array(ArrayType& /*arr*/, std::size_t /*len*/, priority_tag<0> /*unused*/)
{}

/*!
@brief reports an object or array whose announced size exceeds max_size()

Shared by json_sax_dom_parser and json_sax_dom_callback_parser.

@param[in] sax   the SAX parser to report the error to
@param[in] len   the number of elements announced by the input, or unknown_size()
@param[in] kind  "object" or "array"
@param[in] ref   the object or array that was just created
@return whether parsing should continue (false after reporting out_of_range.408)
*/
template<typename SAX, typename BasicJsonType>
JSON_HEDLEY_NEVER_INLINE
bool container_too_large_error(SAX& sax, std::size_t len, const char* kind, BasicJsonType* ref)
{
    return sax.parse_error(0, "", out_of_range::create(exception_id::container_too_large, concat("excessive ", kind, " size: ", std::to_string(len)), ref));
}

template<typename SAX, typename BasicJsonType>
bool check_container_size(SAX& sax, std::size_t len, const char* kind, BasicJsonType* ref)
{
    if (JSON_HEDLEY_UNLIKELY(len != detail::unknown_size() && len > ref->max_size()))
    {
        return container_too_large_error(sax, len, kind, ref);
    }
    return true;
}

#if JSON_DIAGNOSTIC_POSITIONS
/*!
@brief set the diagnostic positions of a value the DOM SAX parsers just stored

Shared by json_sax_dom_parser and json_sax_dom_callback_parser. basic_json
befriends this struct, as the position members are private.
*/
struct diagnostic_positions
{
    /*!
    @param[in,out] v  the object or array whose opening brace or bracket was just read
    @param[in] lexer  the lexer that read it, or nullptr to leave @a v alone
    */
    template<typename BasicJsonType, typename LexerType>
    static void set_container_start(BasicJsonType& v, LexerType* lexer)
    {
        if (lexer)
        {
            // Lexer has read the first character of the container, so
            // subtract 1 from the position to get the correct start position.
            v.start_position = lexer->get_chars_read_total() - 1;
        }
    }

    /*!
    @param[in,out] v  the object or array whose closing brace or bracket was just read
    @param[in] lexer  the lexer that read it, or nullptr to leave @a v alone
    */
    template<typename BasicJsonType, typename LexerType>
    static void set_container_end(BasicJsonType& v, LexerType* lexer)
    {
        if (lexer)
        {
            // Lexer's position is past the closing brace or bracket, so set that as the end position.
            v.end_position = lexer->get_chars_read_total();
        }
    }

    /*!
    @param[in,out] v  the value that was just parsed
    @param[in] lexer  the lexer that read it, or nullptr to leave @a v alone
    */
    template<typename BasicJsonType, typename LexerType>
    static void set_from_lexer(BasicJsonType& v, LexerType* lexer)
    {
        if (lexer)
        {
            // Lexer has read past the current field value, so set the end position to the current position.
            // The start position will be set below based on the length of the string representation
            // of the value.
            v.end_position = lexer->get_chars_read_total();

            switch (v.type())
            {
                case value_t::boolean:
                {
                    // 4 and 5 are the string length of "true" and "false"
                    v.start_position = v.end_position - (v.m_data.m_value.boolean ? 4 : 5);
                    break;
                }

                case value_t::null:
                {
                    // 4 is the string length of "null"
                    v.start_position = v.end_position - 4;
                    break;
                }

                case value_t::string:
                {
                    // escape sequences make the token longer than the value it
                    // parses to, so the start position cannot be derived from
                    // the value; use the offset the lexer recorded instead
                    v.start_position = lexer->get_token_start_position();
                    break;
                }

                case value_t::discarded:
                {
                    // an object or array the callback of
                    // json_sax_dom_callback_parser rejected has no position
                    v.end_position = std::string::npos;
                    v.start_position = v.end_position;
                    break;
                }

                case value_t::binary:
                case value_t::number_integer:
                case value_t::number_unsigned:
                case value_t::number_float:
                {
                    v.start_position = v.end_position - lexer->get_string().size();
                    break;
                }

                case value_t::object:
                case value_t::array:
                {
                    // object and array are handled in start_object() and start_array() handlers
                    // skip setting the values here.
                    break;
                }
                default: // LCOV_EXCL_LINE
                    // Handle all possible types discretely, default handler should never be reached.
                    JSON_ASSERT(false); // NOLINT(cert-dcl03-c,hicpp-static-assert,misc-static-assert) LCOV_EXCL_LINE
            }
        }
    }
};
#endif

/*!
@brief error state shared by the DOM-building SAX parsers

Holds whether a parse error occurred and whether errors are thrown, and
implements the parse_error() and is_errored() members of the SAX interface for
json_sax_dom_parser and json_sax_dom_callback_parser.
*/
class json_sax_dom_error_state
{
  public:
    explicit json_sax_dom_error_state(const bool allow_exceptions_) noexcept
        : allow_exceptions(allow_exceptions_)
    {}

    // make class move-only
    json_sax_dom_error_state(const json_sax_dom_error_state&) = delete;
    json_sax_dom_error_state(json_sax_dom_error_state&&) = default; // NOLINT(hicpp-noexcept-move,performance-noexcept-move-constructor)
    json_sax_dom_error_state& operator=(const json_sax_dom_error_state&) = delete;
    json_sax_dom_error_state& operator=(json_sax_dom_error_state&&) = delete; // the const member prevents assignment
    ~json_sax_dom_error_state() = default;

    template<class Exception>
    bool parse_error(std::size_t /*unused*/, const std::string& /*unused*/,
                     const Exception& ex)
    {
        errored = true;
        static_cast<void>(ex);
        if (allow_exceptions)
        {
            JSON_THROW(ex);
        }
        return false;
    }

    bool is_errored() const
    {
        return errored;
    }

  private:
    /// whether a syntax error occurred
    bool errored = false;
    /// whether to throw exceptions in case of errors
    const bool allow_exceptions = true;
};

/*!
@brief a hash table that finds the position of a key in an object whose
       elements are kept in a vector (ordered_map)

The elements stay where they are: the table only holds their hashes and
positions, and the caller compares the keys.
*/
class object_key_index
{
  public:
    static constexpr std::size_t npos = static_cast<std::size_t>(-1);

    /// @param[in] element_hashes  the hashes of the keys of the elements that are there already
    explicit object_key_index(std::vector<std::size_t>&& element_hashes)
        : hashes(std::move(element_hashes))
    {
        std::size_t size = 256;
        while (size < 4 * hashes.size())
        {
            size *= 2;
        }
        rebuild(size);
    }

    /// @return the position of the element with @a hash for which @a matches(position) holds, or npos
    template<typename Matches>
    std::size_t find(const std::size_t hash, Matches matches) const
    {
        for (std::size_t slot = hash & mask;; slot = (slot + 1) & mask)
        {
            const std::size_t entry = table[slot];
            if (entry == 0)
            {
                return npos;
            }
            if (hashes[entry - 1] == hash && matches(entry - 1))
            {
                return entry - 1;
            }
        }
    }

    /// add the next element, whose position is the number of elements so far
    void add(const std::size_t hash)
    {
        hashes.push_back(hash);
        if (hashes.size() * 2 > table.size())
        {
            rebuild(table.size() * 2);
        }
        else
        {
            place(hash, hashes.size());
        }
    }

  private:
    void rebuild(const std::size_t size)
    {
        table.assign(size, 0);
        mask = size - 1;
        for (std::size_t i = 0; i < hashes.size(); ++i)
        {
            place(hashes[i], i + 1);
        }
    }

    void place(const std::size_t hash, const std::size_t entry)
    {
        std::size_t slot = hash & mask;
        while (table[slot] != 0)
        {
            slot = (slot + 1) & mask;
        }
        table[slot] = entry;
    }

    /// the hash of each element, by position
    std::vector<std::size_t> hashes;
    /// open addressing, a power of two in size: position + 1 of an element, or 0 for a free slot
    std::vector<std::size_t> table {}; // NOLINT(readability-redundant-member-init)
    std::size_t mask = 0;
};

/*!
@brief SAX implementation to create a JSON value from SAX events

This class implements the @ref json_sax interface and processes the SAX events
to create a JSON value which makes it basically a DOM parser. The structure or
hierarchy of the JSON value is managed by the stack `frames` which contains
an entry for each open array or object. The parser of the text formats, for
which the size of a container is not known up front, collects the elements of
an array and the members of an `ordered_json` object on a stack and moves them
into a container of the exact size (with @a Collect, as basic_json's own parse
functions use it); the binary readers use the plain
@ref json_sax_dom_binary_parser instead.

After successful parsing, the value that is passed by reference to the
constructor contains the parsed value. Without @a Collect, every value is
stored in place as it arrives, so after a parse error the value holds what was
read up to it.

@tparam BasicJsonType  the JSON type
@tparam Collect  whether to collect the values of containers of unknown size on
                 a stack (only for a caller that does not use the value after a
                 parse error)
*/
template<typename BasicJsonType, typename InputAdapterType, bool Collect = false>
class json_sax_dom_parser : public json_sax_dom_error_state
{
  public:
    using number_integer_t = typename BasicJsonType::number_integer_t;
    using number_unsigned_t = typename BasicJsonType::number_unsigned_t;
    using number_float_t = typename BasicJsonType::number_float_t;
    using string_t = typename BasicJsonType::string_t;
    using binary_t = typename BasicJsonType::binary_t;
    using lexer_t = lexer<BasicJsonType, InputAdapterType>;

    /*!
    @param[in,out] r  reference to a JSON value that is manipulated while
                       parsing
    @param[in] allow_exceptions_  whether parse errors yield exceptions
    */
    explicit json_sax_dom_parser(BasicJsonType& r, const bool allow_exceptions_ = true, lexer_t* lexer_ = nullptr)
        : json_sax_dom_error_state(allow_exceptions_), root(r), m_lexer_ref(lexer_)
    {}

    // make class move-only
    json_sax_dom_parser(const json_sax_dom_parser&) = delete;
    json_sax_dom_parser(json_sax_dom_parser&&) = default; // NOLINT(hicpp-noexcept-move,performance-noexcept-move-constructor)
    json_sax_dom_parser& operator=(const json_sax_dom_parser&) = delete;
    json_sax_dom_parser& operator=(json_sax_dom_parser&&) = default; // NOLINT(hicpp-noexcept-move,performance-noexcept-move-constructor)
    ~json_sax_dom_parser() = default;

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
        // json_sax documents that the passed value may be moved from,
        // so hand the buffer over instead of copying it
        handle_value(std::move(val));
        return true;
    }

    bool binary(binary_t& val)
    {
        // json_sax documents that the passed value may be moved from,
        // so hand the buffer over instead of copying it
        handle_value(std::move(val));
        return true;
    }

    bool start_object(std::size_t len)
    {
#if JSON_DIAGNOSTICS || JSON_DIAGNOSTIC_POSITIONS
        // the values need their final place from the start (their parent
        // pointers and positions refer to it), so no buffering
        return start_stored_object(len);
#else
        return start_object(len, std::integral_constant<bool, indexed_keys> {});
#endif
    }

    bool key(string_t& val)
    {
        JSON_ASSERT(!frames.empty());
        return key(val, std::integral_constant<bool, indexed_keys> {});
    }

    bool end_object()
    {
        JSON_ASSERT(!frames.empty());
        return end_object(std::integral_constant<bool, indexed_keys> {});
    }

    bool start_array(std::size_t len)
    {
        if (JSON_HEDLEY_UNLIKELY(len != detail::unknown_size() && len > array_t().max_size()))
        {
            // the array does not exist yet: report with an empty one
            BasicJsonType too_large(BasicJsonType::value_t::array);
            return container_too_large_error(*this, len, "array", &too_large);
        }

#if JSON_DIAGNOSTICS || JSON_DIAGNOSTIC_POSITIONS
        // the values need their final place from the start (their parent
        // pointers and positions refer to it), so no buffering
        start_stored_array(len);
#else
        if (!collects(len))
        {
            // the number of elements is known (or the elements must be in
            // place as they arrive): store them directly
            start_stored_array(len);
        }
        else
        {
            // the number of elements is not known, so growing the array
            // would reallocate it (and, being a vector, move its elements)
            // again and again. Collect the elements on a stack shared by all
            // arrays instead, and copy them to an array of the exact size
            // when the closing bracket arrives.
            BasicJsonType* slot = nullptr;
            std::size_t dest_member = 0;
            container_destination(slot, dest_member);
            reserve_elements();
            frames.push_back(frame{nullptr, nullptr, slot, elements.size(), ordered_state(dest_member, false)});
            in_object = false;
            stored_array = nullptr;
        }
#endif
        return true;
    }

    bool end_array()
    {
        JSON_ASSERT(!frames.empty());
        JSON_ASSERT(frames.back().object == nullptr);
        const frame f = frames.back();
        frames.pop_back();
        reenter_enclosing_container();

        if (f.array == nullptr)
        {
            // the elements are the top of the shared elements stack, from
            // f.start on (the elements below belong to enclosing arrays that
            // are still open): move them into the array and pop them
            const auto first = elements.begin() + static_cast<std::ptrdiff_t>(f.start);
            auto* const arr = BasicJsonType::template create<array_t>(std::make_move_iterator(first), std::make_move_iterator(elements.end()));
            BasicJsonType value;
            value.m_data.m_value.array = arr;
            value.m_data.m_type = BasicJsonType::value_t::array;
            elements.erase(first, elements.end());

            place_container(f, frames.empty() ? nullptr : &frames.back(), std::move(value), true);
            return true;
        }

#if JSON_DIAGNOSTIC_POSITIONS
        diagnostic_positions::set_container_end(*f.slot, m_lexer_ref);
#endif
#if JSON_DIAGNOSTICS
        f.slot->set_parents();
#endif
        return true;
    }

  private:
    using object_t = typename BasicJsonType::object_t;
    using array_t = typename BasicJsonType::array_t;

    /// whether objects keep their elements in a vector and a key can be hashed,
    /// so that a big object can find the keys it has in a hash table instead of
    /// searching all of them
    template<typename ObjectType, typename StringType>
    using detect_emplace_new_key = decltype(std::declval<ObjectType&>().emplace_new_key(std::declval<const StringType&>(), std::declval<typename ObjectType::mapped_type>()));
    template<typename StringType>
    using detect_hash = decltype(std::hash<StringType>()(std::declval<const StringType&>()));
    // std::hash is only named once the object can hold the keys in a vector:
    // VS 2015 static-asserts on std::hash of a type without one instead of
    // reporting a substitution failure
    template<typename ObjectType, typename StringType, bool = is_detected<detect_emplace_new_key, ObjectType, StringType>::value>
    struct detect_indexable_keys : std::false_type {};
    template<typename ObjectType, typename StringType>
    struct detect_indexable_keys<ObjectType, StringType, true> : is_detected<detect_hash, StringType> {};
    static constexpr bool indexed_keys = detect_indexable_keys<object_t, string_t>::value;

    /// what a frame holds for objects that are kept in a vector: the key index
    /// of an object with many keys, and for an object that is collected on the
    /// stack the member of the enclosing object it will become
    struct ordered_frame
    {
        /// the entry of key_indexes of an object that has one, else nullptr
        object_key_index* index;
        /// object or array without a slot in an object collected on the stack:
        /// the index of the member in `members` it goes to
        std::size_t dest_member;
        /// whether this is an object collected on the stack
        bool buffered;
    };
    struct no_ordered_frame {};
    using ordered_frame_state = typename std::conditional<indexed_keys, ordered_frame, no_ordered_frame>::type;

    static ordered_frame make_ordered_state(const std::size_t dest_member, const bool buffered, std::true_type /*indexed*/) noexcept
    {
        ordered_frame state = {nullptr, dest_member, buffered};
        return state;
    }

    static no_ordered_frame make_ordered_state(const std::size_t /*dest_member*/, const bool /*buffered*/, std::false_type /*indexed*/) noexcept
    {
        return no_ordered_frame();
    }

    static ordered_frame_state ordered_state(const std::size_t dest_member, const bool buffered) noexcept
    {
        return make_ordered_state(dest_member, buffered, std::integral_constant<bool, indexed_keys> {});
    }

    /// an array or object that is being read
    struct frame
    {
        /// the object, or nullptr for an array
        object_t* object;
        /// the array if its elements are stored in it as they arrive, or
        /// nullptr for an array and an object
        array_t* array;
        /// array without `array`: where the finished array goes (nullptr: it
        /// is an element of the enclosing array); otherwise: the value that
        /// holds the object or array
        BasicJsonType* slot;
        /// array without `array`: the index of its first element in `elements`
        std::size_t start;
        /// what objects in a vector add (see ordered_frame)
        ordered_frame_state ordered;
    };

    /// the open arrays and objects; the first few live in the object itself, so
    /// that the common documents do not allocate for them
    class frame_stack
    {
      public:
        frame_stack() noexcept
            : local() // NOLINT(readability-redundant-member-init)
        {}
        frame_stack(const frame_stack&) = delete;
        frame_stack& operator=(const frame_stack&) = delete;

        frame_stack(frame_stack&& other) noexcept
            : local() // NOLINT(readability-redundant-member-init)
        {
            take(other);
        }

        frame_stack& operator=(frame_stack&& other) noexcept
        {
            if (this != &other)
            {
                release();
                take(other);
            }
            return *this;
        }

        ~frame_stack() = default;

        bool empty() const noexcept
        {
            return count == 0;
        }

        std::size_t size() const noexcept
        {
            return count;
        }

        frame& back() noexcept
        {
            return data[count - 1];
        }

        frame& operator[](const std::size_t i) noexcept
        {
            return data[i];
        }

        void push_back(const frame& f)
        {
            if (JSON_HEDLEY_UNLIKELY(count == capacity))
            {
                grow();
            }
            data[count++] = f;
        }

        void pop_back() noexcept
        {
            JSON_ASSERT(count > 0);
            --count;
        }

      private:
        JSON_HEDLEY_NEVER_INLINE
        void grow()
        {
            const std::size_t new_capacity = capacity * 2;
            std::unique_ptr<frame[]> new_heap(new frame[new_capacity]); // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
            for (std::size_t i = 0; i < count; ++i)
            {
                new_heap[i] = data[i];
            }
            heap = std::move(new_heap);
            data = heap.get();
            capacity = new_capacity;
        }

        void release() noexcept
        {
            heap.reset();
            data = local.data();
            capacity = local_capacity;
        }

        /// make the contents of @a other our own
        void take(frame_stack& other) noexcept
        {
            if (other.heap == nullptr)
            {
                for (std::size_t i = 0; i < other.count; ++i)
                {
                    local[i] = other.local[i];
                }
                data = local.data();
                capacity = local_capacity;
            }
            else
            {
                heap = std::move(other.heap);
                data = heap.get();
                capacity = other.capacity;
                other.data = other.local.data();
                other.capacity = local_capacity;
            }
            count = other.count;
            other.count = 0;
        }

        static constexpr std::size_t local_capacity = 8;

        /// the first frames, left uninitialized: a frame is written before it is
        /// read (the user-provided constructor keeps the member initialization,
        /// which -Weffc++ asks for, from zeroing them)
        struct local_frames : std::array<frame, local_capacity>
        {
            local_frames() noexcept {} // NOLINT(modernize-use-equals-default,hicpp-use-equals-default,cppcoreguidelines-pro-type-member-init,hicpp-member-init): see above
        };

        local_frames local;
        /// the frames once there are more than local_capacity of them
        std::unique_ptr<frame[]> heap {}; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays,readability-redundant-member-init)
        frame* data = local.data();
        std::size_t count = 0;
        std::size_t capacity = local_capacity;
    };

    void release_key_index(const frame& f, std::true_type /*indexed*/)
    {
        if (JSON_HEDLEY_UNLIKELY(f.ordered.index != nullptr))
        {
            ordered_data.key_indexes.pop_back();
        }
    }

    static void release_key_index(const frame& /*f*/, std::false_type /*indexed*/) noexcept {}

    /// the number of keys from which an object looks them up in a hash table
    static constexpr std::size_t key_index_threshold = 64;

    /// add @a key to the object of @a f (or find it, if it is there), searching it in std::map
    static BasicJsonType* insert_key(frame& f, string_t&& key, std::false_type /*indexed*/)
    {
        return &f.object->operator[](std::move(key));
    }

    /// add @a key to the object of @a f (or find it, if it is there), searching it in a vector
    BasicJsonType* insert_key(frame& f, string_t&& key, std::true_type /*indexed*/)
    {
        object_t& obj = *f.object;
        if (JSON_HEDLEY_LIKELY(obj.size() < key_index_threshold))
        {
            return &obj[std::move(key)];
        }
        return insert_key_with_index(f, std::move(key));
    }

    /// add @a key to the big object of @a f (or find it, if it is there), using its key index
    JSON_HEDLEY_NEVER_INLINE
    BasicJsonType* insert_key_with_index(frame& f, string_t&& key)
    {
        object_t& obj = *f.object;
        const std::hash<string_t> hasher {};
        const std::size_t hash = hasher(key);
        if (JSON_HEDLEY_UNLIKELY(f.ordered.index == nullptr))
        {
            std::vector<std::size_t> hashes;
            hashes.reserve(obj.size());
            for (const auto& element : obj)
            {
                hashes.push_back(hasher(element.first));
            }
            ordered_data.key_indexes.emplace_back(new object_key_index(std::move(hashes)));
            f.ordered.index = ordered_data.key_indexes.back().get();
        }

        const std::size_t position = f.ordered.index->find(hash, [&obj, &key](std::size_t i)
        {
            return (obj.begin() + static_cast<std::ptrdiff_t>(i))->first == key;
        });
        if (position != object_key_index::npos)
        {
            return &(obj.begin() + static_cast<std::ptrdiff_t>(position))->second;
        }

        obj.emplace_new_key(key, BasicJsonType());
        f.ordered.index->add(hash);
        return &obj.back().second;
    }

    /// where an array or object that starts now will go when it is finished:
    /// @a slot is the value to assign it to (the root or a member of an object
    /// that is stored directly), or nullptr if it is an element of the
    /// enclosing array or a member of the enclosing object that is collected on
    /// the stack, in which case @a dest_member is the member
    void container_destination(BasicJsonType*& slot, std::size_t& dest_member)
    {
        if (frames.empty())
        {
            slot = &root;
        }
        else if (frames.back().object != nullptr)
        {
            slot = object_element;
        }
        else
        {
            collected_object_member(frames.back(), dest_member, std::integral_constant<bool, indexed_keys> {});
        }
    }

    void collected_object_member(const frame& enclosing, std::size_t& dest_member, std::true_type /*indexed*/) const noexcept
    {
        if (enclosing.ordered.buffered)
        {
            dest_member = ordered_data.member_index;
        }
    }

    static void collected_object_member(const frame& /*enclosing*/, std::size_t& /*dest_member*/, std::false_type /*indexed*/) noexcept {}

    static bool is_collected_object(const frame& f, std::true_type /*indexed*/) noexcept
    {
        return f.ordered.buffered;
    }

    static bool is_collected_object(const frame& /*f*/, std::false_type /*indexed*/) noexcept
    {
        return false;
    }

    /// put a finished array or object that was collected on the stack, or
    /// that outgrew it, where it belongs; @a enclosing is the container it is in.
    /// @a enclosing_is_innermost tells whether that is the container that gets
    /// the next value, so that it can be switched to storing its elements
    /// directly if the value was the one too many.
    void place_container(const frame& f, frame* enclosing, BasicJsonType&& value, const bool enclosing_is_innermost)
    {
        // only a container with a slot may have no enclosing container
        JSON_ASSERT(f.slot != nullptr || enclosing != nullptr);
        if (f.slot != nullptr)
        {
            *f.slot = std::move(value);
        }
        else if (is_collected_object(*enclosing, std::integral_constant<bool, indexed_keys> {}))
        {
            place_member(f, std::move(value), std::integral_constant<bool, indexed_keys> {});
        }
        else if (enclosing->array != nullptr)
        {
            enclosing->array->emplace_back(std::move(value));
        }
        else
        {
            elements.emplace_back(std::move(value));
            if (JSON_HEDLEY_UNLIKELY(enclosing_is_innermost && elements.size() - enclosing->start > buffer_limit))
            {
                spill(*enclosing);
            }
        }
    }

    void place_member(const frame& f, BasicJsonType&& value, std::true_type /*indexed*/)
    {
        ordered_data.members[f.ordered.dest_member].second = std::move(value);
    }

    static void place_member(const frame& /*f*/, BasicJsonType&& /*value*/, std::false_type /*indexed*/) noexcept {}

    /// store the members of a new object directly in it
    bool start_stored_object(std::size_t len)
    {
        BasicJsonType* const ref = store(BasicJsonType::value_t::object);
        frames.push_back(frame{ref->m_data.m_value.object, nullptr, ref, 0, ordered_state(0, false)});
        in_object = true;
        stored_array = nullptr;

#if JSON_DIAGNOSTIC_POSITIONS
        // Ensure this is after the call to store to ensure correct start position.
        diagnostic_positions::set_container_start(*ref, m_lexer_ref);
#endif

        return check_container_size(*this, len, "object", ref);
    }

    /// objects in std::map and the like have no use for collecting their members
    bool start_object(std::size_t len, std::false_type /*indexed*/)
    {
        return start_stored_object(len);
    }

    /// An object in a vector of members adds a member by appending it to the
    /// vector, which grows it again and again (and copies the keys each time).
    /// Collect the members of an object of unknown size on a stack shared by
    /// all open objects instead, and move them into a vector of the exact size
    /// when the closing brace arrives.
    bool start_object(std::size_t len, std::true_type /*indexed*/)
    {
        if (!collects(len))
        {
            return start_stored_object(len);
        }

        BasicJsonType* slot = nullptr;
        std::size_t dest_member = 0;
        container_destination(slot, dest_member);
        frames.push_back(frame{nullptr, nullptr, slot, ordered_data.members.size(), ordered_state(dest_member, true)});
        in_object = false;
        stored_array = nullptr;
        return true;
    }

    bool key(string_t& val, std::false_type /*indexed*/)
    {
        JSON_ASSERT(frames.back().object != nullptr);

        // add null at the given key and store the reference for later; the
        // key is moved, as the lexer starts the next token with reset()
        object_element = insert_key(frames.back(), std::move(val), std::false_type {});
        return true;
    }

    bool key(string_t& val, std::true_type /*indexed*/)
    {
        frame& f = frames.back();
        if (JSON_HEDLEY_UNLIKELY(f.object == nullptr))
        {
            JSON_ASSERT(f.ordered.buffered);
            if (collect_member(f, val))
            {
                return true;
            }
            // the object has grown big: it is stored directly from here on
        }
        object_element = insert_key(f, std::move(val), std::true_type {});
        return true;
    }

    /*!
    @brief add a member to the object that is collected on the stack, or find the one with the key
    @return false if the object has collected enough members to be stored
            directly, which is done and which leaves the key to be inserted
    */
    bool collect_member(frame& f, string_t& key)
    {
        for (std::size_t i = f.start; i < ordered_data.members.size(); ++i)
        {
            if (ordered_data.members[i].first == key)
            {
                ordered_data.member_index = i;
                return true;
            }
        }

        if (JSON_HEDLEY_UNLIKELY(ordered_data.members.size() - f.start >= object_buffer_limit))
        {
            spill_object(f);
            return false;
        }

        reserve_members();
        ordered_data.members.emplace_back(std::move(key), BasicJsonType());
        ordered_data.member_index = ordered_data.members.size() - 1;
        return true;
    }

    /// the members of an object that is collected on the stack as an object;
    /// they are the top of the shared member stack, from f.start on (the
    /// members below belong to enclosing objects that are still open)
    object_t* members_to_object(const frame& f, BasicJsonType& value)
    {
        const auto first = ordered_data.members.begin() + static_cast<std::ptrdiff_t>(f.start);
        auto* const obj = BasicJsonType::template create<object_t>(std::make_move_iterator(first), std::make_move_iterator(ordered_data.members.end()));
        value.m_data.m_value.object = obj;
        value.m_data.m_type = BasicJsonType::value_t::object;
        ordered_data.members.erase(first, ordered_data.members.end());
        return obj;
    }

    /// switch an object that collects its members on the stack to storing them directly
    JSON_HEDLEY_NEVER_INLINE
    void spill_object(frame& f)
    {
        BasicJsonType value;
        f.object = members_to_object(f, value);
        f.ordered.buffered = false;
        in_object = true;
        // false positive: an object without an enclosing container is the root,
        // which has a slot, so place_container() does not use the nullptr
        // @infer-ignore NULLPTR_DEREFERENCE
        place_container(f, frames.size() >= 2 ? &frames[frames.size() - 2] : nullptr, std::move(value), false);
    }

    bool end_object(std::false_type /*indexed*/)
    {
        return end_stored_object();
    }

    bool end_object(std::true_type /*indexed*/)
    {
        if (JSON_HEDLEY_LIKELY(frames.back().object != nullptr))
        {
            return end_stored_object();
        }

        // the members are on the stack: make them the object
        const frame f = frames.back();
        frames.pop_back();
        reenter_enclosing_container();

        BasicJsonType value;
        members_to_object(f, value);
        place_container(f, frames.empty() ? nullptr : &frames.back(), std::move(value), true);
        return true;
    }

    bool end_stored_object()
    {
        JSON_ASSERT(frames.back().object != nullptr);

#if JSON_DIAGNOSTICS || JSON_DIAGNOSTIC_POSITIONS
        // objects are never collected, so their value is where it was stored
        BasicJsonType* const ref = frames.back().slot;
#endif
#if JSON_DIAGNOSTIC_POSITIONS
        diagnostic_positions::set_container_end(*ref, m_lexer_ref);
#endif
#if JSON_DIAGNOSTICS
        ref->set_parents();
#endif

        release_key_index(frames.back(), std::integral_constant<bool, indexed_keys> {});
        frames.pop_back();
        reenter_enclosing_container();
        return true;
    }

    /// the number of members an object collects on the stack before it
    /// switches to storing them directly
    static constexpr std::size_t object_buffer_limit = 32;

    void reserve_members()
    {
        if (JSON_HEDLEY_UNLIKELY(ordered_data.members.capacity() == 0))
        {
            ordered_data.members.reserve(16);
        }
    }

    /// the number of elements an array collects on the stack before it
    /// switches to storing them directly, so that it does not hold up the
    /// stack with its elements (and move all of them in the end)
    static constexpr std::size_t buffer_limit = 16;

    void reserve_elements()
    {
        if (JSON_HEDLEY_UNLIKELY(elements.capacity() == 0))
        {
            elements.reserve(32);
        }
    }

    /// store the elements of a new array directly in it
    void start_stored_array(const std::size_t len)
    {
        BasicJsonType* const ref = store(BasicJsonType::value_t::array);
        frames.push_back(frame{nullptr, ref->m_data.m_value.array, ref, 0, ordered_state(0, false)});
        in_object = false;
        stored_array = ref->m_data.m_value.array;

#if JSON_DIAGNOSTIC_POSITIONS
        // Ensure this is after the call to store to ensure correct start position.
        diagnostic_positions::set_container_start(*ref, m_lexer_ref);
#endif

        if (len != detail::unknown_size())
        {
            reserve_array(*ref->m_data.m_value.array, len, priority_tag<1> {});
        }
    }

    /*!
    @brief store a value as the next element of the open array or object (or
           as the root)
    @return the stored value
    */
    template<typename Value>
    JSON_HEDLEY_RETURNS_NON_NULL
    BasicJsonType* store(Value&& v)
    {
        if (stored_array != nullptr)
        {
            stored_array->emplace_back(std::forward<Value>(v));
            return &stored_array->back();
        }

        if (in_object)
        {
            JSON_ASSERT(object_element);
            set_member(*object_element, std::forward<Value>(v), std::is_same<typename BasicJsonType::json_base_class_t, json_default_base> {});
            return object_element;
        }

        return store_collected(std::forward<Value>(v), std::integral_constant<bool, indexed_keys> {});
    }

    /// store a value that is the root, an element of an array that is collected
    /// on the stack, or (in a vector) a member of an object that is
    template<typename Value>
    BasicJsonType* store_collected(Value&& v, std::true_type /*indexed*/)
    {
        if (!frames.empty() && frames.back().ordered.buffered)
        {
            BasicJsonType& member = ordered_data.members[ordered_data.member_index].second;
            set_member(member, std::forward<Value>(v), std::is_same<typename BasicJsonType::json_base_class_t, json_default_base> {});
            return &member;
        }
        return store_collected(std::forward<Value>(v), std::false_type {});
    }

    template<typename Value>
    BasicJsonType* store_collected(Value&& v, std::false_type /*indexed*/)
    {
        if (frames.empty())
        {
            root = BasicJsonType(std::forward<Value>(v));
            return &root;
        }

        frame& f = frames.back();
        elements.emplace_back(std::forward<Value>(v));
        if (JSON_HEDLEY_UNLIKELY(elements.size() - f.start > buffer_limit))
        {
            return spill(f);
        }
        return &elements.back();
    }

    /*!
    @brief switch an array that collects its elements on the stack to storing
           them directly
    @return the last element of the array
    */
    JSON_HEDLEY_NEVER_INLINE
    BasicJsonType* spill(frame& f)
    {
        JSON_ASSERT(f.array == nullptr);
        const auto first = elements.begin() + static_cast<std::ptrdiff_t>(f.start);
        BasicJsonType value(BasicJsonType::value_t::array);
        array_t& arr = *value.m_data.m_value.array;
        // the capacity a vector that grew by itself has with this many elements
        reserve_array(arr, 2 * buffer_limit, priority_tag<1> {});
        arr.insert(arr.end(), std::make_move_iterator(first), std::make_move_iterator(elements.end()));
        elements.erase(first, elements.end());
        f.array = &arr;
        stored_array = &arr;

        // the array takes the place its first element had on the stack
        place_container(f, frames.size() >= 2 ? &frames[frames.size() - 2] : nullptr, std::move(value), false);
        return &arr.back();
    }

    /// set the value of the member key() just added
    template<typename Value>
    JSON_HEDLEY_ALWAYS_INLINE
    static void set_member(BasicJsonType& member, Value&& v, std::true_type /*default base*/)
    {
        if (JSON_HEDLEY_LIKELY(member.is_null()))
        {
            // a new member is null and holds nothing: construct the value
            // over it instead of destroying and swapping
            ::new (static_cast<void*>(&member)) BasicJsonType(std::forward<Value>(v));
        }
        else
        {
            // the key occurred before
            member = BasicJsonType(std::forward<Value>(v));
        }
    }

    /// a custom base class may care about the lifetime of the value
    template<typename Value>
    static void set_member(BasicJsonType& member, Value&& v, std::false_type /*custom base*/)
    {
        member = BasicJsonType(std::forward<Value>(v));
    }

    /// whether the values of a container of @a len elements are collected on the stack
    static bool collects(const std::size_t len) noexcept
    {
        return collects(len, std::integral_constant<bool, Collect> {});
    }

    static bool collects(const std::size_t len, std::true_type /*collect*/) noexcept
    {
        return len == detail::unknown_size();
    }

    static bool collects(const std::size_t /*len*/, std::false_type /*collect*/) noexcept
    {
        return false;
    }

    /// after a container was closed: the one it was in is the one that gets the next value
    void reenter_enclosing_container()
    {
        if (frames.empty())
        {
            in_object = false;
            stored_array = nullptr;
        }
        else
        {
            const frame& f = frames.back();
            in_object = f.object != nullptr;
            stored_array = f.array;
        }
    }

    template<typename Value>
    void handle_value(Value&& v)
    {
#if JSON_DIAGNOSTIC_POSITIONS
        BasicJsonType* const stored = store(std::forward<Value>(v));
        diagnostic_positions::set_from_lexer(*stored, m_lexer_ref);
#else
        store(std::forward<Value>(v));
#endif
    }

    /// the parsed JSON value
    BasicJsonType& root;
    /// the open arrays and objects
    frame_stack frames {};
    /// the elements of the open arrays that are not stored in them yet
    std::vector<BasicJsonType> elements {};
    /// what objects in a vector need besides the frames (std::map based objects
    /// need nothing, so they do not carry it)
    struct ordered_data_t
    {
        /// the members of the open objects in a vector that are not stored in them yet
        std::vector<std::pair<string_t, BasicJsonType>> members {};
        /// the member of the innermost such object that key() added or found last
        std::size_t member_index = 0;
        /// the key indexes of the open objects that have one, innermost last
        std::vector<std::unique_ptr<object_key_index>> key_indexes {}; // NOLINT(readability-redundant-member-init)
    };
    struct no_ordered_data_t {};
    typename std::conditional<indexed_keys, ordered_data_t, no_ordered_data_t>::type ordered_data {};
    /// helper to hold the reference for the next object element
    BasicJsonType* object_element = nullptr;
    /// whether the innermost container is an object (frames.back().object)
    bool in_object = false;
    /// the array that stores the elements of the innermost array as they
    /// arrive (frames.back().array), or nullptr
    array_t* stored_array = nullptr;
    /// the lexer reference to obtain the current position
    lexer_t* m_lexer_ref = nullptr;
};

/*!
@brief SAX implementation to create a JSON value from the events of a binary reader

The DOM parser of the text formats (json_sax_dom_parser) collects the elements
of arrays and the members of objects on a stack and builds them in one
exact-size allocation, which pays off because a text parser does not know the
number of elements up front. Binary formats announce the size of their
containers (CBOR, MessagePack, BSON and BON8 do, and so do the optimized
containers of UBJSON and BJData), so they store each value directly in its
container, and the bookkeeping of the collecting parser would be pure
overhead for them. This is the plain parser: the structure or hierarchy of the
JSON value is managed by the stack `ref_stack` which contains a pointer to the
respective array or object for each recursion depth.

After successful parsing, the value that is passed by reference to the
constructor contains the parsed value.

@tparam BasicJsonType  the JSON type
*/
template<typename BasicJsonType, typename InputAdapterType>
class json_sax_dom_binary_parser : public json_sax_dom_error_state
{
  public:
    using number_integer_t = typename BasicJsonType::number_integer_t;
    using number_unsigned_t = typename BasicJsonType::number_unsigned_t;
    using number_float_t = typename BasicJsonType::number_float_t;
    using string_t = typename BasicJsonType::string_t;
    using binary_t = typename BasicJsonType::binary_t;
    using lexer_t = lexer<BasicJsonType, InputAdapterType>;

    /*!
    @param[in,out] r  reference to a JSON value that is manipulated while
                       parsing
    @param[in] allow_exceptions_  whether parse errors yield exceptions
    */
    explicit json_sax_dom_binary_parser(BasicJsonType& r, const bool allow_exceptions_ = true, lexer_t* lexer_ = nullptr)
        : json_sax_dom_error_state(allow_exceptions_), root(r), m_lexer_ref(lexer_)
    {}

    // make class move-only
    json_sax_dom_binary_parser(const json_sax_dom_binary_parser&) = delete;
    json_sax_dom_binary_parser(json_sax_dom_binary_parser&&) = default; // NOLINT(hicpp-noexcept-move,performance-noexcept-move-constructor)
    json_sax_dom_binary_parser& operator=(const json_sax_dom_binary_parser&) = delete;
    json_sax_dom_binary_parser& operator=(json_sax_dom_binary_parser&&) = default; // NOLINT(hicpp-noexcept-move,performance-noexcept-move-constructor)
    ~json_sax_dom_binary_parser() = default;

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
        // json_sax documents that the passed value may be moved from,
        // so hand the buffer over instead of copying it
        handle_value(std::move(val));
        return true;
    }

    bool binary(binary_t& val)
    {
        // json_sax documents that the passed value may be moved from,
        // so hand the buffer over instead of copying it
        handle_value(std::move(val));
        return true;
    }

    bool start_object(std::size_t len)
    {
        ref_stack.push_back(handle_value(BasicJsonType::value_t::object));

#if JSON_DIAGNOSTIC_POSITIONS
        // Ensure this is after the call to handle_value to ensure correct start position.
        diagnostic_positions::set_container_start(*ref_stack.back(), m_lexer_ref);
#endif

        return check_container_size(*this, len, "object", ref_stack.back());
    }

    bool key(string_t& val)
    {
        JSON_ASSERT(!ref_stack.empty());
        JSON_ASSERT(ref_stack.back()->is_object());

        // add null at the given key and store the reference for later; the
        // key is moved, as the lexer starts the next token with reset()
        object_element = &(ref_stack.back()->m_data.m_value.object->operator[](std::move(val)));
        return true;
    }

    bool end_object()
    {
        JSON_ASSERT(!ref_stack.empty());
        JSON_ASSERT(ref_stack.back()->is_object());

#if JSON_DIAGNOSTIC_POSITIONS
        diagnostic_positions::set_container_end(*ref_stack.back(), m_lexer_ref);
#endif

        ref_stack.back()->set_parents();
        ref_stack.pop_back();
        return true;
    }

    bool start_array(std::size_t len)
    {
        ref_stack.push_back(handle_value(BasicJsonType::value_t::array));

#if JSON_DIAGNOSTIC_POSITIONS
        // Ensure this is after the call to handle_value to ensure correct start position.
        diagnostic_positions::set_container_start(*ref_stack.back(), m_lexer_ref);
#endif

        if (JSON_HEDLEY_UNLIKELY(!check_container_size(*this, len, "array", ref_stack.back())))
        {
            return false;
        }

        if (len != detail::unknown_size())
        {
            reserve_array(*ref_stack.back()->m_data.m_value.array, len, priority_tag<1> {});
        }

        return true;
    }

    bool end_array()
    {
        JSON_ASSERT(!ref_stack.empty());
        JSON_ASSERT(ref_stack.back()->is_array());

#if JSON_DIAGNOSTIC_POSITIONS
        diagnostic_positions::set_container_end(*ref_stack.back(), m_lexer_ref);
#endif

        ref_stack.back()->set_parents();
        ref_stack.pop_back();
        return true;
    }

  private:

    /*!
    @invariant If the ref stack is empty, then the passed value will be the new
               root.
    @invariant If the ref stack contains a value, then it is an array or an
               object to which we can add elements
    */
    template<typename Value>
    JSON_HEDLEY_RETURNS_NON_NULL
    BasicJsonType* handle_value(Value&& v)
    {
        if (ref_stack.empty())
        {
            root = BasicJsonType(std::forward<Value>(v));

#if JSON_DIAGNOSTIC_POSITIONS
            diagnostic_positions::set_from_lexer(root, m_lexer_ref);
#endif

            return &root;
        }

        JSON_ASSERT(ref_stack.back()->is_array() || ref_stack.back()->is_object());

        if (ref_stack.back()->is_array())
        {
            ref_stack.back()->m_data.m_value.array->emplace_back(std::forward<Value>(v));

#if JSON_DIAGNOSTIC_POSITIONS
            diagnostic_positions::set_from_lexer(ref_stack.back()->m_data.m_value.array->back(), m_lexer_ref);
#endif

            return &(ref_stack.back()->m_data.m_value.array->back());
        }

        JSON_ASSERT(ref_stack.back()->is_object());
        JSON_ASSERT(object_element);
        *object_element = BasicJsonType(std::forward<Value>(v));

#if JSON_DIAGNOSTIC_POSITIONS
        diagnostic_positions::set_from_lexer(*object_element, m_lexer_ref);
#endif

        return object_element;
    }

    /// the parsed JSON value
    BasicJsonType& root;
    /// stack to model hierarchy of values
    std::vector<BasicJsonType*> ref_stack {};
    /// helper to hold the reference for the next object element
    BasicJsonType* object_element = nullptr;
    /// the lexer reference to obtain the current position
    lexer_t* m_lexer_ref = nullptr;
};

template<typename BasicJsonType, typename InputAdapterType>
class json_sax_dom_callback_parser : public json_sax_dom_error_state
{
  public:
    using number_integer_t = typename BasicJsonType::number_integer_t;
    using number_unsigned_t = typename BasicJsonType::number_unsigned_t;
    using number_float_t = typename BasicJsonType::number_float_t;
    using string_t = typename BasicJsonType::string_t;
    using binary_t = typename BasicJsonType::binary_t;
    using parser_callback_t = typename BasicJsonType::parser_callback_t;
    using parse_event_t = typename BasicJsonType::parse_event_t;
    using lexer_t = lexer<BasicJsonType, InputAdapterType>;

    json_sax_dom_callback_parser(BasicJsonType& r,
                                 parser_callback_t cb,
                                 const bool allow_exceptions_ = true,
                                 lexer_t* lexer_ = nullptr)
        : json_sax_dom_error_state(allow_exceptions_), root(r), callback(std::move(cb)), m_lexer_ref(lexer_)
    {
        keep_stack.push_back(true);
    }

    // make class move-only
    json_sax_dom_callback_parser(const json_sax_dom_callback_parser&) = delete;
    json_sax_dom_callback_parser(json_sax_dom_callback_parser&&) = default; // NOLINT(hicpp-noexcept-move,performance-noexcept-move-constructor)
    json_sax_dom_callback_parser& operator=(const json_sax_dom_callback_parser&) = delete;
    json_sax_dom_callback_parser& operator=(json_sax_dom_callback_parser&&) = default; // NOLINT(hicpp-noexcept-move,performance-noexcept-move-constructor)
    ~json_sax_dom_callback_parser() = default;

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
        // json_sax documents that the passed value may be moved from,
        // so hand the buffer over instead of copying it
        handle_value(std::move(val));
        return true;
    }

    bool binary(binary_t& val)
    {
        // json_sax documents that the passed value may be moved from,
        // so hand the buffer over instead of copying it
        handle_value(std::move(val));
        return true;
    }

    bool start_object(std::size_t len)
    {
        // check callback for object start; not called inside a discarded container
        const bool keep = keep_stack.back() && callback(static_cast<int>(ref_stack.size()), parse_event_t::object_start, discarded);
        keep_stack.push_back(keep);

        // the key this object will be stored under, read before handle_value()
        // may consume it; kept in lockstep with ref_stack so end_object() can
        // find the object in its parent again
        container_key_stack.push_back(current_key());

        auto val = handle_value(BasicJsonType::value_t::object, true);
        ref_stack.push_back(val.second);

        if (ref_stack.back())
        {

#if JSON_DIAGNOSTIC_POSITIONS
            // Ensure this is after the call to handle_value to ensure correct start position.
            diagnostic_positions::set_container_start(*ref_stack.back(), m_lexer_ref);
#endif

            return check_container_size(*this, len, "object", ref_stack.back());
        }
        return true;
    }

    bool key(string_t& val)
    {
        if (!keep_stack.back() || !ref_stack.back())
        {
            // the object is not stored: the value of this key is dropped in
            // handle_value() without touching the key stacks
            if (keep_stack.back())
            {
                static_cast<void>(callback(static_cast<int>(ref_stack.size()), parse_event_t::key, key_value(val)));
            }
            return true;
        }

        // check callback for the key
        const bool keep = callback(static_cast<int>(ref_stack.size()), parse_event_t::key, key_value(val));
        key_keep_stack.push_back(keep);
        // remember the key so a rejected value can be erased without searching
        // the object for it (kept in lockstep with key_keep_stack)
        key_stack.push_back(val);

        // add discarded value at the given key and store the reference for later
        if (keep && ref_stack.back())
        {
            auto& obj = *ref_stack.back()->m_data.m_value.object;
            // a single lookup: insert the placeholder, or find the existing member
            const auto inserted = obj.emplace(std::move(val), discarded);
            const auto it = inserted.first;
            if (!inserted.second)
            {
                // this is a duplicate key (legal in JSON); remember its
                // current value so it can be restored later if the new
                // value is rejected by the callback, instead of being
                // erased together with the discarded placeholder
                duplicate_key_stash.emplace_back(&(it->second), it->second);
                it->second = discarded;
            }
            object_element = &(it->second);
        }

        return true;
    }

    bool end_object()
    {
        if (ref_stack.back())
        {
            if (!callback(static_cast<int>(ref_stack.size()) - 1, parse_event_t::object_end, *ref_stack.back()))
            {
                // discard object, unless this slot holds a duplicate key's
                // previous value pending restoration, in which case that
                // value is restored instead of being discarded
                if (!resolve_duplicate_key_stash(ref_stack.back(), true))
                {
                    *ref_stack.back() = discarded;

#if JSON_DIAGNOSTIC_POSITIONS
                    // Set start/end positions for discarded object.
                    diagnostic_positions::set_from_lexer(*ref_stack.back(), m_lexer_ref);
#endif
                }
            }
            else
            {

#if JSON_DIAGNOSTIC_POSITIONS
                diagnostic_positions::set_container_end(*ref_stack.back(), m_lexer_ref);
#endif

                ref_stack.back()->set_parents();
                // this object is finally, definitively kept; drop any
                // pending duplicate-key stash entry for its slot since it
                // can no longer be restored
                resolve_duplicate_key_stash(ref_stack.back(), false);
            }
        }

        const string_t object_key = pop_container();

        if (!ref_stack.empty() && ref_stack.back() && ref_stack.back()->is_structured())
        {
            // remove discarded value
            remove_discarded_value(*ref_stack.back(), object_key);
        }

        return true;
    }

    bool start_array(std::size_t len)
    {
        const bool keep = keep_stack.back() && callback(static_cast<int>(ref_stack.size()), parse_event_t::array_start, discarded);
        keep_stack.push_back(keep);

        // see start_object()
        container_key_stack.push_back(current_key());

        auto val = handle_value(BasicJsonType::value_t::array, true);
        ref_stack.push_back(val.second);

        if (ref_stack.back())
        {

#if JSON_DIAGNOSTIC_POSITIONS
            // Ensure this is after the call to handle_value to ensure correct start position.
            diagnostic_positions::set_container_start(*ref_stack.back(), m_lexer_ref);
#endif

            if (JSON_HEDLEY_UNLIKELY(!check_container_size(*this, len, "array", ref_stack.back())))
            {
                return false;
            }

            if (len != detail::unknown_size())
            {
                reserve_array(*ref_stack.back()->m_data.m_value.array, len, priority_tag<1> {});
            }
        }

        return true;
    }

    bool end_array()
    {
        bool keep = true;
        const bool stored = ref_stack.back() != nullptr;

        if (stored)
        {
            keep = callback(static_cast<int>(ref_stack.size()) - 1, parse_event_t::array_end, *ref_stack.back());
            if (keep)
            {

#if JSON_DIAGNOSTIC_POSITIONS
                diagnostic_positions::set_container_end(*ref_stack.back(), m_lexer_ref);
#endif

                ref_stack.back()->set_parents();
                // this array is finally, definitively kept; drop any
                // pending duplicate-key stash entry for its slot since it
                // can no longer be restored
                resolve_duplicate_key_stash(ref_stack.back(), false);
            }
            else
            {
                // discard array, unless this slot holds a duplicate key's
                // previous value pending restoration, in which case that
                // value is restored instead of being discarded
                if (!resolve_duplicate_key_stash(ref_stack.back(), true))
                {
                    *ref_stack.back() = discarded;

#if JSON_DIAGNOSTIC_POSITIONS
                    // Set start/end positions for discarded array.
                    diagnostic_positions::set_from_lexer(*ref_stack.back(), m_lexer_ref);
#endif
                }
            }
        }

        const string_t object_key = pop_container();

        // remove discarded value
        if (!ref_stack.empty() && ref_stack.back())
        {
            if (!keep && ref_stack.back()->is_array())
            {
                ref_stack.back()->m_data.m_value.array->pop_back();
            }
            else if ((!keep || !stored) && ref_stack.back()->is_object())
            {
                // the array is either still stored under its key or was never
                // stored, leaving the placeholder key() wrote; both show up as
                // a discarded member of the parent object
                remove_discarded_value(*ref_stack.back(), object_key);
            }
        }

        return true;
    }

  private:

    /*!
    @brief the value of a key event for the callback

    A string value of its own for every key would allocate it every time, so
    one is kept and set to the key. A callback that changed or moved it gets a
    new one, as it would have got a new value for every key anyway.
    */
    BasicJsonType& key_value(const string_t& key)
    {
#if JSON_DIAGNOSTIC_POSITIONS
        // a callback may have left positions on the value
        key_scratch = BasicJsonType(key);
#else
        if (JSON_HEDLEY_LIKELY(key_scratch.is_string()))
        {
            *key_scratch.m_data.m_value.string = key;
        }
        else
        {
            key_scratch = BasicJsonType(key);
        }
#endif
        return key_scratch;
    }

    /// if there is a pending duplicate-key stash entry for this exact slot,
    /// remove it from the stash; if restore_value is true, the stashed
    /// previous value is moved back into the slot first (use this when the
    /// new value at that slot was rejected); otherwise the stash entry is
    /// simply dropped (use this when the new value was accepted, so it
    /// correctly supersedes the old one and no restore should ever happen
    /// for this slot again)
    /// @return whether a matching stash entry was found (and processed)
    bool resolve_duplicate_key_stash(BasicJsonType* slot, bool restore_value)
    {
        const auto it = std::find_if(duplicate_key_stash.begin(), duplicate_key_stash.end(),
                                     [slot](const std::pair<BasicJsonType*, BasicJsonType>& entry)
        {
            return entry.first == slot;
        });

        if (it == duplicate_key_stash.end())
        {
            return false;
        }

        if (restore_value)
        {
            *slot = std::move(it->second);
        }
        duplicate_key_stash.erase(it);
        return true;
    }

    /*!
    @brief the key the value now being handled will be stored under

    Empty unless the enclosing container is an object, in which case it is the
    key of the pending key() event. Read before handle_value() consumes that
    key, so it is also correct when the value never reaches its parent.
    */
    string_t current_key() const
    {
        if (!ref_stack.empty() && ref_stack.back() && ref_stack.back()->is_object()
                && !key_stack.empty())
        {
            return key_stack.back();
        }
        return string_t{};
    }

    /*!
    @brief leave the object or array that end_object()/end_array() just closed
    @return the key the container is stored under in its parent (see
            container_key_stack)
    */
    string_t pop_container()
    {
        JSON_ASSERT(!ref_stack.empty());
        JSON_ASSERT(!keep_stack.empty());
        JSON_ASSERT(!container_key_stack.empty());
        ref_stack.pop_back();
        keep_stack.pop_back();
        string_t object_key = std::move(container_key_stack.back());
        container_key_stack.pop_back();
        return object_key;
    }

    /*!
    @brief remove the discarded value the callback rejected from its parent,
    unless it is a duplicate key's slot with a stashed previous value, in
    which case that previous value is restored instead

    A rejected value can only ever be the one most recently added to @a parent:
    the last element of an array, or the placeholder key() stored under @a key
    in an object. Looking there directly makes this O(1) resp. O(log n), where
    searching @a parent for it made a filtering parse quadratic in the number of
    members of a single container.

    Finding no discarded value there means none was stored in the first place -
    the callback rejected the value before it reached its parent - so there is
    nothing to remove.

    @param[in,out] parent  the container to remove the rejected value from
    @param[in] key  the key the value was stored under; unused for arrays
    */
    void remove_discarded_value(BasicJsonType& parent, const string_t& key)
    {
        if (parent.is_array())
        {
            auto& array = *parent.m_data.m_value.array;
            if (!array.empty() && array.back().is_discarded())
            {
                array.pop_back();
            }
        }
        else if (parent.is_object())
        {
            auto& object = *parent.m_data.m_value.object;
            const auto it = object.find(key);
            if (it != object.end() && it->second.is_discarded())
            {
                // a duplicate key's slot has a stashed previous value that
                // must be restored instead of being erased
                if (!resolve_duplicate_key_stash(&it->second, true))
                {
                    object.erase(it);
                }
            }
        }
    }

    /*!
    @param[in] v  value to add to the JSON value we build during parsing
    @param[in] skip_callback  whether we should skip calling the callback
               function; this is required after start_array() and
               start_object() SAX events, because otherwise we would call the
               callback function with an empty array or object, respectively.

    @invariant If the ref stack is empty, then the passed value will be the new
               root.
    @invariant If the ref stack contains a value, then it is an array or an
               object to which we can add elements

    @return pair of boolean (whether value should be kept) and pointer (to the
            passed value in the ref_stack hierarchy; nullptr if not kept)
    */
    template<typename Value>
    std::pair<bool, BasicJsonType*> handle_value(Value&& v, const bool skip_callback = false)
    {
        JSON_ASSERT(!keep_stack.empty());

        // do not handle this value if we know it would be added to a discarded
        // container
        if (!keep_stack.back())
        {
            return {false, nullptr};
        }

        // create value
        auto value = BasicJsonType(std::forward<Value>(v));

#if JSON_DIAGNOSTIC_POSITIONS
        diagnostic_positions::set_from_lexer(value, m_lexer_ref);
#endif

        // check callback
        const bool keep = skip_callback || callback(static_cast<int>(ref_stack.size()), parse_event_t::value, value);

        // do not handle this value if we just learnt it shall be discarded
        if (!keep)
        {
            // if the value was to become an object member, key() already
            // stored a placeholder for it that has to be removed again
            if (!ref_stack.empty() && ref_stack.back() && ref_stack.back()->is_object())
            {
                JSON_ASSERT(!key_keep_stack.empty());
                JSON_ASSERT(!key_stack.empty());
                const bool placeholder_stored = key_keep_stack.back();
                key_keep_stack.pop_back();
                const string_t key = std::move(key_stack.back());
                key_stack.pop_back();
                if (placeholder_stored)
                {
                    remove_discarded_value(*ref_stack.back(), key);
                }
            }
            return {false, nullptr};
        }

        if (ref_stack.empty())
        {
            root = std::move(value);
            return {true, & root};
        }

        // skip this value if we already decided to skip the parent
        // (https://github.com/nlohmann/json/issues/971#issuecomment-413678360)
        if (!ref_stack.back())
        {
            return {false, nullptr};
        }

        // we now only expect arrays and objects
        JSON_ASSERT(ref_stack.back()->is_array() || ref_stack.back()->is_object());

        // array
        if (ref_stack.back()->is_array())
        {
            ref_stack.back()->m_data.m_value.array->emplace_back(std::move(value));
            return {true, & (ref_stack.back()->m_data.m_value.array->back())};
        }

        // object
        JSON_ASSERT(ref_stack.back()->is_object());
        // check if we should store an element for the current key
        JSON_ASSERT(!key_keep_stack.empty());
        JSON_ASSERT(!key_stack.empty());
        const bool store_element = key_keep_stack.back();
        key_keep_stack.pop_back();
        key_stack.pop_back();

        if (!store_element)
        {
            return {false, nullptr};
        }

        JSON_ASSERT(object_element);
        *object_element = std::move(value);
        if (!skip_callback)
        {
            // this scalar value finally, definitively replaces whatever was
            // at this slot; drop any pending duplicate-key stash entry for
            // it since it can no longer be restored (a container value at
            // this slot is resolved later, in end_object()/end_array(),
            // since skip_callback is true for the placeholder handling that
            // happens here for those)
            resolve_duplicate_key_stash(object_element, false);
        }
        return {true, object_element};
    }

    /// the parsed JSON value
    BasicJsonType& root;
    /// stack to model hierarchy of values
    std::vector<BasicJsonType*> ref_stack {};
    /// stack to manage which values to keep
    std::vector<bool> keep_stack {}; // NOLINT(readability-redundant-member-init)
    /// stack to manage which object keys to keep
    std::vector<bool> key_keep_stack {}; // NOLINT(readability-redundant-member-init)
    /// the keys key() stored a placeholder for, in lockstep with key_keep_stack
    std::vector<string_t> key_stack {}; // NOLINT(readability-redundant-member-init)
    /// for each open container, the key it is stored under in its parent
    /// object, in lockstep with ref_stack; unused where the parent is not an
    /// object
    std::vector<string_t> container_key_stack {}; // NOLINT(readability-redundant-member-init)
    /// helper to hold the reference for the next object element
    BasicJsonType* object_element = nullptr;
    /// stash of (slot pointer, previous value) for object members that
    /// already existed when key() was called again for the same key
    /// (duplicate keys); used to restore the previous value if the new
    /// value is later rejected by the callback, instead of erasing the
    /// member entirely
    std::vector<std::pair<BasicJsonType*, BasicJsonType>> duplicate_key_stash {};
    /// callback function
    const parser_callback_t callback = nullptr;
    /// a discarded value for the callback
    BasicJsonType discarded = BasicJsonType::value_t::discarded;
    /// the value of the key event for the callback (see key_value())
    BasicJsonType key_scratch {};
    /// the lexer reference to obtain the current position
    lexer_t* m_lexer_ref = nullptr;
};

template<typename BasicJsonType>
class json_sax_acceptor
{
  public:
    using number_integer_t = typename BasicJsonType::number_integer_t;
    using number_unsigned_t = typename BasicJsonType::number_unsigned_t;
    using number_float_t = typename BasicJsonType::number_float_t;
    using string_t = typename BasicJsonType::string_t;
    using binary_t = typename BasicJsonType::binary_t;

    bool null()
    {
        return true;
    }

    bool boolean(bool /*unused*/)
    {
        return true;
    }

    bool number_integer(number_integer_t /*unused*/)
    {
        return true;
    }

    bool number_unsigned(number_unsigned_t /*unused*/)
    {
        return true;
    }

    bool number_float(number_float_t /*unused*/, const string_t& /*unused*/)
    {
        return true;
    }

    bool string(string_t& /*unused*/)
    {
        return true;
    }

    bool binary(binary_t& /*unused*/)
    {
        return true;
    }

    bool start_object(std::size_t /*unused*/ = detail::unknown_size())
    {
        return true;
    }

    bool key(string_t& /*unused*/)
    {
        return true;
    }

    bool end_object()
    {
        return true;
    }

    bool start_array(std::size_t /*unused*/ = detail::unknown_size())
    {
        return true;
    }

    bool end_array()
    {
        return true;
    }

    bool parse_error(std::size_t /*unused*/, const std::string& /*unused*/, const detail::exception& /*unused*/)
    {
        return false;
    }
};

}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
