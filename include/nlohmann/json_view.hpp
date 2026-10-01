//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

/****************************************************************************\
 * Zero-copy, read-only view of a parsed JSON text.                          *
 *                                                                           *
 * json_document::parse() builds a flat index of the values of a JSON text   *
 * (16 bytes per value) instead of a tree of basic_json values. Strings and  *
 * numbers stay in the source text; only strings with escapes are decoded,   *
 * into one buffer. json_view is a handle to one value of the document, with *
 * the read-only part of the basic_json interface; materialize() turns a     *
 * subtree into the basic_json value that parse() would produce.             *
 *                                                                           *
 * The source text must outlive a document that borrows it (lvalue byte     *
 * containers, C strings); rvalue strings, streams, and other inputs are     *
 * owned by the document.                                                    *
\****************************************************************************/

#ifndef INCLUDE_NLOHMANN_JSON_VIEW_HPP_
#define INCLUDE_NLOHMANN_JSON_VIEW_HPP_

#include <cstddef> // size_t
#include <cstring> // memcpy, strlen
#include <iterator> // distance, input_iterator_tag, iterator_traits
#include <map> // map
#include <memory> // unique_ptr
#include <string> // string
#include <tuple> // tuple_element, tuple_size
#include <type_traits> // decay, enable_if, integral_constant, is_arithmetic, is_base_of, is_integral, is_same, remove_cv, remove_extent
#include <unordered_map> // unordered_map
#include <utility> // forward, move
#include <vector> // vector

#include <nlohmann/json.hpp>

// the view builds on internals of the library: both must be the same version
#if NLOHMANN_JSON_VERSION_MAJOR != 3 || NLOHMANN_JSON_VERSION_MINOR != 12 || NLOHMANN_JSON_VERSION_PATCH != 0
    #error "json_view.hpp requires json.hpp of the same version (3.12.0)"
#endif

#include <nlohmann/detail/view/builder.hpp>
#include <nlohmann/detail/view/document_data.hpp>
#include <nlohmann/detail/view/errors.hpp>
#include <nlohmann/detail/view/input.hpp>
#include <nlohmann/detail/view/iterator.hpp>
#include <nlohmann/detail/view/lookup.hpp>
#include <nlohmann/detail/view/macro_scope.hpp>
#include <nlohmann/detail/view/materialize.hpp>
#include <nlohmann/detail/view/node.hpp>
#include <nlohmann/detail/view/pointer.hpp>
#include <nlohmann/detail/view/string_ref.hpp>
#include <nlohmann/detail/view/value.hpp>

NLOHMANN_JSON_NAMESPACE_BEGIN

template<typename BasicJsonType>
class basic_json_document;

/*!
@brief read-only handle to one value of a basic_json_document

Trivially copyable (two pointers). Valid as long as the document is alive and
has not been re-parsed, and as long as a borrowed source text is alive.
*/
template<typename BasicJsonType>
class basic_json_view
{
    using node = detail::view::node;
    using document_data = detail::view::document_data;

  public:
    using value_t = detail::value_t;
    using string_t = typename BasicJsonType::string_t;
    using number_integer_t = typename BasicJsonType::number_integer_t;
    using number_unsigned_t = typename BasicJsonType::number_unsigned_t;
    using number_float_t = typename BasicJsonType::number_float_t;
    using json_pointer = typename BasicJsonType::json_pointer;
    using size_type = std::size_t;
    /// std::string_view from C++17 on
    using string_view_t = detail::view::string_ref;
    /// forward iterator over elements (arrays) or member values (objects)
    using iterator = detail::view::view_iterator<basic_json_view>;
    using const_iterator = iterator;
    /// a (key, value) item of items()
    using item = detail::view::view_item<basic_json_view>;

    /// an invalid view (type() == value_t::discarded)
    basic_json_view() noexcept = default;

    //////////
    // type //
    //////////

    NLOHMANN_VIEW_ALWAYS_INLINE value_t type() const noexcept
    {
        return m_node != nullptr ? static_cast<value_t>(m_node->kind) : value_t::discarded;
    }

    bool is_null() const noexcept
    {
        return type() == value_t::null;
    }

    bool is_boolean() const noexcept
    {
        return type() == value_t::boolean;
    }

    bool is_number() const noexcept
    {
        return is_number_integer() || is_number_float();
    }

    bool is_number_integer() const noexcept
    {
        return type() == value_t::number_integer || type() == value_t::number_unsigned;
    }

    bool is_number_unsigned() const noexcept
    {
        return type() == value_t::number_unsigned;
    }

    bool is_number_float() const noexcept
    {
        return type() == value_t::number_float;
    }

    bool is_string() const noexcept
    {
        return type() == value_t::string;
    }

    bool is_array() const noexcept
    {
        return type() == value_t::array;
    }

    bool is_object() const noexcept
    {
        return type() == value_t::object;
    }

    /// always false: JSON text has no binary values
    bool is_binary() const noexcept
    {
        return false;
    }

    bool is_primitive() const noexcept
    {
        return is_null() || is_string() || is_boolean() || is_number();
    }

    bool is_structured() const noexcept
    {
        return is_array() || is_object();
    }

    /// the root of a failed parse with allow_exceptions == false, or a
    /// default-constructed view
    bool is_discarded() const noexcept
    {
        return type() == value_t::discarded;
    }

    /// false for discarded views
    explicit operator bool() const noexcept
    {
        return m_node != nullptr;
    }

    /// the name of the type, as basic_json::type_name()
    const char* type_name() const noexcept
    {
        return detail::value_type_name(type());
    }

    //////////////
    // capacity //
    //////////////

    /// the number of elements (arrays, objects), 0 for null and discarded,
    /// 1 otherwise, as basic_json::size()
    size_type size() const noexcept
    {
        switch (type())
        {
            case value_t::null:
            case value_t::discarded:
                return 0;
            case value_t::array:
            case value_t::object:
                return m_node->len;
            case value_t::string:
            case value_t::boolean:
            case value_t::number_integer:
            case value_t::number_unsigned:
            case value_t::number_float:
            case value_t::binary:
            default:
                return 1;
        }
    }

    /// as basic_json::empty()
    bool empty() const noexcept
    {
        switch (type())
        {
            case value_t::null:
            case value_t::discarded:
                return true;
            case value_t::array:
            case value_t::object:
                return m_node->len == 0;
            case value_t::string:
            case value_t::boolean:
            case value_t::number_integer:
            case value_t::number_unsigned:
            case value_t::number_float:
            case value_t::binary:
            default:
                return false;
        }
    }

    ////////////////////
    // element access //
    ////////////////////

    /// the value of the member with this key (the first one, should the key
    /// occur more than once); a discarded view if there is none. Throws
    /// type_error.305 if this is not an object.
    NLOHMANN_VIEW_ALWAYS_INLINE basic_json_view operator[](string_view_t key) const
    {
        if (NLOHMANN_VIEW_UNLIKELY(!is_object()))
        {
            detail::view::throw_type_error(305, "cannot use operator[] with a string argument with ", type_name());
        }
        return lookup(key);
    }

    basic_json_view operator[](const char* key) const
    {
        return operator[](string_view_t(key));
    }

    basic_json_view operator[](const string_t& key) const
    {
        return operator[](string_view_t(key.data(), key.size()));
    }

    /// the element at this index; a discarded view if the index is out of
    /// range. Throws type_error.305 if this is not an array.
    basic_json_view operator[](size_type idx) const
    {
        if (NLOHMANN_VIEW_UNLIKELY(!is_array()))
        {
            detail::view::throw_type_error(305, "cannot use operator[] with a numeric argument with ", type_name());
        }
        return idx < m_node->len ? basic_json_view(m_doc, detail::view::element_at(m_node, idx)) : basic_json_view();
    }

    /// (an int argument would be ambiguous between size_type and const char*)
    basic_json_view operator[](int idx) const
    {
        return operator[](static_cast<size_type>(idx));
    }

    /// the value a JSON pointer refers to; a discarded view if a key is
    /// missing or an index is out of range. Other errors throw what const
    /// basic_json::operator[] throws.
    basic_json_view operator[](const json_pointer& ptr) const
    {
        return detail::view::resolve_pointer(*this, detail::json_pointer_access::reference_tokens(ptr), detail::view::pointer_mode::unchecked);
    }

    /// the value of the member with this key (the first one, should the key
    /// occur more than once). Throws type_error.304 if this is not an object,
    /// and out_of_range.403 if there is no such member.
    basic_json_view at(string_view_t key) const
    {
        if (NLOHMANN_VIEW_UNLIKELY(!is_object()))
        {
            detail::view::throw_type_error(304, "cannot use at() with ", type_name());
        }
        const basic_json_view r = lookup(key);
        if (NLOHMANN_VIEW_UNLIKELY(!r))
        {
            detail::view::throw_out_of_range(403, detail::concat("key '", std::string(key.data(), key.size()), "' not found"));
        }
        return r;
    }

    basic_json_view at(const char* key) const
    {
        return at(string_view_t(key));
    }

    basic_json_view at(const string_t& key) const
    {
        return at(string_view_t(key.data(), key.size()));
    }

    /// the element at this index. Throws type_error.304 if this is not an
    /// array, and out_of_range.401 if the index is out of range.
    basic_json_view at(size_type idx) const
    {
        if (NLOHMANN_VIEW_UNLIKELY(!is_array()))
        {
            detail::view::throw_type_error(304, "cannot use at() with ", type_name());
        }
        if (NLOHMANN_VIEW_UNLIKELY(idx >= m_node->len))
        {
            detail::view::throw_out_of_range(401, detail::concat("array index ", std::to_string(idx), " is out of range"));
        }
        return basic_json_view(m_doc, detail::view::element_at(m_node, idx));
    }

    basic_json_view at(int idx) const
    {
        return at(static_cast<size_type>(idx));
    }

    /// the value a JSON pointer refers to; throws what basic_json::at()
    /// throws if it cannot be resolved
    basic_json_view at(const json_pointer& ptr) const
    {
        return detail::view::resolve_pointer(*this, detail::json_pointer_access::reference_tokens(ptr), detail::view::pointer_mode::checked);
    }

    /// the member with this key converted to T, or the default value if there
    /// is no such member (the first one, should the key occur more than
    /// once). Throws type_error.306 if this is not an object.
    template < typename T, typename std::enable_if < !std::is_same<typename std::decay<T>::type, const char*>::value, int >::type = 0 >
    T value(string_view_t key, const T& default_value) const
    {
        if (NLOHMANN_VIEW_UNLIKELY(!is_object()))
        {
            detail::view::throw_type_error(306, "cannot use value() with ", type_name());
        }
        const basic_json_view r = lookup(key);
        return r ? r.template get<T>() : default_value;
    }

    string_t value(string_view_t key, const char* default_value) const
    {
        return value(key, string_t(default_value));
    }

    /// the value a JSON pointer refers to converted to T, or the default
    /// value if the pointer cannot be resolved. Throws type_error.306 if this
    /// is neither an object nor an array.
    template < typename T, typename std::enable_if < !std::is_same<typename std::decay<T>::type, const char*>::value, int >::type = 0 >
    T value(const json_pointer& ptr, const T& default_value) const
    {
        if (NLOHMANN_VIEW_UNLIKELY(!is_structured()))
        {
            detail::view::throw_type_error(306, "cannot use value() with ", type_name());
        }
        const basic_json_view r = detail::view::resolve_pointer(*this, detail::json_pointer_access::reference_tokens(ptr), detail::view::pointer_mode::value);
        return r ? r.template get<T>() : default_value;
    }

    string_t value(const json_pointer& ptr, const char* default_value) const
    {
        return value(ptr, string_t(default_value));
    }

    /// the first element or member value; a primitive value itself. Throws
    /// invalid_iterator.214 for null, discarded views, and empty containers.
    basic_json_view front() const
    {
        const iterator it = begin();
        if (NLOHMANN_VIEW_UNLIKELY(it == end()))
        {
            detail::view::throw_invalid_iterator(214, "cannot get value");
        }
        return *it;
    }

    /// the last element or member value (linear in the size); a primitive
    /// value itself. Throws invalid_iterator.214 for null, discarded views,
    /// and empty containers.
    basic_json_view back() const
    {
        if (is_structured() && m_node->len != 0)
        {
            return basic_json_view(m_doc, detail::view::last_child(m_node) + (is_object() ? 1 : 0));
        }
        return front();
    }

    ////////////
    // lookup //
    ////////////

    /// an iterator to the member with this key (the first one, should the
    /// key occur more than once), or end(); end() also for non-objects
    iterator find(string_view_t key) const
    {
        if (!is_object())
        {
            return end();
        }
        const node* const k = detail::view::find_member(*m_doc, m_node, key.data(), key.size());
        return k != nullptr ? iterator(m_doc, k, true) : end();
    }

    iterator find(const char* key) const
    {
        return find(string_view_t(key));
    }

    iterator find(const string_t& key) const
    {
        return find(string_view_t(key.data(), key.size()));
    }

    /// whether this is an object with a member with this key
    bool contains(string_view_t key) const
    {
        return is_object() && detail::view::find_member(*m_doc, m_node, key.data(), key.size()) != nullptr;
    }

    bool contains(const char* key) const
    {
        return contains(string_view_t(key));
    }

    bool contains(const string_t& key) const
    {
        return contains(string_view_t(key.data(), key.size()));
    }

    /// whether a JSON pointer can be resolved (never throws, as
    /// basic_json::contains())
    bool contains(const json_pointer& ptr) const
    {
        return static_cast<bool>(detail::view::resolve_pointer(*this, detail::json_pointer_access::reference_tokens(ptr), detail::view::pointer_mode::contains));
    }

    /// 1 if this is an object with a member with this key, else 0 (duplicate
    /// keys count once)
    size_type count(string_view_t key) const
    {
        return contains(key) ? 1 : 0;
    }

    size_type count(const char* key) const
    {
        return count(string_view_t(key));
    }

    size_type count(const string_t& key) const
    {
        return count(string_view_t(key.data(), key.size()));
    }

    ///////////////
    // iteration //
    ///////////////

    /// the first element or member value, in document order; a primitive
    /// value is a range of one element (itself), null an empty range
    NLOHMANN_VIEW_ALWAYS_INLINE iterator begin() const noexcept
    {
        if (NLOHMANN_VIEW_LIKELY(is_structured()))
        {
            return iterator(m_doc, document_data::first_child(m_node), is_object());
        }
        return iterator(m_doc, m_node, false);
    }

    NLOHMANN_VIEW_ALWAYS_INLINE iterator end() const noexcept
    {
        if (NLOHMANN_VIEW_LIKELY(is_structured()))
        {
            return iterator(m_doc, document_data::child_end(m_node), is_object());
        }
        return iterator(m_doc, (is_null() || is_discarded()) ? m_node : m_node + 1, false);
    }

    iterator cbegin() const noexcept
    {
        return begin();
    }

    iterator cend() const noexcept
    {
        return end();
    }

    /// (key, value) items; the key of an array element is its index
    detail::view::view_items<basic_json_view> items() const noexcept
    {
        return detail::view::view_items<basic_json_view>(*this);
    }

    ////////////////
    // conversion //
    ////////////////

    /// the value converted to T, as BasicJsonType::get<T>(): arithmetic types,
    /// strings (string_view_t without a copy), std::nullptr_t, std::vector,
    /// maps with string keys, and views are converted directly; other types
    /// through materialize().get<T>()
    template<typename T>
    NLOHMANN_VIEW_ALWAYS_INLINE T get() const
    {
        return get_impl(detail::view::value_tag<T> {}, detail::priority_tag<2> {});
    }

    template<typename T>
    T& get_to(T& v) const
    {
        v = get<T>();
        return v;
    }

    /// the string, without a copy; valid as long as the view is. Throws
    /// type_error.302 for other types.
    string_view_t get_string() const
    {
        if (NLOHMANN_VIEW_UNLIKELY(!is_string()))
        {
            detail::view::throw_type_error(302, "type must be string, but is ", type_name());
        }
        return {m_doc->str(*m_node), m_node->len};
    }

    /// the text of a number as it appears in the source (e.g. "1.50", "1E2",
    /// or an integer with more digits than any number type holds). Throws
    /// type_error.302 for other types.
    string_view_t number_token() const
    {
        if (NLOHMANN_VIEW_UNLIKELY(!is_number()))
        {
            detail::view::throw_type_error(302, "type must be number, but is ", type_name());
        }
        return {m_doc->str(*m_node), detail::view::number_length(*m_node)};
    }

    /////////////////
    // materialize //
    /////////////////

    /// the basic_json value of this subtree, as parse() would produce it
    /// (a discarded value for a discarded view)
    BasicJsonType materialize() const
    {
        if (m_node == nullptr)
        {
            return BasicJsonType(value_t::discarded);
        }
        return detail::view::materialize<BasicJsonType>(*m_doc, m_node);
    }

    /// byte offset of this value in the source text (for strings: of the
    /// first byte after the opening quote); static_cast<std::size_t>(-1) for
    /// a discarded view and for strings with escapes, which are decoded
    std::size_t source_offset() const noexcept
    {
        return m_node != nullptr && (m_node->flags & detail::view::node_flags::storage) == 0
               ? m_node->off : static_cast<std::size_t>(-1);
    }

  private:
    template<typename> friend class basic_json_document;
    friend iterator;

    basic_json_view(const document_data* d, const node* n) noexcept
        : m_doc(d), m_node(n)
    {}

    /// the value of the first member with this key, or a discarded view
    /// (object required)
    NLOHMANN_VIEW_ALWAYS_INLINE basic_json_view lookup(string_view_t key) const noexcept
    {
        const node* const k = detail::view::find_member(*m_doc, m_node, key.data(), key.size());
        return k != nullptr ? basic_json_view(m_doc, k + 1) : basic_json_view();
    }

    // --- get() dispatch ---

    bool get_impl(detail::view::value_tag<bool> /*unused*/, detail::priority_tag<2> /*unused*/) const
    {
        if (NLOHMANN_VIEW_UNLIKELY(!is_boolean()))
        {
            detail::view::throw_type_error(302, "type must be boolean, but is ", type_name());
        }
        return (m_node->flags & detail::view::node_flags::is_true) != 0;
    }

    template < typename T, typename std::enable_if < std::is_arithmetic<T>::value && !std::is_same<T, bool>::value, int >::type = 0 >
    NLOHMANN_VIEW_ALWAYS_INLINE T get_impl(detail::view::value_tag<T> /*unused*/, detail::priority_tag<2> /*unused*/) const
    {
        if (NLOHMANN_VIEW_UNLIKELY(m_node == nullptr))
        {
            detail::view::throw_type_error(302, "type must be number, but is ", type_name());
        }
        return detail::view::arithmetic_value<T, BasicJsonType>(*m_doc, *m_node);
    }

    std::nullptr_t get_impl(detail::view::value_tag<std::nullptr_t> /*unused*/, detail::priority_tag<2> /*unused*/) const
    {
        if (NLOHMANN_VIEW_UNLIKELY(!is_null()))
        {
            detail::view::throw_type_error(302, "type must be null, but is ", type_name());
        }
        return nullptr;
    }

    string_view_t get_impl(detail::view::value_tag<string_view_t> /*unused*/, detail::priority_tag<2> /*unused*/) const
    {
        return get_string();
    }

    template<typename Traits, typename Alloc>
    std::basic_string<char, Traits, Alloc> get_impl(detail::view::value_tag<std::basic_string<char, Traits, Alloc>> /*unused*/, detail::priority_tag<2> /*unused*/) const
    {
        const string_view_t s = get_string();
        return std::basic_string<char, Traits, Alloc>(s.data(), s.size());
    }

    BasicJsonType get_impl(detail::view::value_tag<BasicJsonType> /*unused*/, detail::priority_tag<2> /*unused*/) const
    {
        return materialize();
    }

    basic_json_view get_impl(detail::view::value_tag<basic_json_view> /*unused*/, detail::priority_tag<2> /*unused*/) const noexcept
    {
        return *this;
    }

    template<typename U, typename A>
    std::vector<U, A> get_impl(detail::view::value_tag<std::vector<U, A>> /*unused*/, detail::priority_tag<2> /*unused*/) const
    {
        return detail::view::vector_value<basic_json_view, U, A>(*this);
    }

    template<typename K, typename V, typename C, typename A, typename std::enable_if<detail::view::is_string_key<K>::value, int>::type = 0>
    std::map<K, V, C, A> get_impl(detail::view::value_tag<std::map<K, V, C, A>> /*unused*/, detail::priority_tag<2> /*unused*/) const
    {
        return detail::view::map_value<std::map<K, V, C, A>>(*this);
    }

    template<typename K, typename V, typename H, typename E, typename A, typename std::enable_if<detail::view::is_string_key<K>::value, int>::type = 0>
    std::unordered_map<K, V, H, E, A> get_impl(detail::view::value_tag<std::unordered_map<K, V, H, E, A>> /*unused*/, detail::priority_tag<2> /*unused*/) const
    {
        return detail::view::map_value<std::unordered_map<K, V, H, E, A>>(*this);
    }

    /// everything else through the BasicJsonType value (from_json included)
    template<typename T>
    T get_impl(detail::view::value_tag<T> /*unused*/, detail::priority_tag<0> /*unused*/) const
    {
        return materialize().template get<T>();
    }

    const document_data* m_doc = nullptr;
    const node* m_node = nullptr;
};

/*!
@brief a parsed JSON text: owns the node index (and, optionally, the text)

Borrowed parses keep a pointer to the caller's text, which must outlive the
document. Owned parses (parse_copy, rvalue std::string, streams, and inputs
that are not contiguous byte ranges) keep their own copy.
*/
template<typename BasicJsonType>
class basic_json_document
{
    using document_data = detail::view::document_data;

    static_assert(sizeof(typename BasicJsonType::number_integer_t) == 8 && sizeof(typename BasicJsonType::number_unsigned_t) == 8,
                  "json_view supports 64-bit integer types only");

  public:
    using view_type = basic_json_view<BasicJsonType>;
    using value_t = detail::value_t;

    /// an empty (discarded) document
    basic_json_document() = default;
    basic_json_document(basic_json_document&&) noexcept = default;
    basic_json_document& operator=(basic_json_document&&) noexcept = default;
    basic_json_document(const basic_json_document&) = delete;
    basic_json_document& operator=(const basic_json_document&) = delete;
    ~basic_json_document() = default;

    /////////////
    // parsing //
    /////////////

    /// parse a JSON text; contiguous byte inputs are borrowed, everything else
    /// (and rvalue std::string) is owned
    template<typename InputType>
    NLOHMANN_VIEW_NODISCARD
    static basic_json_document parse(InputType&& input,
                                     const bool allow_exceptions = true,
                                     const bool ignore_comments = false,
                                     const bool ignore_trailing_commas = false)
    {
        basic_json_document d;
        d.read(std::forward<InputType>(input), allow_exceptions, ignore_comments, ignore_trailing_commas);
        return d;
    }

    /// parse [first, last)
    template<typename IteratorType, typename std::enable_if<
                 std::is_base_of<std::input_iterator_tag, typename std::iterator_traits<IteratorType>::iterator_category>::value, int>::type = 0>
    NLOHMANN_VIEW_NODISCARD
    static basic_json_document parse(IteratorType first, IteratorType last,
                                     const bool allow_exceptions = true,
                                     const bool ignore_comments = false,
                                     const bool ignore_trailing_commas = false)
    {
        basic_json_document d;
        d.read_range(first, last, allow_exceptions, ignore_comments, ignore_trailing_commas);
        return d;
    }

    /// parse a copy of the input; the document does not depend on it afterwards
    template<typename InputType>
    NLOHMANN_VIEW_NODISCARD
    static basic_json_document parse_copy(InputType&& input,
                                          const bool allow_exceptions = true,
                                          const bool ignore_comments = false,
                                          const bool ignore_trailing_commas = false)
    {
        basic_json_document d;
        d.build_owned(collect(std::forward<InputType>(input)), allow_exceptions, ignore_comments, ignore_trailing_commas);
        return d;
    }

    /// check whether the input is valid JSON (the result of basic_json::accept)
    template<typename InputType>
    static bool accept(InputType&& input, const bool ignore_comments = false, const bool ignore_trailing_commas = false)
    {
        basic_json_document d;
        d.read(std::forward<InputType>(input), false, ignore_comments, ignore_trailing_commas);
        return !d.is_discarded();
    }

    /// parse into this document, reusing its memory
    template<typename InputType>
    // flawfinder: ignore (a member function, not POSIX read())
    void read(InputType&& input,
              const bool allow_exceptions = true,
              const bool ignore_comments = false,
              const bool ignore_trailing_commas = false)
    {
        read_kind(std::forward<InputType>(input), allow_exceptions, ignore_comments, ignore_trailing_commas,
                  std::integral_constant<detail::view::input_kind, detail::view::classify_input<InputType>::value> {});
    }

    ////////////
    // access //
    ////////////

    /// the root value (discarded if parsing failed without exceptions)
    view_type root() const noexcept
    {
        if (!m_data || m_data->discarded)
        {
            return view_type();
        }
        return view_type(m_data.get(), m_data->tape);
    }

    bool is_discarded() const noexcept
    {
        return !m_data || m_data->discarded;
    }

    /// the parsed text
    typename view_type::string_view_t source() const noexcept
    {
        return m_data ? typename view_type::string_view_t(m_data->src, m_data->size) : typename view_type::string_view_t();
    }

    /// whether the document holds its own copy of the text
    bool owns_source() const noexcept
    {
        return m_data && !m_data->owned.empty() && m_data->src == m_data->owned.data();
    }

    /// number of index nodes (values plus object keys)
    std::size_t node_count() const noexcept
    {
        return m_data ? m_data->tape_size : 0;
    }

    /// bytes held by the document (index, decoded strings, owned text)
    std::size_t memory_usage() const noexcept
    {
        if (!m_data)
        {
            return 0;
        }
        return sizeof(document_data) + (m_data->inline_cap * sizeof(detail::view::node))
               + (m_data->tape != m_data->inline_tape ? m_data->tape_cap * sizeof(detail::view::node) : 0)
               + m_data->arena.capacity() + m_data->owned.capacity();
    }

    /// release unused capacity of the index and the decoded strings; like
    /// std::vector::shrink_to_fit, this invalidates the views of the document
    /// (take new ones from root())
    void shrink_to_fit()
    {
        if (!m_data)
        {
            return;
        }
        using detail::view::node;
        document_data& d = *m_data;

        // allocate everything first, so that an exception leaves the document
        // unchanged
        const bool shrink_arena = d.arena.capacity() > d.arena.size();
        std::string arena(shrink_arena ? d.arena : std::string());
        const bool shrink_tape = d.tape != d.inline_tape && d.tape_size != d.tape_cap;
        const bool into_header = d.tape_size <= d.inline_cap;
        node* fresh = (shrink_tape && !into_header) ? static_cast<node*>(::operator new (d.tape_size * sizeof(node))) : d.inline_tape;

        if (shrink_tape)
        {
            std::memcpy(fresh, d.tape, d.tape_size * sizeof(node));
            ::operator delete (d.tape);
            d.tape = fresh;
            d.tape_cap = into_header ? d.inline_cap : d.tape_size;
        }
        if (shrink_arena)
        {
            d.arena.swap(arena);
            d.base[1] = d.arena.data();
        }
    }

  private:
    using input_kind = detail::view::input_kind;

    /// create the storage (sized for the input) on first use
    void ensure_data(const char* src, std::size_t size)
    {
        if (!m_data)
        {
            m_data.reset(document_data::create(detail::view::estimate_nodes(src, size)));
        }
    }

    /// parse a buffer the document takes ownership of
    void build_owned(std::string&& buf, bool allow_exceptions, bool comments, bool trailing_commas)
    {
        ensure_data(buf.data(), buf.size());
        m_data->owned = std::move(buf);
        build(m_data->owned.data(), m_data->owned.size(), allow_exceptions, comments, trailing_commas, true, true);
    }

    /// sentinel: src[size] is readable and 0 (std::string, C strings)
    void build(const char* src, std::size_t size, bool allow_exceptions, bool comments, bool trailing_commas, bool owned, bool sentinel)
    {
        ensure_data(src, size);
        document_data& d = *m_data;
        if (!owned)
        {
            d.owned.clear();
        }
        d.src = src;
        d.size = size;
        d.tape_size = 0;
        d.arena.clear();
        d.discarded = true;
        detail::view::parse_failure failure;
        bool ok = false;
        if (NLOHMANN_VIEW_UNLIKELY(size >= 0xFFFFFFF0u))
        {
            failure.code = detail::view::error_code::input_too_large; // LCOV_EXCL_LINE (4 GiB)
        }
        else
        {
            ok = detail::view::build < typename BasicJsonType::number_float_t, !detail::abi_config::strict_nul_handling > (d, src, size, comments, trailing_commas, sentinel, failure);
        }
        if (NLOHMANN_VIEW_LIKELY(ok))
        {
            d.base[0] = d.src;
            d.base[1] = d.arena.data();
            d.discarded = false;
            return;
        }
        if (allow_exceptions)
        {
            detail::view::throw_parse_failure<BasicJsonType>(failure, src, size, comments, trailing_commas);
        }
    }

    // --- input dispatch (see detail::view::input_kind) ---

    void read_kind(std::string&& s, bool ae, bool c, bool tc, std::integral_constant<input_kind, input_kind::move_string> /*unused*/)
    {
        build_owned(std::move(s), ae, c, tc);
    }

    template<typename CharT>
    void read_kind(CharT* s, bool ae, bool c, bool tc, std::integral_constant<input_kind, input_kind::c_string> /*unused*/)
    {
        static_assert(sizeof(CharT) == 1 && std::is_integral<typename std::remove_cv<CharT>::type>::value, "json_view parses byte (char-like) input");
        if (s == nullptr)
        {
            build("", 0, ae, c, tc, false, true);
            return;
        }
        const char* cs = reinterpret_cast<const char*>(s); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        // C strings are null-terminated, as for json::parse(const char*)
        // flawfinder: ignore
        build(cs, std::strlen(cs), ae, c, tc, false, true);
    }

    template<typename Array>
    void read_kind(Array& a, bool ae, bool c, bool tc, std::integral_constant<input_kind, input_kind::char_array> /*unused*/)
    {
        using CharT = typename std::remove_cv<typename std::remove_extent<Array>::type>::type;
        static_assert(sizeof(CharT) == 1 && std::is_integral<CharT>::value, "json_view parses byte (char-like) input");
        const std::size_t n = std::extent<Array>::value;
        // a trailing NUL (string literals) is not part of the text, as for
        // parse(), and serves as sentinel
        const bool terminated = n > 0 && a[n - 1] == 0 && (!detail::abi_config::strict_nul_handling || std::is_same<CharT, char>::value);
        build(reinterpret_cast<const char*>(&a[0]), terminated ? n - 1 : n, ae, c, tc, false, terminated); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    }

    template<typename T>
    void read_kind(const T& s, bool ae, bool c, bool tc, std::integral_constant<input_kind, input_kind::borrow_range> /*unused*/)
    {
        // std::basic_string guarantees data()[size()] == 0: use it as sentinel
        const auto size = static_cast<std::size_t>(s.size());
        build(size == 0 ? "" : reinterpret_cast<const char*>(s.data()), size, ae, c, tc, false, // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
              detail::view::is_std_string<T>::value || size == 0);
    }

    template<typename T>
    void read_kind(const T& s, bool ae, bool c, bool tc, std::integral_constant<input_kind, input_kind::copy_range> /*unused*/)
    {
        build_owned(std::string(reinterpret_cast<const char*>(s.data()), static_cast<std::size_t>(s.size())), ae, c, tc); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    }

    template<typename T>
    void read_kind(T&& input, bool ae, bool c, bool tc, std::integral_constant<input_kind, input_kind::adapter> /*unused*/)
    {
        build_owned(detail::view::collect_adapter(detail::input_adapter(std::forward<T>(input))), ae, c, tc);
    }

    template<typename IteratorType>
    void read_range(IteratorType first, IteratorType last, bool ae, bool c, bool tc)
    {
        using value_type = typename std::remove_cv<typename std::iterator_traits<IteratorType>::value_type>::type;
        // borrow the range where the library's input adapter scans it as one
        // block: pointers and, in C++20, contiguous iterators (std::vector,
        // std::string, ...) over single bytes
        read_range_impl(first, last, ae, c, tc, std::integral_constant < bool, std::is_integral<value_type>::value
                        && detail::iterator_input_adapter<IteratorType>::supports_bulk_scan > {});
    }

    template<typename IteratorType>
    void read_range_impl(IteratorType first, IteratorType last, bool ae, bool c, bool tc, std::true_type /*contiguous bytes*/)
    {
        const auto size = static_cast<std::size_t>(std::distance(first, last));
        build(size == 0 ? "" : reinterpret_cast<const char*>(&*first), size, ae, c, tc, false, size == 0); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    }

    template<typename IteratorType>
    void read_range_impl(IteratorType first, IteratorType last, bool ae, bool c, bool tc, std::false_type /*other*/)
    {
        build_owned(detail::view::collect_adapter(detail::input_adapter(first, last)), ae, c, tc);
    }

    template<typename T>
    static std::string collect(T&& input)
    {
        return collect_impl(std::forward<T>(input), std::integral_constant<bool, detail::is_contiguous_byte_container<typename std::decay<T>::type>::value> {});
    }

    template<typename T>
    static std::string collect_impl(const T& s, std::true_type /*contiguous*/)
    {
        return {reinterpret_cast<const char*>(s.data()), static_cast<std::size_t>(s.size())}; // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    }

    template<typename T>
    static std::string collect_impl(T&& s, std::false_type /*other*/)
    {
        return detail::view::collect_adapter(detail::input_adapter(std::forward<T>(s)));
    }

    std::unique_ptr<document_data, document_data::deleter> m_data{}; // NOLINT(readability-redundant-member-init)
};

/// a parsed JSON text for json
using json_document = basic_json_document<json>;
/// a value of a json_document
using json_view = basic_json_view<json>;
/// a parsed JSON text for ordered_json
using ordered_json_document = basic_json_document<ordered_json>;
/// a value of an ordered_json_document
using ordered_json_view = basic_json_view<ordered_json>;

NLOHMANN_JSON_NAMESPACE_END

// tuple protocol for the items of basic_json_view::items() (structured bindings)
namespace std // NOLINT(cert-dcl58-cpp)
{

#if defined(__clang__)
    // Fix: https://github.com/nlohmann/json/issues/1401
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wmismatched-tags"
#endif
template<typename View>
class tuple_size<::nlohmann::detail::view::view_item<View>> // NOLINT(cert-dcl58-cpp)
    : public std::integral_constant<std::size_t, 2> {};

template<std::size_t N, typename View>
class tuple_element<N, ::nlohmann::detail::view::view_item<View>> // NOLINT(cert-dcl58-cpp)
{
  public:
    using type = decltype(std::declval<::nlohmann::detail::view::view_item<View>>().template get<N>());
};
#if defined(__clang__)
    #pragma clang diagnostic pop
#endif

}  // namespace std

#include <nlohmann/detail/view/macro_unscope.hpp>

#endif  // INCLUDE_NLOHMANN_JSON_VIEW_HPP_
