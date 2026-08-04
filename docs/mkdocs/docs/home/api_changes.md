# API Changes

This page is a per-release reference of changes to the public API surface, derived by
diffing the recorded snapshots under `tools/api_checker/history/` (see
[tools/api_checker/README.md](https://github.com/nlohmann/json/blob/develop/tools/api_checker/README.md)).
It complements, and does **not** replace, the [release notes](releases.md): the release notes
are a curated, prose summary of everything notable about a release; this page tracks the
public API specifically, function by function, covering `v3.1.0` through `v3.12.0` (the range
currently backfilled into `tools/api_checker/history/`).

!!! info "How to read this page"

    Each release lists the functions/types whose public declaration changed, grouped by name
    (not by individual overload). The italicized sentence is a best-effort summary of the
    *mechanical* signature diff; a handful of entries were individually researched and cross-
    checked against the source and documentation earlier in this investigation, but most were
    generated from the diff shape alone, so treat the sentence as a hint about where to look,
    not a substitute for reading the linked page. Purely cosmetic changes (annotation macros
    such as `JSON_NODISCARD` being renamed or added library-wide, or a redundant top-level
    `const` on a by-value parameter) are omitted from the per-function list and instead named
    in a single collapsed line per release, since they carry no behavioral or contract
    difference. This is a textual, not semantic, diff (see `extract_api.py`'s `identity_key()`
    docstring) -- a name not being listed for a release means its declaration text did not
    change in that release.

## 3.12.0

### [`nlohmann::basic_json::bjdata_version_t`](../api/basic_json/bjdata_version_t.md)

*New enum (`draft2`/`draft3`) selecting which BJData ND-array draft `to_bjdata()` encodes for.*

- New symbol.
    ```cpp
    using bjdata_version_t = detail::bjdata_version_t
    ```

### [`nlohmann::basic_json::diff`](../api/basic_json/diff.md)

*Changes the `path` parameter's type from `std::string` to `string_t`, so it respects a custom string type instead of hardcoding `std::string`.*

- Changed:
    ```diff
      JSON_HEDLEY_WARN_UNUSED_RESULT static basic_json diff(const basic_json& source, const basic_json& target, const
    - std::string&
    + string_t&
      path = "")
    ```

### [`nlohmann::basic_json::to_bjdata`](../api/basic_json/to_bjdata.md)

*Adds a `bjdata_version_t version` parameter (default `draft2`) to select between BJData draft 2 and draft 3 ND-array encoding.*

- Changed:
    ```diff
      static std::vector<std::uint8_t> to_bjdata(const basic_json& j, const bool use_size = false, const bool use_type =
    - false)
    + false, const bjdata_version_t version = bjdata_version_t::draft2)
    ```

**Cosmetic-only changes** (no behavioral/contract difference; omitted above): `nlohmann::basic_json::basic_json`, `nlohmann::basic_json::parse`.

## 3.11.3

### [`nlohmann::basic_json::operator ValueType`](../api/basic_json/operator_ValueType.md)

*The `std::any` exclusion from this conversion operator's SFINAE becomes conditional on `JSON_HAS_STATIC_RTTI` instead of unconditional.*

- Changed:
    ```diff
      template < typename ValueType, typename std::enable_if < detail::conjunction < detail::negation<std::is_pointer<ValueType>>, detail::negation<std::is_same<ValueType, std::nullptr_t
    + && JSON_HAS_STATIC_RTTI
      detail::negation<std::is_same<ValueType, std::any>>, #endif detail::is_detected_lazy<detail::get_template_function, const basic_json_t&, ValueType> >::value, int >::type = 0 > JSON
    ```

### [`nlohmann::basic_json::operator=`](../api/basic_json/operator=.md)

*Extends the `noexcept` specification to also depend on the new `json_base_class_t` (`CustomBaseClass`) template parameter's move-assignment.*

- Changed:
    ```diff
      basic_json& operator=(basic_json other) noexcept ( std::is_nothrow_move_constructible<value_t>::value&& std::is_nothrow_move_assignable<value_t>::value&& std::is_nothrow_move_const
    - std::is_nothrow_move_assignable<json_value>::value
    + std::is_nothrow_move_assignable<json_value>::value&& std::is_nothrow_move_assignable<json_base_class_t>::value
      )
    ```

## 3.11.2

### [`nlohmann::basic_json::value`](../api/basic_json/value.md)

*Adjusts the template constraints (SFINAE) controlling which types this overload participates in overload resolution for.*

- Changed:
    ```diff
    - JSON_HEDLEY_NON_NULL(3) string_t value(const json_pointer& ptr, const char*
    + template < class ValueType, class BasicJsonType, class ReturnType = typename value_return_type<ValueType>::type, detail::enable_if_t < detail::is_basic_json<BasicJsonType>::value &
      default_value) const
    ```

**Cosmetic-only changes** (no behavioral/contract difference; omitted above): `nlohmann::basic_json::at`, `nlohmann::basic_json::contains`.

## 3.11.0

### [`nlohmann::operator!=`](../api/basic_json/operator_ne.md)

*Removed from the public API.*

- Removes 1 overload.
    ```cpp
    friend bool operator!=(json_pointer const& lhs, json_pointer const& rhs) noexcept
    ```

### [`nlohmann::operator<`](../api/basic_json/operator_lt.md)

*Updates the `noexcept` specification.*

- Changed:
    ```diff
      friend bool operator<(const_reference lhs, const_reference rhs) noexcept {
    - const auto lhs_type = lhs.type(); const auto rhs_type = rhs.type(); if (lhs_type == rhs_type) { switch (lhs_type) { case value_t::array: return (*lhs.m_value.array) < (*rhs.m_value
    + JSON_IMPLEMENT_OPERATOR( <, false, false, operator<(lhs_type, rhs_type))
      }
    ```

### [`nlohmann::operator<<`](../api/basic_json/operator_gtgt.md)

*Adds a new overload.*

- Adds 1 new overload.
    ```cpp
    friend std::ostream& operator<<(std::ostream& o, const json_pointer& ptr) { o << ptr.to_string(); return o; }
    ```

### [`nlohmann::operator<=`](../api/basic_json/operator_le.md)

*Updates the `noexcept` specification.*

- Changed:
    ```diff
      friend bool operator<=(const_reference lhs, const_reference rhs) noexcept {
    + if (compares_unordered(lhs, rhs, true)) { return false; }
      return !(rhs < lhs); }
    ```

### [`nlohmann::operator==`](../api/basic_json/operator_eq.md)

*Removed from the public API.*

- Removes 1 overload.
    ```cpp
    friend bool operator==(json_pointer const& lhs, json_pointer const& rhs) noexcept
    ```

### [`nlohmann::basic_json::at`](../api/basic_json/at.md)

*Adds 4 new overloads.*

- Adds 4 new overloads.
    ```cpp
    template<class KeyType, detail::enable_if_t< detail::is_usable_as_basic_json_key_type<basic_json_t, KeyType>::value, int> = 0> const_reference at(KeyType && key) const
    ```
    ```cpp
    template<class KeyType, detail::enable_if_t< detail::is_usable_as_basic_json_key_type<basic_json_t, KeyType>::value, int> = 0> reference at(KeyType && key)
    ```
    ```cpp
    template<typename BasicJsonType> JSON_HEDLEY_DEPRECATED_FOR(3.11.0, basic_json::json_pointer or nlohmann::json_pointer<basic_json::string_t>) const_reference at(const ::nlohmann::json_pointer<BasicJsonType>& ptr) const
    ```
    ```cpp
    template<typename BasicJsonType> JSON_HEDLEY_DEPRECATED_FOR(3.11.0, basic_json::json_pointer or nlohmann::json_pointer<basic_json::string_t>) reference at(const ::nlohmann::json_pointer<BasicJsonType>& ptr)
    ```

### [`nlohmann::basic_json::count`](../api/basic_json/count.md)

*Changes parameter `KeyT&& key` to `const typename object_t::key_type& key`.*

- Changed:
    ```diff
    - template<typename KeyT> size_type count(KeyT&&
    + size_type count(const typename object_t::key_type&
      key) const
    ```

### [`nlohmann::basic_json::default_object_comparator_t`](../api/basic_json/default_object_comparator_t.md)

*New addition to the public API.*

- New symbol.
    ```cpp
    using default_object_comparator_t = std::less<>
    ```

### [`nlohmann::basic_json::find`](../api/basic_json/find.md)

*Changes parameter `KeyT&& key` to `const typename object_t::key_type& key`.*

- Changed:
    ```diff
    - template<typename KeyT> const_iterator find(KeyT&&
    + const_iterator find(const typename object_t::key_type&
      key) const
    ```

### [`nlohmann::basic_json::from_bjdata`](../api/basic_json/from_bjdata.md)

*New addition to the public API.*

- New symbols (2 overloads).
    ```cpp
    template<typename InputType> JSON_HEDLEY_WARN_UNUSED_RESULT static basic_json from_bjdata(InputType&& i, const bool strict = true, const bool allow_exceptions = true)
    ```
    ```cpp
    template<typename IteratorType> JSON_HEDLEY_WARN_UNUSED_RESULT static basic_json from_bjdata(IteratorType first, IteratorType last, const bool strict = true, const bool allow_exceptions = true)
    ```

### [`nlohmann::basic_json::json_pointer`](../api/json_pointer.md)

*Changes the declaration; see the signature diff for details.*

- Changed:
    ```diff
      using json_pointer =
    - ::nlohmann::json_pointer<basic_json>
    + ::nlohmann::json_pointer<StringType>
    ```

### [`nlohmann::basic_json::object_comparator_t`](../api/basic_json/object_comparator_t.md)

*Changes the declaration; see the signature diff for details.*

- Changed:
    ```diff
      using object_comparator_t =
    - std::less<>
    + detail::actual_object_comparator_t<basic_json>
    ```

### [`nlohmann::basic_json::object_t`](../api/basic_json/object_t.md)

*Changes the declaration; see the signature diff for details.*

- Changed:
    ```diff
      using object_t = ObjectType<StringType, basic_json,
    - object_comparator_t,
    + default_object_comparator_t,
      AllocatorType<std::pair<const StringType, basic_json>>>
    ```

### [`nlohmann::basic_json::operator ValueType`](../api/basic_json/operator_ValueType.md)

*Adjusts the template constraints (SFINAE) controlling which types this overload participates in overload resolution for.*

- Changed:
    ```diff
      template < typename ValueType, typename std::enable_if < detail::conjunction < detail::negation<std::is_pointer<ValueType>>, detail::negation<std::is_same<ValueType,
    - detail::json_ref<basic_json>>>, detail::negation<std::is_same<ValueType, typename string_t::value_type>>, detail::negation<detail::is_basic_json<ValueType>>, detail::negation<std::
    + std::nullptr_t>>, detail::negation<std::is_same<ValueType, detail::json_ref<basic_json>>>, detail::negation<std::is_same<ValueType, typename string_t::value_type>>, detail::negatio
      #endif detail::is_detected_lazy<detail::get_template_function, const basic_json_t&, ValueType> >::value, int >::type = 0 > JSON_EXPLICIT operator ValueType() const
    ```

### [`nlohmann::basic_json::patch_inplace`](../api/basic_json/patch.md)

*New addition to the public API.*

- New symbol.
    ```cpp
    void patch_inplace(const basic_json& json_patch)
    ```

### [`nlohmann::basic_json::to_bjdata`](../api/basic_json/to_bjdata.md)

*New addition to the public API.*

- New symbols (3 overloads).
    ```cpp
    static std::vector<std::uint8_t> to_bjdata(const basic_json& j, const bool use_size = false, const bool use_type = false)
    ```
    ```cpp
    static void to_bjdata(const basic_json& j, detail::output_adapter<char> o, const bool use_size = false, const bool use_type = false)
    ```
    ```cpp
    static void to_bjdata(const basic_json& j, detail::output_adapter<std::uint8_t> o, const bool use_size = false, const bool use_type = false)
    ```

### [`nlohmann::json_pointer::back`](../api/json_pointer/back.md)

*Changes the declaration; see the signature diff for details.*

- Changed:
    ```diff
      const
    - std::string&
    + string_t&
      back() const
    ```

### [`nlohmann::json_pointer::json_pointer`](../api/json_pointer/json_pointer.md)

*Changes parameter `const std::string& s = ""` to `const string_t& s = ""`.*

- Changed:
    ```diff
      explicit json_pointer(const
    - std::string&
    + string_t&
      s = "")
    ```

### `nlohmann::json_pointer::operator std::string`

*Removed from the public API.*

- Removes 1 overload.
    ```cpp
    operator std::string() const
    ```

### [`nlohmann::json_pointer::operator string_t`](../api/json_pointer/operator_string.md)

*New addition to the public API.*

- New symbol.
    ```cpp
    JSON_HEDLEY_DEPRECATED_FOR(3.11.0, to_string()) operator string_t() const
    ```

### [`nlohmann::json_pointer::push_back`](../api/json_pointer/push_back.md)

*Changes parameter `const std::string& token` to `const string_t& token`.*

- Changed:
    ```diff
      void push_back(const
    - std::string&
    + string_t&
      token)
    ```

### [`nlohmann::json_pointer::string_t`](../api/json_pointer/string_t.md)

*New addition to the public API.*

- New symbol.
    ```cpp
    using string_t = typename string_t_helper<RefStringType>::type
    ```

### [`nlohmann::json_pointer::to_string`](../api/json_pointer/to_string.md)

*Changes the declaration; see the signature diff for details.*

- Changed:
    ```diff
    - std::string
    + string_t
      to_string() const
    ```

### [`nlohmann::ordered_map::at`](../api/ordered_map/at.md)

*Changes parameter `const Key& key` to `const key_type& key`.*

- Changed:
    ```diff
      T& at(const
    - Key&
    + key_type&
      key)
    ```

### [`nlohmann::ordered_map::count`](../api/ordered_map/count.md)

*Changes parameter `const Key& key` to `const key_type& key`.*

- Changed:
    ```diff
      size_type count(const
    - Key&
    + key_type&
      key) const
    ```

### [`nlohmann::ordered_map::emplace`](../api/ordered_map/emplace.md)

*Adds a new overload.*

- Adds 1 new overload.
    ```cpp
    template<class KeyType, detail::enable_if_t< detail::is_usable_as_key_type<key_compare, key_type, KeyType>::value, int> = 0> std::pair<iterator, bool> emplace(KeyType && key, T && t)
    ```

### [`nlohmann::ordered_map::find`](../api/ordered_map/find.md)

*Changes parameter `const Key& key` to `const key_type& key`.*

- Changed:
    ```diff
      const_iterator find(const
    - Key&
    + key_type&
      key) const
    ```

### [`nlohmann::ordered_map::key_compare`](../api/ordered_map/key_compare.md)

*New addition to the public API.*

- New symbol.
    ```cpp
    using key_compare = std::equal_to<>
    ```

### [`nlohmann::ordered_map::operator[]`](../api/ordered_map/operator[].md)

*Changes parameter `const Key& key` to `const key_type& key`.*

- Changed:
    ```diff
      T& operator[](const
    - Key&
    + key_type&
      key)
    ```

### [`nlohmann::ordered_map::ordered_map`](../api/ordered_map/ordered_map.md)

*Changes parameter `const Allocator& alloc = Allocator()` to `const Allocator& alloc`.*

- Changed:
    ```diff
    - ordered_map(const Allocator& alloc = Allocator())
    + explicit ordered_map(const Allocator& alloc) noexcept(noexcept(Container(alloc)))
    ```

**Cosmetic-only changes** (no behavioral/contract difference; omitted above): `nlohmann::basic_json::contains`, `nlohmann::basic_json::erase`, `nlohmann::basic_json::operator[]`, `nlohmann::basic_json::value`, `nlohmann::json_pointer::operator/=`, `nlohmann::operator/`, `nlohmann::ordered_map::erase`.

## 3.10.5

### [`nlohmann::basic_json::update`](../api/basic_json/update.md)

*Adds an optional `bool merge_objects` parameter (default `false`).*

- Changed:
    ```diff
      void update(const_iterator first, const_iterator
    - last)
    + last, bool merge_objects = false)
    ```

### `nlohmann::ordered_map::const_iterator`

*New addition to the public API.*

- New symbol.
    ```cpp
    using const_iterator = typename Container::const_iterator
    ```

### [`nlohmann::ordered_map::erase`](../api/ordered_map/erase.md)

*Adds a new overload.*

- Adds 1 new overload.
    ```cpp
    iterator erase(iterator first, iterator last)
    ```

### `nlohmann::ordered_map::iterator`

*New addition to the public API.*

- New symbol.
    ```cpp
    using iterator = typename Container::iterator
    ```

### `nlohmann::ordered_map::size_type`

*New addition to the public API.*

- New symbol.
    ```cpp
    using size_type = typename Container::size_type
    ```

### `nlohmann::ordered_map::value_type`

*New addition to the public API.*

- New symbol.
    ```cpp
    using value_type = typename Container::value_type
    ```

**Cosmetic-only changes** (no behavioral/contract difference; omitted above): `nlohmann::operator/`.

## 3.10.0

### [`nlohmann::operator<`](../api/basic_json/operator_lt.md)

*Updates the `noexcept` specification.*

- Changed:
    ```diff
      friend bool operator<(const_reference lhs, const_reference rhs) noexcept { const auto lhs_type = lhs.type(); const auto rhs_type = rhs.type(); if (lhs_type == rhs_type) { switch (l
    + case value_t::discarded:
      default: return false; } } else if (lhs_type == value_t::number_integer && rhs_type == value_t::number_float) { return static_cast<number_float_t>(lhs.m_value.number_integer) < rhs
    ```

### [`nlohmann::adl_serializer::from_json`](../api/adl_serializer/from_json.md)

*Removes a parameter from the signature.*

- Changed:
    ```diff
      template<typename BasicJsonType, typename
    - ValueType> static auto from_json(BasicJsonType&& j, ValueType& val) noexcept( noexcept(::nlohmann::from_json(std::forward<BasicJsonType>(j), val))) -> decltype(::nlohmann::from_jso
    + TargetType = ValueType> static auto from_json(BasicJsonType && j) noexcept( noexcept(::nlohmann::from_json(std::forward<BasicJsonType>(j), detail::identity_tag<TargetType> {}))) ->
    ```

### [`nlohmann::adl_serializer::to_json`](../api/adl_serializer/to_json.md)

*Changes parameter `ValueType&& val` to `TargetType && val`.*

- Changed:
    ```diff
      template<typename BasicJsonType, typename
    - ValueType> static auto to_json(BasicJsonType& j, ValueType&& val) noexcept( noexcept(::nlohmann::to_json(j, std::forward<ValueType>(val)))) -> decltype(::nlohmann::to_json(j, std::
    + TargetType = ValueType> static auto to_json(BasicJsonType& j, TargetType && val) noexcept( noexcept(::nlohmann::to_json(j, std::forward<TargetType>(val)))) -> decltype(::nlohmann::
      void())
    ```

### [`nlohmann::basic_json::get`](../api/basic_json/get.md)

*Adds a new `JSON_HAS_CPP_14` parameter.*

- Changed:
    ```diff
      template < typename
    - BasicJsonType, detail::enable_if_t < !std::is_same<BasicJsonType, basic_json>::value&& detail::is_basic_json<BasicJsonType>::value, int > = 0 > BasicJsonType get() const
    + ValueTypeCV, typename ValueType = detail::uncvref_t<ValueTypeCV>> #if defined(JSON_HAS_CPP_14) constexpr #endif auto get() const noexcept( noexcept(std::declval<const basic_json_t&
    ```

### [`nlohmann::basic_json::operator ValueType`](../api/basic_json/operator_ValueType.md)

*Adjusts the template constraints (SFINAE) controlling which types this overload participates in overload resolution for.*

- Changed:
    ```diff
      template < typename ValueType, typename std::enable_if <
    - !std::is_pointer<ValueType>::value&& !std::is_same<ValueType, detail::json_ref<basic_json>>::value&& !std::is_same<ValueType, typename string_t::value_type>::value&& !detail::is_ba
    + detail::conjunction < detail::negation<std::is_pointer<ValueType>>, detail::negation<std::is_same<ValueType, detail::json_ref<basic_json>>>, detail::negation<std::is_same<ValueType
      int >::type = 0 > JSON_EXPLICIT operator ValueType() const
    ```

### [`nlohmann::basic_json::to_bson`](../api/basic_json/to_bson.md)

*Changes the declaration; see the signature diff for details.*

- Changed:
    ```diff
      static
    - std::vector<uint8_t>
    + std::vector<std::uint8_t>
      to_bson(const basic_json& j)
    ```

### [`nlohmann::basic_json::to_cbor`](../api/basic_json/to_cbor.md)

*Changes the declaration; see the signature diff for details.*

- Changed:
    ```diff
      static
    - std::vector<uint8_t>
    + std::vector<std::uint8_t>
      to_cbor(const basic_json& j)
    ```

### [`nlohmann::basic_json::to_msgpack`](../api/basic_json/to_msgpack.md)

*Changes the declaration; see the signature diff for details.*

- Changed:
    ```diff
      static
    - std::vector<uint8_t>
    + std::vector<std::uint8_t>
      to_msgpack(const basic_json& j)
    ```

### [`nlohmann::basic_json::to_ubjson`](../api/basic_json/to_ubjson.md)

*Changes the declaration; see the signature diff for details.*

- Changed:
    ```diff
      static
    - std::vector<uint8_t>
    + std::vector<std::uint8_t>
      to_ubjson(const basic_json& j, const bool use_size = false, const bool use_type = false)
    ```

### [`nlohmann::byte_container_with_subtype::set_subtype`](../api/byte_container_with_subtype/set_subtype.md)

*Changes parameter `std::uint8_t subtype` to `subtype_type subtype_`.*

- Changed:
    ```diff
      void
    - set_subtype(std::uint8_t subtype)
    + set_subtype(subtype_type subtype_)
      noexcept
    ```

### [`nlohmann::byte_container_with_subtype::subtype`](../api/byte_container_with_subtype/subtype.md)

*Updates the `noexcept` specification.*

- Changed:
    ```diff
      constexpr
    - std::uint8_t
    + subtype_type
      subtype() const noexcept
    ```

### [`nlohmann::byte_container_with_subtype::subtype_type`](../api/byte_container_with_subtype/subtype_type.md)

*New addition to the public API.*

- New symbol.
    ```cpp
    using subtype_type = std::uint64_t
    ```

### [`nlohmann::json_sax::json_sax`](../api/json_sax/json_sax.md)

*New addition to the public API.*

- New symbols (3 overloads).
    ```cpp
    json_sax() = default
    ```
    ```cpp
    json_sax(const json_sax&) = default
    ```
    ```cpp
    json_sax(json_sax&&) noexcept = default
    ```

### [`nlohmann::json_sax::operator=`](../api/json_sax/operator=.md)

*New addition to the public API.*

- New symbols (2 overloads).
    ```cpp
    json_sax& operator=(const json_sax&) = default
    ```
    ```cpp
    json_sax& operator=(json_sax&&) noexcept = default
    ```

### [`nlohmann::ordered_map::insert`](../api/ordered_map/insert.md)

*Adds a new overload.*

- Adds 1 new overload.
    ```cpp
    template<typename InputIt, typename = require_input_iter<InputIt>> void insert(InputIt first, InputIt last)
    ```

**Cosmetic-only changes** (no behavioral/contract difference; omitted above): `nlohmann::basic_json::binary`, `nlohmann::byte_container_with_subtype::byte_container_with_subtype`.

## 3.9.1

### [`nlohmann::ordered_map::at`](../api/ordered_map/at.md)

*New addition to the public API.*

- New symbols (2 overloads).
    ```cpp
    T& at(const Key& key)
    ```
    ```cpp
    const T& at(const Key& key) const
    ```

### [`nlohmann::ordered_map::count`](../api/ordered_map/count.md)

*New addition to the public API.*

- New symbol.
    ```cpp
    size_type count(const Key& key) const
    ```

### [`nlohmann::ordered_map::emplace`](../api/ordered_map/emplace.md)

*Changes parameter `key_type&& key` to `const key_type& key`.*

- Changed:
    ```diff
      std::pair<iterator, bool>
    - emplace(key_type&&
    + emplace(const key_type&
      key, T&& t)
    ```

### [`nlohmann::ordered_map::erase`](../api/ordered_map/erase.md)

*Adds a new overload.*

- Adds 1 new overload.
    ```cpp
    iterator erase(iterator pos)
    ```

### [`nlohmann::ordered_map::find`](../api/ordered_map/find.md)

*New addition to the public API.*

- New symbols (2 overloads).
    ```cpp
    const_iterator find(const Key& key) const
    ```
    ```cpp
    iterator find(const Key& key)
    ```

### [`nlohmann::ordered_map::insert`](../api/ordered_map/insert.md)

*New addition to the public API.*

- New symbols (2 overloads).
    ```cpp
    std::pair<iterator, bool> insert( const value_type& value )
    ```
    ```cpp
    std::pair<iterator, bool> insert( value_type&& value )
    ```

### [`nlohmann::ordered_map::operator[]`](../api/ordered_map/operator[].md)

*Changes parameter `Key&& key` to `const Key& key`.*

- Changed:
    ```diff
      T&
    - operator[](Key&&
    + operator[](const Key&
      key)
    ```

## 3.9.0

### [`nlohmann::operator<`](../api/basic_json/operator_lt.md)

*Updates the `noexcept` specification.*

- Changed:
    ```diff
      friend bool operator<(const_reference lhs, const_reference rhs) noexcept { const auto lhs_type = lhs.type(); const auto rhs_type = rhs.type(); if (lhs_type == rhs_type) { switch (l
    - and rhs_type == value_t::number_float) { return static_cast<number_float_t>(lhs.m_value.number_integer) < rhs.m_value.number_float; } else if (lhs_type == value_t::number_float and
    + && rhs_type == value_t::number_float) { return static_cast<number_float_t>(lhs.m_value.number_integer) < rhs.m_value.number_float; } else if (lhs_type == value_t::number_float && r
      rhs_type == value_t::number_integer) { return static_cast<number_integer_t>(lhs.m_value.number_unsigned) < rhs.m_value.number_integer; } return operator<(lhs_type, rhs_type); }
    ```

### [`nlohmann::operator<=`](../api/basic_json/operator_le.md)

*Updates the `noexcept` specification.*

- Changed:
    ```diff
      friend bool operator<=(const_reference lhs, const_reference rhs) noexcept { return
    - not (rhs
    + !(rhs
      < lhs); }
    ```

### [`nlohmann::swap`](../api/basic_json/swap.md)

*New addition to the public API.*

- New symbol.
    ```cpp
    friend void swap(reference left, reference right) noexcept ( std::is_nothrow_move_constructible<value_t>::value&& std::is_nothrow_move_assignable<value_t>::value&& std::is_nothrow_move_constructible<json_value>::value&&  [...]
    ```

### [`nlohmann::adl_serializer::to_json`](../api/adl_serializer/to_json.md)

*Updates the `noexcept` specification.*

- Changed:
    ```diff
    - template <typename
    + template<typename
      BasicJsonType, typename ValueType> static auto to_json(BasicJsonType& j, ValueType&& val) noexcept( noexcept(::nlohmann::to_json(j, std::forward<ValueType>(val)))) -> decltype(::nl
    ```

### [`nlohmann::basic_json::accept`](../api/basic_json/accept.md)

*Changes the declaration; see the signature diff for details.*

- Changed:
    ```diff
      JSON_HEDLEY_WARN_UNUSED_RESULT JSON_HEDLEY_DEPRECATED_FOR(3.8.0, accept(ptr, ptr + len)) static bool accept(detail::span_input_adapter&&
    - i)
    + i, const bool ignore_comments = false)
    ```

### [`nlohmann::basic_json::cbor_tag_handler_t`](../api/basic_json/cbor_tag_handler_t.md)

*New addition to the public API.*

- New symbol.
    ```cpp
    using cbor_tag_handler_t = detail::cbor_tag_handler_t
    ```

### [`nlohmann::basic_json::from_cbor`](../api/basic_json/from_cbor.md)

*Changes the declaration; see the signature diff for details.*

- Changed:
    ```diff
      JSON_HEDLEY_WARN_UNUSED_RESULT JSON_HEDLEY_DEPRECATED_FOR(3.8.0, from_cbor(ptr, ptr + len)) static basic_json from_cbor(detail::span_input_adapter&& i, const bool strict = true, co
    - true)
    + true, const cbor_tag_handler_t tag_handler = cbor_tag_handler_t::error)
    ```

### [`nlohmann::basic_json::get`](../api/basic_json/get.md)

*Adjusts the template constraints (SFINAE) controlling which types this overload participates in overload resolution for.*

- Changed:
    ```diff
    - template<typename BasicJsonType, detail::enable_if_t< not std::is_same<BasicJsonType, basic_json>::value and detail::is_basic_json<BasicJsonType>::value, int> = 0>
    + template < typename BasicJsonType, detail::enable_if_t < !std::is_same<BasicJsonType, basic_json>::value&& detail::is_basic_json<BasicJsonType>::value, int > = 0 >
      BasicJsonType get() const
    ```

### [`nlohmann::basic_json::get_ptr`](../api/basic_json/get_ptr.md)

*Updates the `noexcept` specification.*

- Changed:
    ```diff
    - template<typename PointerType, typename std::enable_if< std::is_pointer<PointerType>::value and std::is_const<typename std::remove_pointer<PointerType>::type>::value, int>::type = 
    + template < typename PointerType, typename std::enable_if < std::is_pointer<PointerType>::value&& std::is_const<typename std::remove_pointer<PointerType>::type>::value, int >::type 
      constexpr auto get_ptr() const noexcept -> decltype(std::declval<const basic_json_t&>().get_impl_ptr(std::declval<PointerType>()))
    ```

### [`nlohmann::basic_json::get_ref`](../api/basic_json/get_ref.md)

*Adjusts the template constraints (SFINAE) controlling which types this overload participates in overload resolution for.*

- Changed:
    ```diff
    - template<typename ReferenceType, typename std::enable_if< std::is_reference<ReferenceType>::value and std::is_const<typename std::remove_reference<ReferenceType>::type>::value, int
    + template < typename ReferenceType, typename std::enable_if < std::is_reference<ReferenceType>::value&& std::is_const<typename std::remove_reference<ReferenceType>::type>::value, in
      ReferenceType get_ref() const
    ```

### [`nlohmann::basic_json::operator ValueType`](../api/basic_json/operator_ValueType.md)

*Adjusts the template constraints (SFINAE) controlling which types this overload participates in overload resolution for.*

- Changed:
    ```diff
      template < typename ValueType, typename std::enable_if <
    - not std::is_pointer<ValueType>::value and not std::is_same<ValueType, detail::json_ref<basic_json>>::value and not std::is_same<ValueType, typename string_t::value_type>::value and
    + !std::is_pointer<ValueType>::value&& !std::is_same<ValueType, detail::json_ref<basic_json>>::value&& !std::is_same<ValueType, typename string_t::value_type>::value&& !detail::is_ba
      operator ValueType() const
    ```

### [`nlohmann::basic_json::operator=`](../api/basic_json/operator=.md)

*Updates the `noexcept` specification.*

- Changed:
    ```diff
      basic_json& operator=(basic_json other) noexcept (
    - std::is_nothrow_move_constructible<value_t>::value and std::is_nothrow_move_assignable<value_t>::value and std::is_nothrow_move_constructible<json_value>::value and
    + std::is_nothrow_move_constructible<value_t>::value&& std::is_nothrow_move_assignable<value_t>::value&& std::is_nothrow_move_constructible<json_value>::value&&
      std::is_nothrow_move_assignable<json_value>::value )
    ```

### [`nlohmann::basic_json::parse`](../api/basic_json/parse.md)

*Changes the declaration; see the signature diff for details.*

- Changed:
    ```diff
      JSON_HEDLEY_WARN_UNUSED_RESULT JSON_HEDLEY_DEPRECATED_FOR(3.8.0, parse(ptr, ptr + len)) static basic_json parse(detail::span_input_adapter&& i, const parser_callback_t cb = nullptr
    - true)
    + true, const bool ignore_comments = false)
    ```

### [`nlohmann::basic_json::sax_parse`](../api/basic_json/sax_parse.md)

*Changes the declaration; see the signature diff for details.*

- Changed:
    ```diff
      template <typename InputType, typename SAX> JSON_HEDLEY_NON_NULL(2) static bool sax_parse(InputType&& i, SAX* sax, input_format_t format = input_format_t::json, const bool strict =
    - true)
    + true, const bool ignore_comments = false)
    ```

### [`nlohmann::ordered_map::Container`](../api/ordered_map/Container.md)

*New addition to the public API.*

- New symbol.
    ```cpp
    using Container = std::vector<std::pair<const Key, T>, Allocator>
    ```

### [`nlohmann::ordered_map::emplace`](../api/ordered_map/emplace.md)

*New addition to the public API.*

- New symbol.
    ```cpp
    std::pair<iterator, bool> emplace(key_type&& key, T&& t)
    ```

### [`nlohmann::ordered_map::erase`](../api/ordered_map/erase.md)

*New addition to the public API.*

- New symbol.
    ```cpp
    size_type erase(const Key& key)
    ```

### `nlohmann::ordered_map::key_type`

*New addition to the public API.*

- New symbol.
    ```cpp
    using key_type = Key
    ```

### `nlohmann::ordered_map::mapped_type`

*New addition to the public API.*

- New symbol.
    ```cpp
    using mapped_type = T
    ```

### [`nlohmann::ordered_map::operator[]`](../api/ordered_map/operator[].md)

*New addition to the public API.*

- New symbol.
    ```cpp
    T& operator[](Key&& key)
    ```

### [`nlohmann::ordered_map::ordered_map`](../api/ordered_map/ordered_map.md)

*New addition to the public API.*

- New symbols (3 overloads).
    ```cpp
    ordered_map(const Allocator& alloc = Allocator())
    ```
    ```cpp
    ordered_map(std::initializer_list<T> init, const Allocator& alloc = Allocator() )
    ```
    ```cpp
    template <class It> ordered_map(It first, It last, const Allocator& alloc = Allocator())
    ```

**Cosmetic-only changes** (no behavioral/contract difference; omitted above): `nlohmann::basic_json::basic_json`, `nlohmann::basic_json::contains`, `nlohmann::basic_json::erase`, `nlohmann::basic_json::get_to`, `nlohmann::basic_json::swap`, `nlohmann::basic_json::value`.

## 3.8.0

### [`nlohmann::operator<`](../api/basic_json/operator_lt.md)

*Updates the `noexcept` specification.*

- Changed:
    ```diff
      friend bool operator<(const_reference lhs, const_reference rhs) noexcept { const auto lhs_type = lhs.type(); const auto rhs_type = rhs.type(); if (lhs_type == rhs_type) { switch (l
    + case value_t::binary: return (*lhs.m_value.binary) < (*rhs.m_value.binary);
      default: return false; } } else if (lhs_type == value_t::number_integer and rhs_type == value_t::number_float) { return static_cast<number_float_t>(lhs.m_value.number_integer) < rh
    ```

### [`nlohmann::operator<<`](../api/basic_json/operator_gtgt.md)

*Adds a new `operator>>(std::istream&, basic_json&)` parameter.*

- Changed:
    ```diff
    - JSON_HEDLEY_DEPRECATED(3.0.0)
    + JSON_HEDLEY_DEPRECATED_FOR(3.0.0, operator>>(std::istream&, basic_json&))
      friend std::istream& operator<<(basic_json& j, std::istream& i) { return operator>>(i, j);
    ```

### [`nlohmann::operator>>`](../api/basic_json/operator_ltlt.md)

*Adds a new `operator<<(std::ostream&, const basic_json&)` parameter.*

- Changed:
    ```diff
    - JSON_HEDLEY_DEPRECATED(3.0.0)
    + JSON_HEDLEY_DEPRECATED_FOR(3.0.0, operator<<(std::ostream&, const basic_json&))
      friend std::ostream& operator>>(const basic_json& j, std::ostream& o)
    ```

### [`nlohmann::basic_json::accept`](../api/basic_json/accept.md)

*Changes the parameter list.*

- Changed:
    ```diff
    - static bool accept(detail::input_adapter&&
    + JSON_HEDLEY_WARN_UNUSED_RESULT JSON_HEDLEY_DEPRECATED_FOR(3.8.0, accept(ptr, ptr + len)) static bool accept(detail::span_input_adapter&&
      i)
    ```

### [`nlohmann::basic_json::basic_json`](../api/basic_json/basic_json.md)

- Adds 1 new overload.
    ```cpp
    template <typename JsonRef, detail::enable_if_t<detail::conjunction<detail::is_json_ref<JsonRef>, std::is_same<typename JsonRef::value_type, basic_json>>::value, int> = 0 > basic_json(const JsonRef& ref)
    ```
- Removes 1 overload.
    ```cpp
    basic_json(const detail::json_ref<basic_json>& ref)
    ```

### [`nlohmann::basic_json::binary`](../api/basic_json/binary.md)

*New addition to the public API.*

- New symbols (4 overloads).
    ```cpp
    JSON_HEDLEY_WARN_UNUSED_RESULT static basic_json binary(const typename binary_t::container_type& init)
    ```
    ```cpp
    JSON_HEDLEY_WARN_UNUSED_RESULT static basic_json binary(const typename binary_t::container_type& init, std::uint8_t subtype)
    ```
    ```cpp
    JSON_HEDLEY_WARN_UNUSED_RESULT static basic_json binary(typename binary_t::container_type&& init)
    ```
    ```cpp
    JSON_HEDLEY_WARN_UNUSED_RESULT static basic_json binary(typename binary_t::container_type&& init, std::uint8_t subtype)
    ```

### [`nlohmann::basic_json::binary_t`](../api/basic_json/binary_t.md)

*New addition to the public API.*

- New symbol.
    ```cpp
    using binary_t = nlohmann::byte_container_with_subtype<BinaryType>
    ```

### [`nlohmann::basic_json::from_bson`](../api/basic_json/from_bson.md)

*Removes a parameter from the signature.*

- Changed:
    ```diff
      JSON_HEDLEY_WARN_UNUSED_RESULT
    - static basic_json from_bson(detail::input_adapter&&
    + JSON_HEDLEY_DEPRECATED_FOR(3.8.0, from_bson(ptr, ptr + len)) static basic_json from_bson(detail::span_input_adapter&&
      i, const bool strict = true, const bool allow_exceptions = true)
    ```

### [`nlohmann::basic_json::from_cbor`](../api/basic_json/from_cbor.md)

*Removes a parameter from the signature.*

- Changed:
    ```diff
      JSON_HEDLEY_WARN_UNUSED_RESULT
    - static basic_json from_cbor(detail::input_adapter&&
    + JSON_HEDLEY_DEPRECATED_FOR(3.8.0, from_cbor(ptr, ptr + len)) static basic_json from_cbor(detail::span_input_adapter&&
      i, const bool strict = true, const bool allow_exceptions = true)
    ```

### [`nlohmann::basic_json::from_msgpack`](../api/basic_json/from_msgpack.md)

*Removes a parameter from the signature.*

- Changed:
    ```diff
      JSON_HEDLEY_WARN_UNUSED_RESULT
    - static basic_json from_msgpack(detail::input_adapter&&
    + JSON_HEDLEY_DEPRECATED_FOR(3.8.0, from_msgpack(ptr, ptr + len)) static basic_json from_msgpack(detail::span_input_adapter&&
      i, const bool strict = true, const bool allow_exceptions = true)
    ```

### [`nlohmann::basic_json::from_ubjson`](../api/basic_json/from_ubjson.md)

*Removes a parameter from the signature.*

- Changed:
    ```diff
      JSON_HEDLEY_WARN_UNUSED_RESULT
    - static basic_json from_ubjson(detail::input_adapter&&
    + JSON_HEDLEY_DEPRECATED_FOR(3.8.0, from_ubjson(ptr, ptr + len)) static basic_json from_ubjson(detail::span_input_adapter&&
      i, const bool strict = true, const bool allow_exceptions = true)
    ```

### [`nlohmann::basic_json::get_binary`](../api/basic_json/get_binary.md)

*New addition to the public API.*

- New symbols (2 overloads).
    ```cpp
    binary_t& get_binary()
    ```
    ```cpp
    const binary_t& get_binary() const
    ```

### [`nlohmann::basic_json::is_binary`](../api/basic_json/is_binary.md)

*New addition to the public API.*

- New symbol.
    ```cpp
    constexpr bool is_binary() const noexcept
    ```

### [`nlohmann::basic_json::iterator_wrapper`](../api/basic_json/items.md)

*Adds a new `items()` parameter.*

- Changed:
    ```diff
    - JSON_HEDLEY_DEPRECATED(3.1.0)
    + JSON_HEDLEY_DEPRECATED_FOR(3.1.0, items())
      static iteration_proxy<const_iterator> iterator_wrapper(const_reference ref) noexcept
    ```

### [`nlohmann::basic_json::operator ValueType`](../api/basic_json/operator_ValueType.md)

*Adjusts the template constraints (SFINAE) controlling which types this overload participates in overload resolution for.*

- Changed:
    ```diff
      template < typename ValueType, typename std::enable_if < not std::is_pointer<ValueType>::value and not std::is_same<ValueType, detail::json_ref<basic_json>>::value and not std::is_
    - #ifndef _MSC_VER and not std::is_same<ValueType, std::initializer_list<typename string_t::value_type>>::value #if defined(JSON_HAS_CPP_17) && (defined(__GNUC__) || (defined(_MSC_VE
    + and not std::is_same<ValueType, std::initializer_list<typename string_t::value_type>>::value #if defined(JSON_HAS_CPP_17) && (defined(__GNUC__) || (defined(_MSC_VER) and _MSC_VER >
    ```

### [`nlohmann::basic_json::parse`](../api/basic_json/parse.md)

*Removes a parameter from the signature.*

- Changed:
    ```diff
      JSON_HEDLEY_WARN_UNUSED_RESULT
    - static basic_json parse(detail::input_adapter&&
    + JSON_HEDLEY_DEPRECATED_FOR(3.8.0, parse(ptr, ptr + len)) static basic_json parse(detail::span_input_adapter&&
      i, const parser_callback_t cb = nullptr, const bool allow_exceptions = true)
    ```

### [`nlohmann::basic_json::parse_event_t`](../api/basic_json/parse_event_t.md)

*Changes the declaration; see the signature diff for details.*

- Changed:
    ```diff
      using parse_event_t =
    - typename parser::parse_event_t
    + detail::parse_event_t
    ```

### [`nlohmann::basic_json::parser_callback_t`](../api/basic_json/parser_callback_t.md)

*Changes the declaration; see the signature diff for details.*

- Changed:
    ```diff
      using parser_callback_t =
    - typename parser::parser_callback_t
    + detail::parser_callback_t<basic_json>
    ```

### [`nlohmann::basic_json::sax_parse`](../api/basic_json/sax_parse.md)

*Changes the declaration; see the signature diff for details.*

- Changed:
    ```diff
      template <typename
    - SAX> JSON_HEDLEY_NON_NULL(2) static bool sax_parse(detail::input_adapter&&
    + InputType, typename SAX> JSON_HEDLEY_NON_NULL(2) static bool sax_parse(InputType&&
      i, SAX* sax, input_format_t format = input_format_t::json, const bool strict = true)
    ```

### [`nlohmann::basic_json::swap`](../api/basic_json/swap.md)

*Adds 2 new overloads.*

- Adds 2 new overloads.
    ```cpp
    void swap(binary_t& other)
    ```
    ```cpp
    void swap(typename binary_t::container_type& other)
    ```

### [`nlohmann::byte_container_with_subtype::byte_container_with_subtype`](../api/byte_container_with_subtype/byte_container_with_subtype.md)

*New addition to the public API.*

- New symbols (5 overloads).
    ```cpp
    byte_container_with_subtype() noexcept(noexcept(container_type()))
    ```
    ```cpp
    byte_container_with_subtype(const container_type& b) noexcept(noexcept(container_type(b)))
    ```
    ```cpp
    byte_container_with_subtype(const container_type& b, std::uint8_t subtype) noexcept(noexcept(container_type(b)))
    ```
    ```cpp
    byte_container_with_subtype(container_type&& b) noexcept(noexcept(container_type(std::move(b))))
    ```

### [`nlohmann::byte_container_with_subtype::clear_subtype`](../api/byte_container_with_subtype/clear_subtype.md)

*New addition to the public API.*

- New symbol.
    ```cpp
    void clear_subtype() noexcept
    ```

### [`nlohmann::byte_container_with_subtype::container_type`](../api/byte_container_with_subtype/container_type.md)

*New addition to the public API.*

- New symbol.
    ```cpp
    using container_type = BinaryType
    ```

### [`nlohmann::byte_container_with_subtype::has_subtype`](../api/byte_container_with_subtype/has_subtype.md)

*New addition to the public API.*

- New symbol.
    ```cpp
    constexpr bool has_subtype() const noexcept
    ```

### [`nlohmann::byte_container_with_subtype::operator!=`](../api/byte_container_with_subtype/operator_ne.md)

*New addition to the public API.*

- New symbol.
    ```cpp
    bool operator!=(const byte_container_with_subtype& rhs) const
    ```

### [`nlohmann::byte_container_with_subtype::operator==`](../api/byte_container_with_subtype/operator_eq.md)

*New addition to the public API.*

- New symbol.
    ```cpp
    bool operator==(const byte_container_with_subtype& rhs) const
    ```

### [`nlohmann::byte_container_with_subtype::set_subtype`](../api/byte_container_with_subtype/set_subtype.md)

*New addition to the public API.*

- New symbol.
    ```cpp
    void set_subtype(std::uint8_t subtype) noexcept
    ```

### [`nlohmann::byte_container_with_subtype::subtype`](../api/byte_container_with_subtype/subtype.md)

*New addition to the public API.*

- New symbol.
    ```cpp
    constexpr std::uint8_t subtype() const noexcept
    ```

### [`nlohmann::json_sax::binary`](../api/json_sax/binary.md)

*New addition to the public API.*

- New symbol.
    ```cpp
    virtual bool binary(binary_t& val) = 0
    ```

### [`nlohmann::json_sax::binary_t`](../api/json_sax/binary_t.md)

*New addition to the public API.*

- New symbol.
    ```cpp
    using binary_t = typename BasicJsonType::binary_t
    ```

**Cosmetic-only changes** (no behavioral/contract difference; omitted above): `nlohmann::basic_json::value`, `nlohmann::json_pointer::operator/=`, `nlohmann::operator/`.

## 3.7.1

**Cosmetic-only changes** (no behavioral/contract difference; omitted above): `nlohmann::basic_json::contains`, `nlohmann::basic_json::get`, `nlohmann::json_pointer::back`.

## 3.7.0

### [`nlohmann::operator<`](../api/basic_json/operator_lt.md)

*Updates the `noexcept` specification.*

- Changed:
    ```diff
      friend bool operator<(const_reference lhs, const_reference rhs) noexcept { const auto lhs_type = lhs.type(); const auto rhs_type = rhs.type(); if (lhs_type == rhs_type) { switch (l
    - *lhs.m_value.object < *rhs.m_value.object; case value_t::null: return false; case value_t::string: return *lhs.m_value.string < *rhs.m_value.string; case value_t::boolean: return l
    + (*lhs.m_value.object) < (*rhs.m_value.object); case value_t::null: return false; case value_t::string: return (*lhs.m_value.string) < (*rhs.m_value.string); case value_t::boolean: 
      default: return false; } } else if (lhs_type == value_t::number_integer and rhs_type == value_t::number_float) { return static_cast<number_float_t>(lhs.m_value.number_integer) < rh
    ```

### [`nlohmann::basic_json::contains`](../api/basic_json/contains.md)

*Changes parameter `KeyT&& key` to `const json_pointer& ptr`.*

- Changed:
    ```diff
    - template<typename KeyT> bool contains(KeyT&& key)
    + bool contains(const json_pointer& ptr)
      const
    ```

### [`nlohmann::basic_json::emplace_back`](../api/basic_json/emplace_back.md)

*Changes the declaration; see the signature diff for details.*

- Changed:
    ```diff
      template<class... Args>
    - void
    + reference
      emplace_back(Args&& ... args)
    ```

### [`nlohmann::basic_json::get_to`](../api/basic_json/get_to.md)

*Adds a new overload.*

- Adds 1 new overload.
    ```cpp
    template < typename T, std::size_t N, typename Array = T (&)[N], detail::enable_if_t < detail::has_from_json<basic_json_t, Array>::value, int > = 0 > Array get_to(T (&v)[N]) const noexcept(noexcept(JSONSerializer<Array>: [...]
    ```

**Cosmetic-only changes** (no behavioral/contract difference; omitted above): `nlohmann::basic_json::array`, `nlohmann::basic_json::diff`, `nlohmann::basic_json::from_bson`, `nlohmann::basic_json::from_cbor`, `nlohmann::basic_json::from_msgpack`, `nlohmann::basic_json::from_ubjson`, `nlohmann::basic_json::iterator_wrapper`, `nlohmann::basic_json::meta`, `nlohmann::basic_json::object`, `nlohmann::basic_json::operator[]`, `nlohmann::basic_json::parse`, `nlohmann::basic_json::sax_parse`, `nlohmann::basic_json::type_name`, `nlohmann::basic_json::value`, `nlohmann::operator<<`, `nlohmann::operator>>`.

## 3.6.1

### [`nlohmann::operator<`](../api/basic_json/operator_lt.md)

*Updates the `noexcept` specification.*

- Changed:
    ```diff
      friend bool operator<(const_reference lhs, const_reference rhs) noexcept { const auto lhs_type = lhs.type(); const auto rhs_type = rhs.type(); if (lhs_type == rhs_type) { switch (l
    - *lhs.m_value.array < *rhs.m_value.array;
    + (*lhs.m_value.array) < (*rhs.m_value.array);
      case value_t::object: return *lhs.m_value.object < *rhs.m_value.object; case value_t::null: return false; case value_t::string: return *lhs.m_value.string < *rhs.m_value.string; ca
    ```

## 3.6.0

### [`nlohmann::operator/`](../api/json_pointer/operator_slash.md)

*New addition to the public API.*

- New symbols (3 overloads).
    ```cpp
    friend json_pointer operator/(const json_pointer& lhs, const json_pointer& rhs)
    ```
    ```cpp
    friend json_pointer operator/(const json_pointer& ptr, std::size_t array_index)
    ```
    ```cpp
    friend json_pointer operator/(const json_pointer& ptr, std::string token)
    ```

### [`nlohmann::operator<`](../api/basic_json/operator_lt.md)

*Updates the `noexcept` specification.*

- Changed:
    ```diff
      friend bool operator<(const_reference lhs, const_reference rhs) noexcept { const auto lhs_type = lhs.type(); const auto rhs_type = rhs.type(); if (lhs_type == rhs_type) { switch (l
    - (*lhs.m_value.array) < (*rhs.m_value.array);
    + *lhs.m_value.array < *rhs.m_value.array;
      case value_t::object: return *lhs.m_value.object < *rhs.m_value.object; case value_t::null: return false; case value_t::string: return *lhs.m_value.string < *rhs.m_value.string; ca
    ```

### [`nlohmann::basic_json::contains`](../api/basic_json/contains.md)

*New addition to the public API.*

- New symbol.
    ```cpp
    template<typename KeyT> bool contains(KeyT&& key) const
    ```

### [`nlohmann::basic_json::operator ValueType`](../api/basic_json/operator_ValueType.md)

*Changes the declaration; see the signature diff for details.*

- Changed:
    ```diff
      template < typename ValueType, typename std::enable_if < not std::is_pointer<ValueType>::value and not std::is_same<ValueType, detail::json_ref<basic_json>>::value and not std::is_
    - defined(_MSC_VER) and _MSC_VER <= 1914
    + (defined(__GNUC__) || (defined(_MSC_VER) and _MSC_VER <= 1914))
      and not std::is_same<ValueType, typename std::string_view>::value #endif #endif and detail::is_detected<detail::get_template_function, const basic_json_t&, ValueType>::value , int 
    ```

### `nlohmann::json_pointer::array_index`

*Removed from the public API.*

- Removes 1 overload.
    ```cpp
    static int array_index(const std::string& s)
    ```

### [`nlohmann::json_pointer::back`](../api/json_pointer/back.md)

*New addition to the public API.*

- New symbol.
    ```cpp
    const std::string& back()
    ```

### [`nlohmann::json_pointer::empty`](../api/json_pointer/empty.md)

*New addition to the public API.*

- New symbol.
    ```cpp
    bool empty() const noexcept
    ```

### [`nlohmann::json_pointer::operator/=`](../api/json_pointer/operator_slasheq.md)

*New addition to the public API.*

- New symbols (3 overloads).
    ```cpp
    json_pointer& operator/=(const json_pointer& ptr)
    ```
    ```cpp
    json_pointer& operator/=(std::size_t array_index)
    ```
    ```cpp
    json_pointer& operator/=(std::string token)
    ```

### [`nlohmann::json_pointer::parent_pointer`](../api/json_pointer/parent_pointer.md)

*New addition to the public API.*

- New symbol.
    ```cpp
    json_pointer parent_pointer() const
    ```

### [`nlohmann::json_pointer::pop_back`](../api/json_pointer/pop_back.md)

*New addition to the public API.*

- New symbol.
    ```cpp
    void pop_back()
    ```

### [`nlohmann::json_pointer::push_back`](../api/json_pointer/push_back.md)

*New addition to the public API.*

- New symbols (2 overloads).
    ```cpp
    void push_back(const std::string& token)
    ```
    ```cpp
    void push_back(std::string&& token)
    ```

**Cosmetic-only changes** (no behavioral/contract difference; omitted above): `nlohmann::basic_json::array`, `nlohmann::basic_json::diff`, `nlohmann::basic_json::from_bson`, `nlohmann::basic_json::from_cbor`, `nlohmann::basic_json::from_msgpack`, `nlohmann::basic_json::from_ubjson`, `nlohmann::basic_json::meta`, `nlohmann::basic_json::object`, `nlohmann::basic_json::parse`, `nlohmann::operator<<`.

## 3.5.0

### [`nlohmann::basic_json::merge_patch`](../api/basic_json/merge_patch.md)

*Changes parameter `const basic_json& patch` to `const basic_json& apply_patch`.*

- Changed:
    ```diff
      void merge_patch(const basic_json&
    - patch)
    + apply_patch)
    ```

## 3.4.0

### [`nlohmann::adl_serializer::from_json`](../api/adl_serializer/from_json.md)

*Updates the `noexcept` specification.*

- Changed:
    ```diff
      template<typename BasicJsonType, typename ValueType> static auto from_json(BasicJsonType&& j, ValueType& val) noexcept( noexcept(::nlohmann::from_json(std::forward<BasicJsonType>(j
    - decltype( ::nlohmann::from_json(std::forward<BasicJsonType>(j), val), void() )
    + decltype(::nlohmann::from_json(std::forward<BasicJsonType>(j), val), void())
    ```

### [`nlohmann::basic_json::dump`](../api/basic_json/dump.md)

*Adds an optional `const error_handler_t error_handler` parameter (default `error_handler_t::strict`).*

- Changed:
    ```diff
      string_t dump(const int indent = -1, const char indent_char = ' ', const bool ensure_ascii =
    - false)
    + false, const error_handler_t error_handler = error_handler_t::strict)
      const
    ```

### [`nlohmann::basic_json::error_handler_t`](../api/basic_json/error_handler_t.md)

*New addition to the public API.*

- New symbol.
    ```cpp
    using error_handler_t = detail::error_handler_t
    ```

### [`nlohmann::basic_json::from_bson`](../api/basic_json/from_bson.md)

*New addition to the public API.*

- New symbols (2 overloads).
    ```cpp
    static basic_json from_bson(detail::input_adapter&& i, const bool strict = true, const bool allow_exceptions = true)
    ```
    ```cpp
    template<typename A1, typename A2, detail::enable_if_t<std::is_constructible<detail::input_adapter, A1, A2>::value, int> = 0> static basic_json from_bson(A1 && a1, A2 && a2, const bool strict = true, const bool allow_exc [...]
    ```

### [`nlohmann::basic_json::operator=`](../api/basic_json/operator=.md)

*Updates the `noexcept` specification.*

- Changed:
    ```diff
    - reference&
    + basic_json&
      operator=(basic_json other) noexcept ( std::is_nothrow_move_constructible<value_t>::value and std::is_nothrow_move_assignable<value_t>::value and std::is_nothrow_move_constructible
    ```

### [`nlohmann::basic_json::to_bson`](../api/basic_json/to_bson.md)

*New addition to the public API.*

- New symbols (3 overloads).
    ```cpp
    static std::vector<uint8_t> to_bson(const basic_json& j)
    ```
    ```cpp
    static void to_bson(const basic_json& j, detail::output_adapter<char> o)
    ```
    ```cpp
    static void to_bson(const basic_json& j, detail::output_adapter<uint8_t> o)
    ```

### [`nlohmann::json_pointer::to_string`](../api/json_pointer/to_string.md)

*Updates the `noexcept` specification.*

- Changed:
    ```diff
      std::string to_string() const
    - noexcept
    ```

## 3.3.0

### [`nlohmann::adl_serializer::from_json`](../api/adl_serializer/from_json.md)

*Updates the `noexcept` specification.*

- Changed:
    ```diff
      template<typename BasicJsonType, typename ValueType> static
    - void from_json(BasicJsonType&& j, ValueType& val) noexcept( noexcept(::nlohmann::from_json(std::forward<BasicJsonType>(j), val)))
    + auto from_json(BasicJsonType&& j, ValueType& val) noexcept( noexcept(::nlohmann::from_json(std::forward<BasicJsonType>(j), val))) -> decltype( ::nlohmann::from_json(std::forward<Ba
    ```

### [`nlohmann::adl_serializer::to_json`](../api/adl_serializer/to_json.md)

*Updates the `noexcept` specification.*

- Changed:
    ```diff
    - template<typename BasicJsonType, typename ValueType> static void to_json(BasicJsonType& j, ValueType&& val) noexcept( noexcept(::nlohmann::to_json(j, std::forward<ValueType>(val)))
    + template <typename BasicJsonType, typename ValueType> static auto to_json(BasicJsonType& j, ValueType&& val) noexcept( noexcept(::nlohmann::to_json(j, std::forward<ValueType>(val))
    ```

### [`nlohmann::basic_json::get_ptr`](../api/basic_json/get_ptr.md)

*Updates the `noexcept` specification.*

- Changed:
    ```diff
      template<typename PointerType, typename std::enable_if< std::is_pointer<PointerType>::value and std::is_const<typename std::remove_pointer<PointerType>::type>::value, int>::type = 
    - const PointerType get_ptr() const noexcept
    + auto get_ptr() const noexcept -> decltype(std::declval<const basic_json_t&>().get_impl_ptr(std::declval<PointerType>()))
    ```

### [`nlohmann::basic_json::get_to`](../api/basic_json/get_to.md)

*New addition to the public API.*

- New symbol.
    ```cpp
    template<typename ValueType, detail::enable_if_t < not detail::is_basic_json<ValueType>::value and detail::has_from_json<basic_json_t, ValueType>::value, int> = 0> ValueType & get_to(ValueType& v) const noexcept(noexcept [...]
    ```

### `nlohmann::basic_json::insert_iterator`

*New addition to the public API.*

- New symbol.
    ```cpp
    template<typename... Args> iterator insert_iterator(const_iterator pos, Args&& ... args)
    ```

### [`nlohmann::basic_json::operator ValueType`](../api/basic_json/operator_ValueType.md)

*Adjusts the template constraints (SFINAE) controlling which types this overload participates in overload resolution for.*

- Changed:
    ```diff
      template < typename ValueType, typename std::enable_if < not std::is_pointer<ValueType>::value and not std::is_same<ValueType, detail::json_ref<basic_json>>::value and not std::is_
    + and detail::is_detected<detail::get_template_function, const basic_json_t&, ValueType>::value
      , int >::type = 0 > operator ValueType() const { return get<ValueType>(); }
    ```

**Cosmetic-only changes** (no behavioral/contract difference; omitted above): `nlohmann::basic_json::basic_json`, `nlohmann::basic_json::get`.

## 3.2.0

### [`nlohmann::basic_json::accept`](../api/basic_json/accept.md)

*Changes parameter `detail::input_adapter i` to `detail::input_adapter&& i`.*

- Changed:
    ```diff
      static bool
    - accept(detail::input_adapter
    + accept(detail::input_adapter&&
      i)
    ```

### [`nlohmann::basic_json::from_cbor`](../api/basic_json/from_cbor.md)

*Changes the parameter list.*

- Changed:
    ```diff
      static basic_json
    - from_cbor(detail::input_adapter i, const bool strict
    + from_cbor(detail::input_adapter&& i, const bool strict = true, const bool allow_exceptions
      = true)
    ```

### [`nlohmann::basic_json::from_msgpack`](../api/basic_json/from_msgpack.md)

*Changes the parameter list.*

- Changed:
    ```diff
      static basic_json
    - from_msgpack(detail::input_adapter i, const bool strict
    + from_msgpack(detail::input_adapter&& i, const bool strict = true, const bool allow_exceptions
      = true)
    ```

### [`nlohmann::basic_json::from_ubjson`](../api/basic_json/from_ubjson.md)

*Changes the parameter list.*

- Changed:
    ```diff
      static basic_json
    - from_ubjson(detail::input_adapter i, const bool strict
    + from_ubjson(detail::input_adapter&& i, const bool strict = true, const bool allow_exceptions
      = true)
    ```

### [`nlohmann::basic_json::input_format_t`](../api/basic_json/input_format_t.md)

*New addition to the public API.*

- New symbol.
    ```cpp
    using input_format_t = detail::input_format_t
    ```

### [`nlohmann::basic_json::json_sax_t`](../api/basic_json/json_sax_t.md)

*New addition to the public API.*

- New symbol.
    ```cpp
    using json_sax_t = json_sax<basic_json>
    ```

### [`nlohmann::basic_json::operator ValueType`](../api/basic_json/operator_ValueType.md)

*Adjusts the template constraints (SFINAE) controlling which types this overload participates in overload resolution for.*

- Changed:
    ```diff
      template < typename ValueType, typename std::enable_if < not std::is_pointer<ValueType>::value and not std::is_same<ValueType, detail::json_ref<basic_json>>::value and not std::is_
    - #endif #if defined(JSON_HAS_CPP_17) and not std::is_same<ValueType, typename std::string_view>::value #endif , int >::type = 0 > operator ValueType() const
    + #if defined(JSON_HAS_CPP_17) && defined(_MSC_VER) and _MSC_VER <= 1914 and not std::is_same<ValueType, typename std::string_view>::value #endif #endif , int >::type = 0 > operator 
    ```

### [`nlohmann::basic_json::parse`](../api/basic_json/parse.md)

*Changes parameter `detail::input_adapter i` to `detail::input_adapter&& i`.*

- Changed:
    ```diff
      static basic_json
    - parse(detail::input_adapter
    + parse(detail::input_adapter&&
      i, const parser_callback_t cb = nullptr, const bool allow_exceptions = true)
    ```

### [`nlohmann::basic_json::sax_parse`](../api/basic_json/sax_parse.md)

*New addition to the public API.*

- New symbols (2 overloads).
    ```cpp
    template <typename SAX> static bool sax_parse(detail::input_adapter&& i, SAX* sax, input_format_t format = input_format_t::json, const bool strict = true)
    ```
    ```cpp
    template<class IteratorType, class SAX, typename std::enable_if< std::is_base_of< std::random_access_iterator_tag, typename std::iterator_traits<IteratorType>::iterator_category>::value, int>::type = 0> static bool sax_p [...]
    ```

### [`nlohmann::json_sax::boolean`](../api/json_sax/boolean.md)

*New addition to the public API.*

- New symbol.
    ```cpp
    virtual bool boolean(bool val) = 0
    ```

### [`nlohmann::json_sax::end_array`](../api/json_sax/end_array.md)

*New addition to the public API.*

- New symbol.
    ```cpp
    virtual bool end_array() = 0
    ```

### [`nlohmann::json_sax::end_object`](../api/json_sax/end_object.md)

*New addition to the public API.*

- New symbol.
    ```cpp
    virtual bool end_object() = 0
    ```

### [`nlohmann::json_sax::key`](../api/json_sax/key.md)

*New addition to the public API.*

- New symbol.
    ```cpp
    virtual bool key(string_t& val) = 0
    ```

### [`nlohmann::json_sax::null`](../api/json_sax/null.md)

*New addition to the public API.*

- New symbol.
    ```cpp
    virtual bool null() = 0
    ```

### [`nlohmann::json_sax::number_float`](../api/json_sax/number_float.md)

*New addition to the public API.*

- New symbol.
    ```cpp
    virtual bool number_float(number_float_t val, const string_t& s) = 0
    ```

### [`nlohmann::json_sax::number_float_t`](../api/json_sax/number_float_t.md)

*New addition to the public API.*

- New symbol.
    ```cpp
    using number_float_t = typename BasicJsonType::number_float_t
    ```

### [`nlohmann::json_sax::number_integer`](../api/json_sax/number_integer.md)

*New addition to the public API.*

- New symbol.
    ```cpp
    virtual bool number_integer(number_integer_t val) = 0
    ```

### [`nlohmann::json_sax::number_integer_t`](../api/json_sax/number_integer_t.md)

*New addition to the public API.*

- New symbol.
    ```cpp
    using number_integer_t = typename BasicJsonType::number_integer_t
    ```

### [`nlohmann::json_sax::number_unsigned`](../api/json_sax/number_unsigned.md)

*New addition to the public API.*

- New symbol.
    ```cpp
    virtual bool number_unsigned(number_unsigned_t val) = 0
    ```

### [`nlohmann::json_sax::number_unsigned_t`](../api/json_sax/number_unsigned_t.md)

*New addition to the public API.*

- New symbol.
    ```cpp
    using number_unsigned_t = typename BasicJsonType::number_unsigned_t
    ```

### [`nlohmann::json_sax::parse_error`](../api/json_sax/parse_error.md)

*New addition to the public API.*

- New symbol.
    ```cpp
    virtual bool parse_error(std::size_t position, const std::string& last_token, const detail::exception& ex) = 0
    ```

### [`nlohmann::json_sax::start_array`](../api/json_sax/start_array.md)

*New addition to the public API.*

- New symbol.
    ```cpp
    virtual bool start_array(std::size_t elements) = 0
    ```

### [`nlohmann::json_sax::start_object`](../api/json_sax/start_object.md)

*New addition to the public API.*

- New symbol.
    ```cpp
    virtual bool start_object(std::size_t elements) = 0
    ```

### [`nlohmann::json_sax::string`](../api/json_sax/string.md)

*New addition to the public API.*

- New symbol.
    ```cpp
    virtual bool string(string_t& val) = 0
    ```

### [`nlohmann::json_sax::string_t`](../api/json_sax/string_t.md)

*New addition to the public API.*

- New symbol.
    ```cpp
    using string_t = typename BasicJsonType::string_t
    ```

### [`nlohmann::json_sax::~json_sax`](../api/json_sax/~json_sax.md)

*New addition to the public API.*

- New symbol.
    ```cpp
    virtual ~json_sax() = default
    ```

## 3.1.2

### [`nlohmann::basic_json::basic_json`](../api/basic_json/basic_json.md)

*Adds a new overload.*

- Adds 1 new overload.
    ```cpp
    template <typename BasicJsonType, detail::enable_if_t< detail::is_basic_json<BasicJsonType>::value and not std::is_same<basic_json, BasicJsonType>::value, int> = 0> basic_json(const BasicJsonType& val)
    ```

### [`nlohmann::basic_json::get`](../api/basic_json/get.md)

*Adjusts the template constraints (SFINAE) controlling which types this overload participates in overload resolution for.*

- Changed:
    ```diff
      template<typename BasicJsonType, detail::enable_if_t<
    - std::is_same<typename std::remove_const<BasicJsonType>::type, basic_json_t>::value, int> = 0> basic_json
    + not std::is_same<BasicJsonType, basic_json>::value and detail::is_basic_json<BasicJsonType>::value, int> = 0> BasicJsonType
      get() const
    ```

### [`nlohmann::basic_json::operator ValueType`](../api/basic_json/operator_ValueType.md)

*Adjusts the template constraints (SFINAE) controlling which types this overload participates in overload resolution for.*

- Changed:
    ```diff
      template < typename ValueType, typename std::enable_if < not std::is_pointer<ValueType>::value and not std::is_same<ValueType, detail::json_ref<basic_json>>::value and not std::is_
    + and not detail::is_basic_json<ValueType>::value
      #ifndef _MSC_VER and not std::is_same<ValueType, std::initializer_list<typename string_t::value_type>>::value #endif #if defined(JSON_HAS_CPP_17) and not std::is_same<ValueType, ty
    ```
