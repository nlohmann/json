#pragma once

#include <cstddef> // size_t
#include <string> // string, to_string
#include <iterator> // input_iterator_tag

#include <nlohmann/detail/value_t.hpp>

namespace nlohmann
{
namespace detail
{
/// proxy class for the items() function
template<typename IteratorType> class iteration_proxy
{
  private:
    /// helper class for iteration
    class iteration_proxy_internal
    {
      public:
        using difference_type = std::ptrdiff_t;
        using value_type = iteration_proxy_internal;
        using pointer = iteration_proxy_internal*;
        using reference = iteration_proxy_internal&;
        using iterator_category = std::input_iterator_tag;

      private:
        /// the iterator
        IteratorType anchor;
        /// an index for arrays (used to create key names)
        std::size_t array_index = 0;
        /// last stringified array index
        mutable std::size_t array_index_last = 0;
        /// a string representation of the array index
        mutable std::string array_index_str = "0";
        /// an empty string (to return a reference for primitive values)
        const std::string empty_str = "";

      public:
        explicit iteration_proxy_internal(IteratorType it) noexcept : anchor(it) {}

        /// dereference operator (needed for range-based for)
        iteration_proxy_internal& operator*()
        {
            return *this;
        }

        /// increment operator (needed for range-based for)
        iteration_proxy_internal& operator++()
        {
            ++anchor;
            ++array_index;

            return *this;
        }

        /// equality operator (needed for InputIterator)
        bool operator==(const iteration_proxy_internal& o) const noexcept
        {
            return anchor == o.anchor;
        }

        /// inequality operator (needed for range-based for)
        bool operator!=(const iteration_proxy_internal& o) const noexcept
        {
            return anchor != o.anchor;
        }

        /// return key of the iterator
        const std::string& key() const
        {
            assert(anchor.m_object != nullptr);

            switch (anchor.m_object->type())
            {
                // use integer array index as key
                case value_t::array:
                {
                    if (array_index != array_index_last)
                    {
                        array_index_str = std::to_string(array_index);
                        array_index_last = array_index;
                    }
                    return array_index_str;
                }

                // use key from the object
                case value_t::object:
                    return anchor.key();

                // use an empty key for all primitive types
                default:
                    return empty_str;
            }
        }

        /// return value of the iterator
        typename IteratorType::reference value() const
        {
            return anchor.value();
        }
    };

    /// the container to iterate
    typename IteratorType::reference container;

  public:
    /// construct iteration proxy from a container
    explicit iteration_proxy(typename IteratorType::reference cont) noexcept
        : container(cont) {}

    /// return iterator begin (needed for range-based for)
    iteration_proxy_internal begin() noexcept
    {
        return iteration_proxy_internal(container.begin());
    }

    /// return iterator end (needed for range-based for)
    iteration_proxy_internal end() noexcept
    {
        return iteration_proxy_internal(container.end());
    }
};
}  // namespace detail
}  // namespace nlohmann
