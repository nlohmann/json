#pragma once

#include <functional> // less
#include <memory> // allocator
#include <utility> // pair
#include <vector> // vector

namespace nlohmann
{

/// ordered_map: a minimal map-like container that preserves insertion order
/// for use within nlohmann::basic_json<ordered_map>
template <class Key, class T, class IgnoredLess = std::less<Key>,
          class Allocator = std::allocator<std::pair<const Key, T>>>
struct ordered_map : std::vector<typename Allocator::value_type, Allocator>
{
    using Container = std::vector<typename Allocator::value_type, Allocator>;
    using key_type = Key;
    using mapped_type = T;
    using typename Container::iterator;
    using typename Container::value_type;
    using typename Container::size_type;
    using Container::Container;

    std::pair<iterator, bool> emplace(key_type&& key, T&& t)
    {
        for (auto it = this->begin(); it != this->end(); ++it)
        {
            if (it->first == key)
            {
                return {it, false};
            }
        }
        Container::emplace_back(key, t);
        return {--this->end(), true};
    }

    T& operator[](Key&& key)
    {
        return emplace(std::move(key), T{}).first->second;
    }

    size_type erase(const Key& key)
    {
        for (auto it = this->begin(); it != this->end(); ++it)
        {
            if (it->first == key)
            {
                // Since we cannot move const Keys, re-construct them in place
                for (auto next = it; ++next != this->end(); ++it)
                {
                    // *it = std::move(*next); // deleted
                    it->~value_type(); // Destroy but keep allocation
                    new (&*it) value_type{std::move(*next)};
                }
                Container::pop_back();
                return 1;
            }
        }
        return 0;
    }
};

}  // namespace nlohmann
