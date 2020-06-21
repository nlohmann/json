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
          class Allocator = std::allocator<std::pair<Key, T>>,
          class Container = std::vector<std::pair<Key, T>, Allocator>>
struct ordered_map : Container
{
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
                Container::erase(it);
                return 1;
            }
        }
        return 0;
    }
};

}  // namespace nlohmann
