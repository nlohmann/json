#pragma once

#include <iterator> // random_access_iterator_tag

#include <nlohmann/detail/meta/void_t.hpp>

namespace nlohmann
{
namespace detail
{
template <class It, class = void>
struct _iterator_types {};

template <class It>
struct _iterator_types<
    It,
    void_t<typename It::difference_type, typename It::value_type, typename It::pointer,
           typename It::reference, typename It::iterator_category>> {
  using difference_type = typename It::difference_type;
  using value_type = typename It::value_type;
  using pointer = typename It::pointer;
  using reference = typename It::reference;
  using iterator_category = typename It::iterator_category;
};

template <class Iter>
struct iterator_traits : _iterator_types<Iter> {};

template <class T>
struct iterator_traits<T*> {
  typedef std::random_access_iterator_tag iterator_category;
  typedef T value_type;
  typedef ptrdiff_t difference_type;
  typedef T* pointer;
  typedef T& reference;
};

template <class T>
struct iterator_traits<const T*> {
  typedef std::random_access_iterator_tag iterator_category;
  typedef T value_type;
  typedef ptrdiff_t difference_type;
  typedef const T* pointer;
  typedef const T& reference;
};
}
}