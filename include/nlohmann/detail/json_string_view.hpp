#pragma once

// ------------------------------------------------------------------------
// This header, and the associated changes in json.hpp enable string_view and struct { const char * } as a map_key type.
//
// Why would you want this?  In my case, I am using millions of json objects, each one uses the same keys.
// Why use objects at all?  This is a question for another time.
//
// In any case, since my keys are known, and finite, I would rather there be a key look-up table, so as to no have a billion copies
// of "transform" lying around.  I would rather just have one.
//
// The differences of string_view and const char * are simple.
// string_view uses a strcmp in it's core of the map lookup, so there is no performance increase.
// struct { const char * } uses a pure pointer comparison, so map operations are super fast, and as well, the map should probably be changed
// into a hash map using the pointers.
//
// The draw back of the struct { const char * }, is that, for the full performance, you must cache the correct to_map_key("my_key_value")
// and use that (so it doesn't need to look up the correct pointer first).  This is trivial to do however, so, the performance increase
// is great.
//
// ------------------------------------------------------------------------

#include <functional>

#ifdef USE_EXPERIMENTAL_STRINGVIEW
#include <experimental/string_view>
#endif

namespace nlohmann
{


#ifdef USE_EXPERIMENTAL_STRINGVIEW
using json_string_view = std::experimental::string_view;
#else

// a minimum implementation of string_view
struct json_string_view
{
	const char *data_;
	size_t size_;
	
	json_string_view(const char *data, size_t size) :
		data_(data), size_(size)
	{}

	json_string_view(const char *data) :
		data_(data), size_(strlen(data))
	{}
	
	json_string_view(const std::string &s) :
		data_(s.c_str()), size_(s.size())
	{
	}
	
	json_string_view (const json_string_view &rhs) :
		data_(rhs.data_), size_(rhs.size_)
	{}

	json_string_view (json_string_view &&rhs) :
		data_(rhs.data_), size_(rhs.size_)
	{}
	
	const char *data() const
	{
		return data_;
	}
	
	size_t size() const
	{
		return size_;
	}
	
	operator std::string() const
	{
		return std::string(data_, size_);
	}
	
	const char *begin() const
	{
		return data_;
	}
	
	const char *end () const
	{
		return data_ + size_;
	}
} ;

inline
bool operator ==(const json_string_view &l, const json_string_view &r)
{
	if (l.data_ == r.data_ && l.size_ == r.size_)
		return true;
	
	return l.size_ == r.size_ && strncmp(l.data_, r.data_, l.size_) == 0;
}

inline
bool operator !=(const json_string_view &l, const json_string_view &r)
{
	return !(l == r);
}

inline
bool operator <(const json_string_view &l, const json_string_view &r)
{
	// will implement, i need to look up proper way to do this
	std::string ls(l);
	std::string rs(r);
	return ls < rs;
}

inline
std::ostream &operator <<(std::ostream &l, const json_string_view &r)
{
	return l << std::string(r);
}

} // namespace

// this is gross, yes I know, it probably shouldn't be done this way, copied from example
// on the internetz
namespace std {

template <>
struct hash<nlohmann::json_string_view>
{
	hash<std::string> hasher;
	
	size_t operator()(const nlohmann::json_string_view& k_) const
	{
		std::string k(k_.data(), k_.size());
		// Compute individual hash values for two data members and combine them using XOR and bit shifting
		return hasher(k);
	}
};

} // namespace


#endif

namespace nlohmann {

// -----------------------


struct json_const_char_star {
	const char *data;
	
	json_const_char_star(const char *s);
	json_const_char_star(const std::string &s);
	json_const_char_star(const json_const_char_star &rhs) :
		data(rhs.data) {}
	json_const_char_star(json_const_char_star &&rhs) :
		data(rhs.data) {}
} ;

inline
bool operator ==(const json_const_char_star &l, const json_const_char_star &r)
{
	return (l.data == r.data);
}

inline
bool operator !=(const json_const_char_star &l, const json_const_char_star &r)
{
	return !(l == r);
}

inline
bool operator <(const json_const_char_star &l, const json_const_char_star &r)
{
	// pure pointer compare
	return l.data < r.data;
}

inline
std::ostream &operator <<(std::ostream &l, const json_const_char_star &r)
{
	return l << std::string(r.data);
}

} // namespace

// this is gross, yes I know, it probably shouldn't be done this way, copied from example
// on the internetz
namespace std {

template <>
struct hash<nlohmann::json_const_char_star>
{
	hash<unsigned long long> hasher;
	
	size_t operator()(const nlohmann::json_const_char_star& k) const
	{
		// Compute individual hash values for two data members and combine them using XOR and bit shifting
		return hasher(reinterpret_cast<unsigned long long>(k.data));
	}
};
	
} // namespace


namespace nlohmann {

// -------------------

// why am I having trouble getting rid of this? it must be too late
typedef const char *__stupid_const_char_typedef;

template<typename R> inline R to_map_key(const __stupid_const_char_typedef &s);
template<typename R> inline R to_map_key(const json_string_view &s);
template<typename R> inline R to_map_key(const std::string &s);
template<typename R> inline R to_map_key(const json_const_char_star &s);

template<typename R> inline R to_lookup_key(const __stupid_const_char_typedef &s);
template<typename R> inline R to_lookup_key(const json_string_view &s);
template<typename R> inline R to_lookup_key(const std::string &s);
template<typename R> inline R to_lookup_key(const json_const_char_star &s);

template<typename R, typename T> R to_concatable_string(const T &t);


template<>
inline
std::string to_map_key(const std::string &t)
{
	return t;
}

template<>
inline
std::string to_lookup_key(const std::string &t)
{
	return t;
}

template<>
inline
std::string to_concatable_string(const std::string &t)
{
	return t;
}

// -------------------
 
template<>
inline json_string_view to_map_key(const json_string_view &s)
{
	static std::set<std::string> strings;
	static std::set<json_string_view> internals;

	auto i = internals.find(s);
	if (i == internals.end())
	{
		std::string str(s.begin(), s.end());
		strings.insert(str);
		
		auto sv = json_string_view(*strings.find(str));

		internals.insert(sv);
		return sv;
	}

	return *i;
} ;

template<>
inline json_string_view to_map_key(const std::string &s)
{
	return to_map_key<json_string_view>(json_string_view(s));
} ;

template<>
inline json_string_view to_map_key(const __stupid_const_char_typedef &s)
{
	return to_map_key<json_string_view>(json_string_view(s, strlen(s)));
}

// -----------------------
 
template<>
inline json_string_view to_lookup_key(const json_string_view &s)
{
	return s;
}

template<>
inline json_string_view to_lookup_key(const std::string &s)
{
	return json_string_view(s);
} ;

template<>
inline json_string_view to_lookup_key(const __stupid_const_char_typedef &s)
{
	return json_string_view(s, strlen(s));
} ;

template<>
inline
std::string to_concatable_string(const json_string_view &t)
{
	return std::string(t.data(), t.size());
}

// -----------------------


inline const char *generate_json_const_char_star(const std::string &s)
{
	static std::set<std::string> strings;

	auto i = strings.find(s);
	if (i == strings.end())
	{
		std::string str(s);
		strings.insert(str);
		
		i = strings.find(str);
	}

	return i->c_str();
} ;

template<>
inline json_const_char_star to_map_key(const std::string &s)
{
	return json_const_char_star(s);
}

template<>
inline json_const_char_star to_map_key(const __stupid_const_char_typedef &s)
{
	return to_map_key<json_const_char_star>(std::string(s));
}

template<>
inline json_const_char_star to_map_key(const json_const_char_star &s)
{
	return s;
}

template<>
inline json_const_char_star to_lookup_key(const std::string &s)
{
	return to_map_key<json_const_char_star>(s);
} ;

template<>
inline json_const_char_star to_lookup_key(const __stupid_const_char_typedef &s)
{
	return to_map_key<json_const_char_star>(s);
}

template<>
inline json_const_char_star to_lookup_key(const json_const_char_star &s)
{
	return s;
}

template<>
inline
std::string to_concatable_string(const json_const_char_star &t)
{
	return std::string(t.data);
}

// ---------------------------------------

inline json_const_char_star::json_const_char_star(const std::string &s) :
	data(generate_json_const_char_star(s))
{
}

inline json_const_char_star::json_const_char_star(const char *s) :
	data(generate_json_const_char_star(s))
{
}

} // namespace
