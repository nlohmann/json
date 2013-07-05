#pragma once

// a helper macro to detect C++11 compliant compilers
#if __cplusplus >= 201103L
#define __cplusplus11
#endif

// allow us to use "nullptr" everywhere
#include <cstddef>
#ifndef nullptr
#define nullptr NULL
#endif

#include <string>
#include <vector>
#include <map>

// additional C++11 header
#ifdef __cplusplus11
#include <mutex>
#include <initializer_list>
#endif

class JSON {
        // forward declaration to friend this class
    public:
        class iterator;
        class const_iterator;

    private:
#ifdef __cplusplus11
        /// mutex to guard payload
        static std::mutex _token;
#endif

    public:
        /// possible types of a JSON object
        typedef enum {
            array, object, null, string, boolean, number, number_float
        } json_t;

    private:
        /// the type of this object
        json_t _type;

        /// the payload
        void* _payload;

    public:
        /// a type for an object
        typedef std::map<std::string, JSON> object_t;
        /// a type for an array
        typedef std::vector<JSON> array_t;

#ifdef __cplusplus11
        /// a type for array initialization
        typedef std::initializer_list<JSON> array_init_t;
#endif

    public:
        /// create an empty (null) object
        JSON();
        /// create an empty object according to given type
        JSON(json_t);
        /// create a string object from C++ string
        JSON(const std::string&);
        /// create a string object from C string
        JSON(char*);
        /// create a string object from C string
        JSON(const char*);
        /// create a Boolean object
        JSON(const bool);
        /// create a number object
        JSON(const int);
        /// create a number object
        JSON(const double);
        /// create an array
        JSON(array_t);
        /// create an object
        JSON(object_t);
#ifdef __cplusplus11
        /// create from an initializer list (to an array)
        JSON(array_init_t);
#endif

        /// copy constructor
        JSON(const JSON&);

#ifdef __cplusplus11
        /// move constructor
        JSON(JSON&&);
#endif

        /// copy assignment
#ifdef __cplusplus11
        JSON& operator=(JSON);
#else
        JSON& operator=(const JSON&);
#endif

        /// destructor
        ~JSON();

        /// implicit conversion to string representation
        operator const std::string() const;
        /// implicit conversion to integer (only for numbers)
        operator int() const;
        /// implicit conversion to double (only for numbers)
        operator double() const;
        /// implicit conversion to Boolean (only for Booleans)
        operator bool() const;

        /// write to stream
        friend std::ostream& operator<<(std::ostream& o, const JSON& j) {
            o << j.toString();
            return o;
        }

        /// write to stream
        friend std::ostream& operator>>(const JSON& j, std::ostream& o) {
            o << j.toString();
            return o;
        }

        /// read from stream
        friend std::istream& operator>>(std::istream& i, JSON& j) {
            parser(i).parse(j);
            return i;
        }

        /// read from stream
        friend std::istream& operator<<(JSON& j, std::istream& i) {
            parser(i).parse(j);
            return i;
        }

        /// explicit conversion to string representation (C++ style)
        const std::string toString() const;

        /// add an object/array to an array
        JSON& operator+=(const JSON&);
        /// add a string to an array
        JSON& operator+=(const std::string&);
        /// add a string to an array
        JSON& operator+=(const char*);
        /// add a Boolean to an array
        JSON& operator+=(bool);
        /// add a number to an array
        JSON& operator+=(int);
        /// add a number to an array
        JSON& operator+=(double);

        /// add an object/array to an array
        void push_back(const JSON&);
        /// add a string to an array
        void push_back(const std::string&);
        /// add a string to an array
        void push_back(const char*);
        /// add a Boolean to an array
        void push_back(bool);
        /// add a number to an array
        void push_back(int);
        /// add a number to an array
        void push_back(double);

        /// operator to set an element in an array
        JSON& operator[](int);
        /// operator to get an element in an array
        const JSON& operator[](const int) const;

        /// operator to set an element in an object
        JSON& operator[](const std::string&);
        /// operator to set an element in an object
        JSON& operator[](const char*);
        /// operator to get an element in an object
        const JSON& operator[](const std::string&) const;

        /// return the number of stored values
        size_t size() const;
        /// checks whether object is empty
        bool empty() const;

        /// return the type of the object
        json_t type() const;

        /// find an element in an object (returns end() iterator otherwise)
        iterator find(const std::string&);
        const_iterator find(const std::string&) const;
        iterator find(const char*);
        const_iterator find(const char*) const;

        /// direct access to the underlying payload
        void* data();
        /// direct access to the underlying payload
        const void* data() const;

        /// lexicographically compares the values
        bool operator==(const JSON&) const;

    private:
        /// return the type as string
        std::string _typename() const;

    public:
        /// an iterator
        class iterator {
                friend class JSON;
                friend class JSON::const_iterator;
            public:
                iterator();
                iterator(JSON*);
                iterator(const iterator&);
                ~iterator();

                iterator& operator=(const iterator&);
                bool operator==(const iterator&) const;
                bool operator!=(const iterator&) const;
                iterator& operator++();
                JSON& operator*() const;
                JSON* operator->() const;

                /// getter for the key (in case of objects)
                std::string key() const;
                /// getter for the value
                JSON& value() const;

            private:
                /// a JSON value
                JSON* _object;
                /// an iterator for JSON arrays
                array_t::iterator* _vi;
                /// an iterator for JSON objects
                object_t::iterator* _oi;
        };

        /// a const iterator
        class const_iterator {
                friend class JSON;
            public:
                const_iterator();
                const_iterator(const JSON*);
                const_iterator(const const_iterator&);
                const_iterator(const iterator&);
                ~const_iterator();

                const_iterator& operator=(const const_iterator&);
                bool operator==(const const_iterator&) const;
                bool operator!=(const const_iterator&) const;
                const_iterator& operator++();
                const JSON& operator*() const;
                const JSON* operator->() const;

                /// getter for the key (in case of objects)
                std::string key() const;
                /// getter for the value
                const JSON& value() const;

            private:
                /// a JSON value
                const JSON* _object;
                /// an iterator for JSON arrays
                array_t::const_iterator* _vi;
                /// an iterator for JSON objects
                object_t::const_iterator* _oi;
        };

    public:
        iterator begin();
        iterator end();
        const_iterator begin() const;
        const_iterator end() const;
        const_iterator cbegin() const;
        const_iterator cend() const;

    private:
        class parser {
            public:
                parser(char*);
                parser(std::string&);
                parser(std::istream&);
                ~parser();
                void parse(JSON&);

            private:
                bool next();
                void error(std::string = "");
                std::string parseString();
                void parseTrue();
                void parseFalse();
                void parseNull();
                void expect(char);

                char _current;
                char* _buffer;
                size_t _pos;
                size_t _length;
        };
};
