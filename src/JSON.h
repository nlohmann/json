#pragma once

// a helper macro to detect C++11 compliant compilers
#if __cplusplus >= 201103L
#define __cplusplus11
#endif

// STL containers
#include <string>
#include <vector>
#include <map>

// additional C++11 headers
#ifdef __cplusplus11
#include <mutex>
#include <initializer_list>
#endif

class JSON {
    // forward declaration to friend this class
    public:
        class iterator;
        class const_iterator;

#ifdef __cplusplus11
    private:
        /// mutex to guard payload
        static std::mutex _token;
#endif

    public:
        /// possible types of a JSON object
        typedef enum {
            array, object, null, string, boolean, number, number_float
        } json_t;

    public:
        /// a type for an object
        typedef std::map<std::string, JSON> object_t;
        /// a type for an array
        typedef std::vector<JSON> array_t;
        /// a type for a string
        typedef std::string string_t;
        /// a type for a Boolean
        typedef bool boolean_t;
        /// a type for an integer number
        typedef int number_t;
        /// a type for a floating point number
        typedef double number_float_t;

        /// a JSON value
        union value {
            /// array as pointer to array_t
            array_t* array;
            /// object as pointer to object_t
            object_t* object;
            /// string as pointer to string_t
            string_t* string;
            /// Boolean
            boolean_t boolean;
            /// number (integer)
            number_t number;
            /// number (float)
            number_float_t number_float;

            /// default constructor
            value() {}
            /// constructor for arrays
            value(array_t* array): array(array) {}
            /// constructor for objects
            value(object_t* object): object(object) {}
            /// constructor for strings
            value(string_t* string): string(string) {}
            /// constructor for Booleans
            value(boolean_t boolean) : boolean(boolean) {}
            /// constructor for numbers (integer)
            value(number_t number) : number(number) {}
            /// constructor for numbers (float)
            value(number_float_t number_float) : number_float(number_float) {}
        };

    private:
        /// the type of this object
        json_t _type;

        /// the payload
        value _value;
        
#ifdef __cplusplus11
        /// a type for array initialization
        typedef std::initializer_list<JSON> array_init_t;
#endif

    public:
        /// create a null object
        JSON();
        /// create an object according to given type
        JSON(json_t);
        /// create a string object from a C++ string
        JSON(const std::string&);
        /// create a string object from a C string
        JSON(char*);
        /// create a string object from a C string
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
        /// implicit conversion to JSON vector (not for objects)
        operator std::vector<JSON>() const;
        /// implicit conversion to JSON map (only for objects)
        operator std::map<std::string, JSON>() const;

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
        /// find an element in an object (returns end() iterator otherwise)
        const_iterator find(const std::string&) const;
        /// find an element in an object (returns end() iterator otherwise)
        iterator find(const char*);
        /// find an element in an object (returns end() iterator otherwise)
        const_iterator find(const char*) const;

        /// direct access to the underlying payload
        value data();
        /// direct access to the underlying payload
        const value data() const;

        /// lexicographically compares the values
        bool operator==(const JSON&) const;
        /// lexicographically compares the values
        bool operator!=(const JSON&) const;

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
        /// a helper class to parse a JSON object
        class parser {
            public:
                /// a parser reading from a C string
                parser(char*);
                /// a parser reading from a C++ string
                parser(std::string&);
                /// a parser reading from an input stream
                parser(std::istream&);
                /// destructor of the parser
                ~parser();
                /// parse into a given JSON object
                void parse(JSON&);

            private:
                /// read the next character, stripping whitespace
                bool next();
                /// raise an exception with an error message
                void error(std::string) __attribute__((noreturn));
                /// parse a quoted string
                std::string parseString();
                /// parse a Boolean "true"
                void parseTrue();
                /// parse a Boolean "false"
                void parseFalse();
                /// parse a null object
                void parseNull();
                /// a helper function to expect a certain character
                void expect(char);

                /// the current character
                char _current;
                /// a buffer of the input
                char* _buffer;
                /// the position inside the input buffer
                size_t _pos;
                /// the length of the input buffer
                size_t _length;
        };
};
