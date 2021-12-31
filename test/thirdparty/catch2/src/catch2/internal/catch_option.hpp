
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
#ifndef CATCH_OPTION_HPP_INCLUDED
#define CATCH_OPTION_HPP_INCLUDED

namespace Catch {

    // An optional type
    template<typename T>
    class Option {
    public:
        Option() : nullableValue( nullptr ) {}
        Option( T const& _value )
        : nullableValue( new( storage ) T( _value ) )
        {}
        Option( Option const& _other )
        : nullableValue( _other ? new( storage ) T( *_other ) : nullptr )
        {}

        ~Option() {
            reset();
        }

        Option& operator= ( Option const& _other ) {
            if( &_other != this ) {
                reset();
                if( _other )
                    nullableValue = new( storage ) T( *_other );
            }
            return *this;
        }
        Option& operator = ( T const& _value ) {
            reset();
            nullableValue = new( storage ) T( _value );
            return *this;
        }

        void reset() {
            if( nullableValue )
                nullableValue->~T();
            nullableValue = nullptr;
        }

        T& operator*() { return *nullableValue; }
        T const& operator*() const { return *nullableValue; }
        T* operator->() { return nullableValue; }
        const T* operator->() const { return nullableValue; }

        T valueOr( T const& defaultValue ) const {
            return nullableValue ? *nullableValue : defaultValue;
        }

        bool some() const { return nullableValue != nullptr; }
        bool none() const { return nullableValue == nullptr; }

        bool operator !() const { return nullableValue == nullptr; }
        explicit operator bool() const {
            return some();
        }

    private:
        T *nullableValue;
        alignas(alignof(T)) char storage[sizeof(T)];
    };

} // end namespace Catch

#endif // CATCH_OPTION_HPP_INCLUDED
