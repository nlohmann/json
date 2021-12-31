
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
#ifndef CATCH_EXCEPTION_TRANSLATOR_REGISTRY_HPP_INCLUDED
#define CATCH_EXCEPTION_TRANSLATOR_REGISTRY_HPP_INCLUDED

#include <catch2/interfaces/catch_interfaces_exception.hpp>
#include <vector>
#include <string>

namespace Catch {

    class ExceptionTranslatorRegistry : public IExceptionTranslatorRegistry {
    public:
        ~ExceptionTranslatorRegistry();
        virtual void registerTranslator( const IExceptionTranslator* translator );
        std::string translateActiveException() const override;
        std::string tryTranslators() const;

    private:
        ExceptionTranslators m_translators;
    };
}

#endif // CATCH_EXCEPTION_TRANSLATOR_REGISTRY_HPP_INCLUDED
