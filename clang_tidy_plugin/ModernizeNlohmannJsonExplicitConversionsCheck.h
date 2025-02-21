// SPDX-FileCopyrightText: 2025 Mike Crowe
// SPDX-License-Identifier: MIT

#ifndef LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_MODERNIZE_NLOHMANNJSONEXPLICITCONVERSIONSCHECK_H
#define LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_MODERNIZE_NLOHMANNJSONEXPLICITCONVERSIONSCHECK_H

#include "clang-tidy/ClangTidyCheck.h"

namespace clang::tidy::modernize {

/// Convert implicit conversions via operator ValueType() from nlohmann::json to
/// explicit calls to the get<> method because the next major version of the
/// library will remove support for implicit conversions.
///
/// For the user-facing documentation see:
/// https://clang.llvm.org/extra/clang-tidy/checks/modernize/nlohmann-json-explicit-conversions.html
class NlohmannJsonExplicitConversionsCheck : public ClangTidyCheck {
public:
  NlohmannJsonExplicitConversionsCheck(StringRef Name,
                                       ClangTidyContext *Context)
      : ClangTidyCheck(Name, Context) {}
  void registerMatchers(ast_matchers::MatchFinder *Finder) override;
  void check(const ast_matchers::MatchFinder::MatchResult &Result) override;
  bool isLanguageVersionSupported(const LangOptions &LangOpts) const override {
    return LangOpts.CPlusPlus;
  }
};

} // namespace clang::tidy::modernize

#endif // LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_MODERNIZE_NLOHMANNJSONEXPLICITCONVERSIONSCHECK_H
