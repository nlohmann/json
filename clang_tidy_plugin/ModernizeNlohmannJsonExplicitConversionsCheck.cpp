// SPDX-FileCopyrightText: 2025 Mike Crowe
// SPDX-License-Identifier: MIT

#include "ModernizeNlohmannJsonExplicitConversionsCheck.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/Lex/Lexer.h"

using namespace clang::ast_matchers;

namespace {
    void replaceAll(std::string &Str, const std::string &From, const std::string &To) {
        assert(!From.empty());

        std::string::size_type StartPos = 0;
        while ((StartPos = Str.find(From, StartPos)) != std::string::npos) {
            Str.replace(StartPos, From.length(), To);
            StartPos += To.length();
        }
    }
}

namespace clang::tidy::modernize {

void NlohmannJsonExplicitConversionsCheck::registerMatchers(
    MatchFinder *Finder) {
  auto Matcher =
      cxxMemberCallExpr(
          on(expr().bind("arg")),
          callee(cxxConversionDecl(ofClass(hasName("nlohmann::basic_json")))
                     .bind("conversionDecl")))
          .bind("conversionCall");
  Finder->addMatcher(Matcher, this);
}

void NlohmannJsonExplicitConversionsCheck::check(
    const MatchFinder::MatchResult &Result) {
  const auto *Decl =
      Result.Nodes.getNodeAs<CXXConversionDecl>("conversionDecl");
  const auto *Call =
      Result.Nodes.getNodeAs<CXXMemberCallExpr>("conversionCall");
  const auto *Arg = Result.Nodes.getNodeAs<Expr>("arg");

  const QualType DestinationType = Decl->getConversionType();
  std::string DestinationTypeStr =
      DestinationType.getAsString(Result.Context->getPrintingPolicy());
  replaceAll(DestinationTypeStr, "std::basic_string<char>", "std::string");

  const SourceRange ExprRange = Call->getSourceRange();
  if (!ExprRange.isValid())
    return;

  bool Deref = false;
  if (const auto *Op = llvm::dyn_cast<UnaryOperator>(Arg);
      Op && Op->getOpcode() == UO_Deref)
    Deref = true;
  else if (const auto *Op = llvm::dyn_cast<CXXOperatorCallExpr>(Arg);
           Op && Op->getOperator() == OO_Star)
    Deref = true;

  llvm::StringRef SourceText = clang::Lexer::getSourceText(
      clang::CharSourceRange::getTokenRange(ExprRange), *Result.SourceManager,
      Result.Context->getLangOpts());

  if (Deref)
    SourceText.consume_front("*");

  const std::string ReplacementText =
      (llvm::Twine(SourceText) + (Deref ? "->" : ".") + "get<" +
       DestinationTypeStr + ">()")
          .str();
  diag(Call->getExprLoc(),
       "implicit nlohmann::json conversion to %0 should be explicit")
      << DestinationTypeStr
      << FixItHint::CreateReplacement(CharSourceRange::getTokenRange(ExprRange),
                                      ReplacementText);
}

} // namespace clang::tidy::modernize
