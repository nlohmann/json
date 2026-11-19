// SPDX-FileCopyrightText: 2025-2026 Mike Crowe
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
  auto ExplicitCast = explicitCastExpr().bind("cast");
  auto ParentCast = anyOf(
      hasParent(ExplicitCast),
      hasParent(initListExpr(unless(hasInit(1, expr())),
                             hasParent(ExplicitCast))));
  auto Matcher =
      cxxMemberCallExpr(
          on(expr().bind("arg")),
          callee(cxxConversionDecl(ofClass(hasName("nlohmann::basic_json")))
                     .bind("conversionDecl")),
          optionally(expr(isInTemplateInstantiation()).bind("instantiation")),
          optionally(hasParent(implicitCastExpr(
              hasCastKind(CK_UserDefinedConversion),
              anyOf(ParentCast,
                    hasParent(cxxBindTemporaryExpr(ParentCast)))))))
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
  const auto *Cast = Result.Nodes.getNodeAs<ExplicitCastExpr>("cast");

  const QualType DestinationType = Decl->getConversionType();

  // Ensure that OneInt{j} keeps the cast.
  if (Cast && !Result.Context->hasSameUnqualifiedType(Cast->getType(),
                                                      DestinationType))
    Cast = nullptr;

  std::string DestinationTypeStr =
      DestinationType.getAsString(Result.Context->getPrintingPolicy());
  replaceAll(DestinationTypeStr, "std::basic_string<char>", "std::string");

  const SourceLocation DiagLoc =
      Cast ? Cast->getBeginLoc() : Call->getExprLoc();
  if (DiagLoc.isInvalid())
    return;

  // Warn even if the conversion is inside a macro expansion, but we
  // can't fix it in that case.
  const SourceManager &SM = *Result.SourceManager;
  const LangOptions &LangOpts = Result.Context->getLangOpts();
  const SourceRange ExprRange = Call->getSourceRange();
  const SourceRange ReplaceRange = Cast ? Cast->getSourceRange() : ExprRange;

  // If we're parsing a template definition then we might be able to
  // fix the conversion if it wasn't dependent on a template
  // parameter. If we did that, then we'll have stored it in
  // AlreadySeen.
  //
  // We'll match again later during each instantiation. If the fix was
  // already applied then we don't want to warn. If it wasn't then we
  // don't know the type that should be used so just warn so that the
  // location can be fixed by hand.
  //
  if (Result.Nodes.getNodeAs<Expr>("instantiation")) {
    if (!AlreadySeen.contains(DiagLoc))
      diag(DiagLoc,
           "implicit nlohmann::json conversion to templated type should be explicit");
    return;
  }

  bool CanFix = ExprRange.isValid() && ReplaceRange.isValid() &&
                !(Cast && SM.isMacroBodyExpansion(Cast->getBeginLoc()));

  CharSourceRange FileExprRange;
  CharSourceRange FileReplaceRange;

  if (CanFix) {
    FileExprRange = Lexer::makeFileCharRange(
        CharSourceRange::getTokenRange(ExprRange), SM, LangOpts);
    FileReplaceRange = Lexer::makeFileCharRange(
        CharSourceRange::getTokenRange(ReplaceRange), SM, LangOpts);
    CanFix = FileExprRange.isValid() && FileReplaceRange.isValid();
  }

  if (!CanFix) {
    diag(DiagLoc, "implicit nlohmann::json conversion to %0 should be explicit")
        << DestinationTypeStr;
    AlreadySeen.insert(DiagLoc);
    return;
  }

  bool Deref = false;
  if (const auto *Op = llvm::dyn_cast<UnaryOperator>(Arg);
      Op && Op->getOpcode() == UO_Deref)
    Deref = true;
  else if (const auto *Op = llvm::dyn_cast<CXXOperatorCallExpr>(Arg);
           Op && Op->getOperator() == OO_Star)
    Deref = true;

  llvm::StringRef SourceText =
      clang::Lexer::getSourceText(FileExprRange, SM, LangOpts);

  if (Deref)
    SourceText.consume_front("*");

  const std::string ReplacementText =
      (llvm::Twine(SourceText) + (Deref ? "->" : ".") + "get<" +
       DestinationTypeStr + ">()")
          .str();
  diag(DiagLoc, "implicit nlohmann::json conversion to %0 should be explicit")
      << DestinationTypeStr
      << FixItHint::CreateReplacement(FileReplaceRange, ReplacementText);

  AlreadySeen.insert(DiagLoc);
}

} // namespace clang::tidy::modernize
