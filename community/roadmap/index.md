# Roadmap

This page describes what the project intends to do, and what it does not intend to do, over the next year. Concrete work items are tracked in the [GitHub milestones](https://github.com/nlohmann/json/milestones) and the [issue tracker](https://github.com/nlohmann/json/issues).

## What the project will do

- **Keep the C++11 baseline.** The library will continue to compile with every [supported C++11 compiler](https://github.com/nlohmann/json/blob/develop/README.md#supported-compilers). Features of later standards are only used when they are guarded by the `JSON_HAS_CPP_*` macros.
- **Stay conformant to JSON.** The parser and serializer follow [RFC 8259](https://datatracker.ietf.org/doc/html/rfc8259). Extensions such as [comments](https://json.nlohmann.me/features/comments/index.md) or [trailing commas](https://json.nlohmann.me/features/trailing_commas/index.md) remain opt-in.
- **Keep the 3.x public API stable.** Releases follow [semantic versioning](https://semver.org). Changes that would break existing code are only added behind a feature macro, so users can opt in and test their code before a next major release.
- **Support a broad range of compilers and platforms.** The [CI](https://json.nlohmann.me/community/quality_assurance/index.md) keeps testing old and new versions of GCC, Clang, MSVC, and other compilers on Linux, macOS, and Windows.
- **Keep the quality assurance up.** Every change keeps the test coverage at 100%, passes the static and dynamic analysis, and is fuzz-tested by OSS-Fuzz, see [Quality assurance](https://json.nlohmann.me/community/quality_assurance/index.md).
- **Harden the library against hostile input.** Handling deeply nested values without exhausting the call stack is ongoing work.
- **Fix bugs and security issues** reported through the issue tracker and the [security policy](https://json.nlohmann.me/community/security_policy/index.md).

## What the project will not do

- **Break the public API of version 3.x.** See the [contribution guidelines](https://github.com/nlohmann/json/blob/develop/.github/CONTRIBUTING.md#break-the-public-api) for what counts as a breaking change.
- **Require a newer C++ standard than C++11.**
- **Break JSON conformance** or enable non-standard extensions by default.
- **Add dependencies** or require a build step. The library remains header-only, and the single header `json.hpp` remains a complete distribution.
- **Trade simplicity for speed or memory efficiency.** Performance improvements are welcome, but the library is not meant to compete with the fastest JSON libraries, see [Design goals](https://json.nlohmann.me/home/design_goals/index.md).

## Version 4.0

There is no decision yet on whether or when a version 4.0 with breaking changes will be released. Proposals that need a major version, for instance stricter type conversions, are collected in issue [#3453](https://github.com/nlohmann/json/issues/3453). Until then, such changes are only added as opt-in behavior behind feature macros.
