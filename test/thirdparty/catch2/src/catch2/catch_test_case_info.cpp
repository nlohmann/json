
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
#include <catch2/catch_test_case_info.hpp>
#include <catch2/internal/catch_enforce.hpp>
#include <catch2/catch_test_spec.hpp>
#include <catch2/interfaces/catch_interfaces_testcase.hpp>
#include <catch2/internal/catch_string_manip.hpp>

#include <cassert>
#include <cctype>
#include <algorithm>

namespace Catch {

    namespace {
        using TCP_underlying_type = uint8_t;
        static_assert(sizeof(TestCaseProperties) == sizeof(TCP_underlying_type),
                      "The size of the TestCaseProperties is different from the assumed size");

        TestCaseProperties operator|(TestCaseProperties lhs, TestCaseProperties rhs) {
            return static_cast<TestCaseProperties>(
                static_cast<TCP_underlying_type>(lhs) | static_cast<TCP_underlying_type>(rhs)
            );
        }

        TestCaseProperties& operator|=(TestCaseProperties& lhs, TestCaseProperties rhs) {
            lhs = static_cast<TestCaseProperties>(
                static_cast<TCP_underlying_type>(lhs) | static_cast<TCP_underlying_type>(rhs)
            );
            return lhs;
        }

        TestCaseProperties operator&(TestCaseProperties lhs, TestCaseProperties rhs) {
            return static_cast<TestCaseProperties>(
                static_cast<TCP_underlying_type>(lhs) & static_cast<TCP_underlying_type>(rhs)
            );
        }

        bool applies(TestCaseProperties tcp) {
            static_assert(static_cast<TCP_underlying_type>(TestCaseProperties::None) == 0,
                          "TestCaseProperties::None must be equal to 0");
            return tcp != TestCaseProperties::None;
        }

        TestCaseProperties parseSpecialTag( StringRef tag ) {
            if( !tag.empty() && tag[0] == '.' )
                return TestCaseProperties::IsHidden;
            else if( tag == "!throws"_sr )
                return TestCaseProperties::Throws;
            else if( tag == "!shouldfail"_sr )
                return TestCaseProperties::ShouldFail;
            else if( tag == "!mayfail"_sr )
                return TestCaseProperties::MayFail;
            else if( tag == "!nonportable"_sr )
                return TestCaseProperties::NonPortable;
            else if( tag == "!benchmark"_sr )
                return static_cast<TestCaseProperties>(TestCaseProperties::Benchmark | TestCaseProperties::IsHidden );
            else
                return TestCaseProperties::None;
        }
        bool isReservedTag( StringRef tag ) {
            return parseSpecialTag( tag ) == TestCaseProperties::None
                && tag.size() > 0
                && !std::isalnum( static_cast<unsigned char>(tag[0]) );
        }
        void enforceNotReservedTag( StringRef tag, SourceLineInfo const& _lineInfo ) {
            CATCH_ENFORCE( !isReservedTag(tag),
                          "Tag name: [" << tag << "] is not allowed.\n"
                          << "Tag names starting with non alphanumeric characters are reserved\n"
                          << _lineInfo );
        }

        std::string makeDefaultName() {
            static size_t counter = 0;
            return "Anonymous test case " + std::to_string(++counter);
        }

        StringRef extractFilenamePart(StringRef filename) {
            size_t lastDot = filename.size();
            while (lastDot > 0 && filename[lastDot - 1] != '.') {
                --lastDot;
            }
            --lastDot;

            size_t nameStart = lastDot;
            while (nameStart > 0 && filename[nameStart - 1] != '/' && filename[nameStart - 1] != '\\') {
                --nameStart;
            }

            return filename.substr(nameStart, lastDot - nameStart);
        }

        // Returns the upper bound on size of extra tags ([#file]+[.])
        size_t sizeOfExtraTags(StringRef filepath) {
            // [.] is 3, [#] is another 3
            const size_t extras = 3 + 3;
            return extractFilenamePart(filepath).size() + extras;
        }
    }

    Detail::unique_ptr<TestCaseInfo>
        makeTestCaseInfo(std::string const& _className,
                         NameAndTags const& nameAndTags,
                         SourceLineInfo const& _lineInfo ) {
        return Detail::unique_ptr<TestCaseInfo>(new TestCaseInfo(_className, nameAndTags, _lineInfo));
    }

    TestCaseInfo::TestCaseInfo(std::string const& _className,
                               NameAndTags const& _nameAndTags,
                               SourceLineInfo const& _lineInfo):
        name( _nameAndTags.name.empty() ? makeDefaultName() : _nameAndTags.name ),
        className( _className ),
        lineInfo( _lineInfo )
    {
        StringRef originalTags = _nameAndTags.tags;
        // We need to reserve enough space to store all of the tags
        // (including optional hidden tag and filename tag)
        auto requiredSize = originalTags.size() + sizeOfExtraTags(_lineInfo.file);
        backingTags.reserve(requiredSize);
        backingLCaseTags.reserve(requiredSize);

        // We cannot copy the tags directly, as we need to normalize
        // some tags, so that [.foo] is copied as [.][foo].
        size_t tagStart = 0;
        size_t tagEnd = 0;
        bool inTag = false;
        for (size_t idx = 0; idx < originalTags.size(); ++idx) {
            auto c = originalTags[idx];
            if (c == '[') {
                assert(!inTag);
                inTag = true;
                tagStart = idx;
            }
            if (c == ']') {
                assert(inTag);
                inTag = false;
                tagEnd = idx;
                assert(tagStart < tagEnd);

                // We need to check the tag for special meanings, copy
                // it over to backing storage and actually reference the
                // backing storage in the saved tags
                StringRef tagStr = originalTags.substr(tagStart+1, tagEnd - tagStart - 1);
                enforceNotReservedTag(tagStr, lineInfo);
                properties |= parseSpecialTag(tagStr);
                // When copying a tag to the backing storage, we need to
                // check if it is a merged hide tag, such as [.foo], and
                // if it is, we need to handle it as if it was [foo].
                if (tagStr.size() > 1 && tagStr[0] == '.') {
                    tagStr = tagStr.substr(1, tagStr.size() - 1);
                }
                // We skip over dealing with the [.] tag, as we will add
                // it later unconditionally and then sort and unique all
                // the tags.
                internalAppendTag(tagStr);
            }
            (void)inTag; // Silence "set-but-unused" warning in release mode.
        }
        // Add [.] if relevant
        if (isHidden()) {
            internalAppendTag("."_sr);
        }

        // Sort and prepare tags
        toLowerInPlace(backingLCaseTags);
        std::sort(begin(tags), end(tags), [](Tag lhs, Tag rhs) { return lhs.lowerCased < rhs.lowerCased; });
        tags.erase(std::unique(begin(tags), end(tags), [](Tag lhs, Tag rhs) {return lhs.lowerCased == rhs.lowerCased; }),
                   end(tags));
    }

    bool TestCaseInfo::isHidden() const {
        return applies( properties & TestCaseProperties::IsHidden );
    }
    bool TestCaseInfo::throws() const {
        return applies( properties & TestCaseProperties::Throws );
    }
    bool TestCaseInfo::okToFail() const {
        return applies( properties & (TestCaseProperties::ShouldFail | TestCaseProperties::MayFail ) );
    }
    bool TestCaseInfo::expectedToFail() const {
        return applies( properties & (TestCaseProperties::ShouldFail) );
    }

    void TestCaseInfo::addFilenameTag() {
        std::string combined("#");
        combined += extractFilenamePart(lineInfo.file);
        internalAppendTag(combined);
    }

    std::string TestCaseInfo::tagsAsString() const {
        std::string ret;
        // '[' and ']' per tag
        std::size_t full_size = 2 * tags.size();
        for (const auto& tag : tags) {
            full_size += tag.original.size();
        }
        ret.reserve(full_size);
        for (const auto& tag : tags) {
            ret.push_back('[');
            ret += tag.original;
            ret.push_back(']');
        }

        return ret;
    }

    void TestCaseInfo::internalAppendTag(StringRef tagStr) {
        backingTags += '[';
        const auto backingStart = backingTags.size();
        backingTags += tagStr;
        const auto backingEnd = backingTags.size();
        backingTags += ']';
        backingLCaseTags += '[';
        // We append the tag to the lower-case backing storage as-is,
        // because we will perform the lower casing later, in bulk
        backingLCaseTags += tagStr;
        backingLCaseTags += ']';
        tags.emplace_back(StringRef(backingTags.c_str() + backingStart, backingEnd - backingStart),
                          StringRef(backingLCaseTags.c_str() + backingStart, backingEnd - backingStart));
    }


    bool TestCaseHandle::operator == ( TestCaseHandle const& rhs ) const {
        return m_invoker == rhs.m_invoker
            && m_info->name == rhs.m_info->name
            && m_info->className == rhs.m_info->className;
    }

    bool TestCaseHandle::operator < ( TestCaseHandle const& rhs ) const {
        return m_info->name < rhs.m_info->name;
    }

    TestCaseInfo const& TestCaseHandle::getTestCaseInfo() const {
        return *m_info;
    }

} // end namespace Catch
