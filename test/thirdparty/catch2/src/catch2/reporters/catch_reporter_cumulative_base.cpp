
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
#include <catch2/reporters/catch_reporter_cumulative_base.hpp>

#include <algorithm>
#include <cassert>

namespace Catch {
    namespace {
        struct BySectionInfo {
            BySectionInfo( SectionInfo const& other ): m_other( other ) {}
            BySectionInfo( BySectionInfo const& other ):
                m_other( other.m_other ) {}
            bool operator()(
                std::shared_ptr<CumulativeReporterBase::SectionNode> const&
                    node ) const {
                return (
                    ( node->stats.sectionInfo.name == m_other.name ) &&
                    ( node->stats.sectionInfo.lineInfo == m_other.lineInfo ) );
            }
            void operator=( BySectionInfo const& ) = delete;

        private:
            SectionInfo const& m_other;
        };

        void prepareExpandedExpression( AssertionResult& result ) {
            result.getExpandedExpression();
        }
    } // namespace


    CumulativeReporterBase::~CumulativeReporterBase() = default;

    void
    CumulativeReporterBase::sectionStarting( SectionInfo const& sectionInfo ) {
        SectionStats incompleteStats( sectionInfo, Counts(), 0, false );
        std::shared_ptr<SectionNode> node;
        if ( m_sectionStack.empty() ) {
            if ( !m_rootSection )
                m_rootSection =
                    std::make_shared<SectionNode>( incompleteStats );
            node = m_rootSection;
        } else {
            SectionNode& parentNode = *m_sectionStack.back();
            auto it = std::find_if( parentNode.childSections.begin(),
                                    parentNode.childSections.end(),
                                    BySectionInfo( sectionInfo ) );
            if ( it == parentNode.childSections.end() ) {
                node = std::make_shared<SectionNode>( incompleteStats );
                parentNode.childSections.push_back( node );
            } else {
                node = *it;
            }
        }
        m_sectionStack.push_back( node );
        m_deepestSection = std::move( node );
    }

    bool CumulativeReporterBase::assertionEnded(
        AssertionStats const& assertionStats ) {
        assert( !m_sectionStack.empty() );
        // AssertionResult holds a pointer to a temporary DecomposedExpression,
        // which getExpandedExpression() calls to build the expression string.
        // Our section stack copy of the assertionResult will likely outlive the
        // temporary, so it must be expanded or discarded now to avoid calling
        // a destroyed object later.
        prepareExpandedExpression(
            const_cast<AssertionResult&>( assertionStats.assertionResult ) );
        SectionNode& sectionNode = *m_sectionStack.back();
        sectionNode.assertions.push_back( assertionStats );
        return true;
    }

    void CumulativeReporterBase::sectionEnded( SectionStats const& sectionStats ) {
        assert( !m_sectionStack.empty() );
        SectionNode& node = *m_sectionStack.back();
        node.stats = sectionStats;
        m_sectionStack.pop_back();
    }

    void CumulativeReporterBase::testCaseEnded(
        TestCaseStats const& testCaseStats ) {
        auto node = std::make_shared<TestCaseNode>( testCaseStats );
        assert( m_sectionStack.size() == 0 );
        node->children.push_back( m_rootSection );
        m_testCases.push_back( node );
        m_rootSection.reset();

        assert( m_deepestSection );
        m_deepestSection->stdOut = testCaseStats.stdOut;
        m_deepestSection->stdErr = testCaseStats.stdErr;
    }

    void CumulativeReporterBase::testGroupEnded(
        TestGroupStats const& testGroupStats ) {
        auto node = std::make_shared<TestGroupNode>( testGroupStats );
        node->children.swap( m_testCases );
        m_testGroups.push_back( node );
    }

    void CumulativeReporterBase::testRunEnded( TestRunStats const& testRunStats ) {
        auto node = std::make_shared<TestRunNode>( testRunStats );
        node->children.swap( m_testGroups );
        m_testRuns.push_back( node );
        testRunEndedCumulative();
    }

} // end namespace Catch
