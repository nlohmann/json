
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
#include <catch2/internal/catch_test_case_tracker.hpp>

#include <catch2/internal/catch_enforce.hpp>
#include <catch2/internal/catch_string_manip.hpp>

#include <algorithm>
#include <cassert>
#include <memory>

#if defined(__clang__)
#    pragma clang diagnostic push
#    pragma clang diagnostic ignored "-Wexit-time-destructors"
#endif

namespace Catch {
namespace TestCaseTracking {

    NameAndLocation::NameAndLocation( std::string const& _name, SourceLineInfo const& _location )
    :   name( _name ),
        location( _location )
    {}


    ITracker::~ITracker() = default;

    void ITracker::addChild( ITrackerPtr const& child ) {
        m_children.push_back( child );
    }

    ITrackerPtr ITracker::findChild( NameAndLocation const& nameAndLocation ) {
        auto it = std::find_if(
            m_children.begin(),
            m_children.end(),
            [&nameAndLocation]( ITrackerPtr const& tracker ) {
                return tracker->nameAndLocation().location ==
                           nameAndLocation.location &&
                       tracker->nameAndLocation().name == nameAndLocation.name;
            } );
        return ( it != m_children.end() ) ? *it : nullptr;
    }



    ITracker& TrackerContext::startRun() {
        using namespace std::string_literals;
        m_rootTracker = std::make_shared<SectionTracker>( NameAndLocation( "{root}"s, CATCH_INTERNAL_LINEINFO ), *this, nullptr );
        m_currentTracker = nullptr;
        m_runState = Executing;
        return *m_rootTracker;
    }

    void TrackerContext::endRun() {
        m_rootTracker.reset();
        m_currentTracker = nullptr;
        m_runState = NotStarted;
    }

    void TrackerContext::startCycle() {
        m_currentTracker = m_rootTracker.get();
        m_runState = Executing;
    }
    void TrackerContext::completeCycle() {
        m_runState = CompletedCycle;
    }

    bool TrackerContext::completedCycle() const {
        return m_runState == CompletedCycle;
    }
    ITracker& TrackerContext::currentTracker() {
        return *m_currentTracker;
    }
    void TrackerContext::setCurrentTracker( ITracker* tracker ) {
        m_currentTracker = tracker;
    }


    TrackerBase::TrackerBase( NameAndLocation const& nameAndLocation, TrackerContext& ctx, ITracker* parent ):
        ITracker(nameAndLocation),
        m_ctx( ctx ),
        m_parent( parent )
    {}

    bool TrackerBase::isComplete() const {
        return m_runState == CompletedSuccessfully || m_runState == Failed;
    }
    bool TrackerBase::isSuccessfullyCompleted() const {
        return m_runState == CompletedSuccessfully;
    }
    bool TrackerBase::isOpen() const {
        return m_runState != NotStarted && !isComplete();
    }

    ITracker& TrackerBase::parent() {
        assert( m_parent ); // Should always be non-null except for root
        return *m_parent;
    }

    void TrackerBase::openChild() {
        if( m_runState != ExecutingChildren ) {
            m_runState = ExecutingChildren;
            if( m_parent )
                m_parent->openChild();
        }
    }

    bool TrackerBase::isSectionTracker() const { return false; }
    bool TrackerBase::isGeneratorTracker() const { return false; }

    void TrackerBase::open() {
        m_runState = Executing;
        moveToThis();
        if( m_parent )
            m_parent->openChild();
    }

    void TrackerBase::close() {

        // Close any still open children (e.g. generators)
        while( &m_ctx.currentTracker() != this )
            m_ctx.currentTracker().close();

        switch( m_runState ) {
            case NeedsAnotherRun:
                break;

            case Executing:
                m_runState = CompletedSuccessfully;
                break;
            case ExecutingChildren:
                if( std::all_of(m_children.begin(), m_children.end(), [](ITrackerPtr const& t){ return t->isComplete(); }) )
                    m_runState = CompletedSuccessfully;
                break;

            case NotStarted:
            case CompletedSuccessfully:
            case Failed:
                CATCH_INTERNAL_ERROR( "Illogical state: " << m_runState );

            default:
                CATCH_INTERNAL_ERROR( "Unknown state: " << m_runState );
        }
        moveToParent();
        m_ctx.completeCycle();
    }
    void TrackerBase::fail() {
        m_runState = Failed;
        if( m_parent )
            m_parent->markAsNeedingAnotherRun();
        moveToParent();
        m_ctx.completeCycle();
    }
    void TrackerBase::markAsNeedingAnotherRun() {
        m_runState = NeedsAnotherRun;
    }

    void TrackerBase::moveToParent() {
        assert( m_parent );
        m_ctx.setCurrentTracker( m_parent );
    }
    void TrackerBase::moveToThis() {
        m_ctx.setCurrentTracker( this );
    }

    SectionTracker::SectionTracker( NameAndLocation const& nameAndLocation, TrackerContext& ctx, ITracker* parent )
    :   TrackerBase( nameAndLocation, ctx, parent ),
        m_trimmed_name(trim(nameAndLocation.name))
    {
        if( parent ) {
            while( !parent->isSectionTracker() )
                parent = &parent->parent();

            SectionTracker& parentSection = static_cast<SectionTracker&>( *parent );
            addNextFilters( parentSection.m_filters );
        }
    }

    bool SectionTracker::isComplete() const {
        bool complete = true;

        if (m_filters.empty()
            || m_filters[0] == ""
            || std::find(m_filters.begin(), m_filters.end(), m_trimmed_name) != m_filters.end()) {
            complete = TrackerBase::isComplete();
        }
        return complete;
    }

    bool SectionTracker::isSectionTracker() const { return true; }

    SectionTracker& SectionTracker::acquire( TrackerContext& ctx, NameAndLocation const& nameAndLocation ) {
        std::shared_ptr<SectionTracker> section;

        ITracker& currentTracker = ctx.currentTracker();
        if( ITrackerPtr childTracker = currentTracker.findChild( nameAndLocation ) ) {
            assert( childTracker );
            assert( childTracker->isSectionTracker() );
            section = std::static_pointer_cast<SectionTracker>( childTracker );
        }
        else {
            section = std::make_shared<SectionTracker>( nameAndLocation, ctx, &currentTracker );
            currentTracker.addChild( section );
        }
        if( !ctx.completedCycle() )
            section->tryOpen();
        return *section;
    }

    void SectionTracker::tryOpen() {
        if( !isComplete() )
            open();
    }

    void SectionTracker::addInitialFilters( std::vector<std::string> const& filters ) {
        if( !filters.empty() ) {
            m_filters.reserve( m_filters.size() + filters.size() + 2 );
            m_filters.emplace_back(""); // Root - should never be consulted
            m_filters.emplace_back(""); // Test Case - not a section filter
            m_filters.insert( m_filters.end(), filters.begin(), filters.end() );
        }
    }
    void SectionTracker::addNextFilters( std::vector<std::string> const& filters ) {
        if( filters.size() > 1 )
            m_filters.insert( m_filters.end(), filters.begin()+1, filters.end() );
    }

} // namespace TestCaseTracking

using TestCaseTracking::ITracker;
using TestCaseTracking::TrackerContext;
using TestCaseTracking::SectionTracker;

} // namespace Catch

#if defined(__clang__)
#    pragma clang diagnostic pop
#endif
