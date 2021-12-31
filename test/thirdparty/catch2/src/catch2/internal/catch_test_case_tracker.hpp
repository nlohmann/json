
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
#ifndef CATCH_TEST_CASE_TRACKER_HPP_INCLUDED
#define CATCH_TEST_CASE_TRACKER_HPP_INCLUDED

#include <catch2/internal/catch_compiler_capabilities.hpp>
#include <catch2/internal/catch_common.hpp>

#include <string>
#include <vector>
#include <memory>

namespace Catch {
namespace TestCaseTracking {

    struct NameAndLocation {
        std::string name;
        SourceLineInfo location;

        NameAndLocation( std::string const& _name, SourceLineInfo const& _location );
        friend bool operator==(NameAndLocation const& lhs, NameAndLocation const& rhs) {
            return lhs.name == rhs.name
                && lhs.location == rhs.location;
        }
    };

    class ITracker;

    using ITrackerPtr = std::shared_ptr<ITracker>;

    class  ITracker {
        NameAndLocation m_nameAndLocation;

        using Children = std::vector<ITrackerPtr>;

    protected:
        Children m_children;

    public:
        ITracker(NameAndLocation const& nameAndLoc) :
            m_nameAndLocation(nameAndLoc)
        {}


        // static queries
        NameAndLocation const& nameAndLocation() const {
            return m_nameAndLocation;
        }

        virtual ~ITracker();


        // dynamic queries
        virtual bool isComplete() const = 0; // Successfully completed or failed
        virtual bool isSuccessfullyCompleted() const = 0;
        virtual bool isOpen() const = 0; // Started but not complete
        virtual bool hasStarted() const = 0;

        virtual ITracker& parent() = 0;

        // actions
        virtual void close() = 0; // Successfully complete
        virtual void fail() = 0;
        virtual void markAsNeedingAnotherRun() = 0;

        //! Register a nested ITracker
        void addChild( ITrackerPtr const& child );
        /**
         * Returns ptr to specific child if register with this tracker.
         *
         * Returns nullptr if not found.
         */
        ITrackerPtr findChild( NameAndLocation const& nameAndLocation );
        //! Have any children been added?
        bool hasChildren() const {
            return !m_children.empty();
        }


        virtual void openChild() = 0;

        // Debug/ checking
        virtual bool isSectionTracker() const = 0;
        virtual bool isGeneratorTracker() const = 0;
    };

    class TrackerContext {

        enum RunState {
            NotStarted,
            Executing,
            CompletedCycle
        };

        ITrackerPtr m_rootTracker;
        ITracker* m_currentTracker = nullptr;
        RunState m_runState = NotStarted;

    public:

        ITracker& startRun();
        void endRun();

        void startCycle();
        void completeCycle();

        bool completedCycle() const;
        ITracker& currentTracker();
        void setCurrentTracker( ITracker* tracker );
    };

    class TrackerBase : public ITracker {
    protected:
        enum CycleState {
            NotStarted,
            Executing,
            ExecutingChildren,
            NeedsAnotherRun,
            CompletedSuccessfully,
            Failed
        };

        TrackerContext& m_ctx;
        ITracker* m_parent;
        CycleState m_runState = NotStarted;

    public:
        TrackerBase( NameAndLocation const& nameAndLocation, TrackerContext& ctx, ITracker* parent );

        bool isComplete() const override;
        bool isSuccessfullyCompleted() const override;
        bool isOpen() const override;
        bool hasStarted() const override {
            return m_runState != NotStarted;
        }

        ITracker& parent() override;

        void openChild() override;

        bool isSectionTracker() const override;
        bool isGeneratorTracker() const override;

        void open();

        void close() override;
        void fail() override;
        void markAsNeedingAnotherRun() override;

    private:
        void moveToParent();
        void moveToThis();
    };

    class SectionTracker : public TrackerBase {
        std::vector<std::string> m_filters;
        std::string m_trimmed_name;
    public:
        SectionTracker( NameAndLocation const& nameAndLocation, TrackerContext& ctx, ITracker* parent );

        bool isSectionTracker() const override;

        bool isComplete() const override;

        static SectionTracker& acquire( TrackerContext& ctx, NameAndLocation const& nameAndLocation );

        void tryOpen();

        void addInitialFilters( std::vector<std::string> const& filters );
        void addNextFilters( std::vector<std::string> const& filters );
    };

} // namespace TestCaseTracking

using TestCaseTracking::ITracker;
using TestCaseTracking::TrackerContext;
using TestCaseTracking::SectionTracker;

} // namespace Catch

#endif // CATCH_TEST_CASE_TRACKER_HPP_INCLUDED
