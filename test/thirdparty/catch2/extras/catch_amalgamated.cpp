//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0

//  Catch v3.0.0-preview.3
//  Generated: 2020-10-08 13:59:26.616931
//  ----------------------------------------------------------
//  This file is an amalgamation of multiple different files.
//  You probably shouldn't edit it directly.
//  ----------------------------------------------------------

#include "catch_amalgamated.hpp"


// Adapted from donated nonius code.



#include <cassert>
#include <iterator>
#include <random>


#if defined(CATCH_CONFIG_USE_ASYNC)
#include <future>
#endif

namespace {

using Catch::Benchmark::Detail::sample;

     template <typename URng, typename Estimator>
     sample resample(URng& rng, int resamples, std::vector<double>::iterator first, std::vector<double>::iterator last, Estimator& estimator) {
         auto n = last - first;
         std::uniform_int_distribution<decltype(n)> dist(0, n - 1);

         sample out;
         out.reserve(resamples);
         std::generate_n(std::back_inserter(out), resamples, [n, first, &estimator, &dist, &rng] {
             std::vector<double> resampled;
             resampled.reserve(n);
             std::generate_n(std::back_inserter(resampled), n, [first, &dist, &rng] { return first[dist(rng)]; });
             return estimator(resampled.begin(), resampled.end());
         });
         std::sort(out.begin(), out.end());
         return out;
     }


    double erf_inv(double x) {
        // Code accompanying the article "Approximating the erfinv function" in GPU Computing Gems, Volume 2
        double w, p;

        w = -log((1.0 - x) * (1.0 + x));

        if (w < 6.250000) {
            w = w - 3.125000;
            p = -3.6444120640178196996e-21;
            p = -1.685059138182016589e-19 + p * w;
            p = 1.2858480715256400167e-18 + p * w;
            p = 1.115787767802518096e-17 + p * w;
            p = -1.333171662854620906e-16 + p * w;
            p = 2.0972767875968561637e-17 + p * w;
            p = 6.6376381343583238325e-15 + p * w;
            p = -4.0545662729752068639e-14 + p * w;
            p = -8.1519341976054721522e-14 + p * w;
            p = 2.6335093153082322977e-12 + p * w;
            p = -1.2975133253453532498e-11 + p * w;
            p = -5.4154120542946279317e-11 + p * w;
            p = 1.051212273321532285e-09 + p * w;
            p = -4.1126339803469836976e-09 + p * w;
            p = -2.9070369957882005086e-08 + p * w;
            p = 4.2347877827932403518e-07 + p * w;
            p = -1.3654692000834678645e-06 + p * w;
            p = -1.3882523362786468719e-05 + p * w;
            p = 0.0001867342080340571352 + p * w;
            p = -0.00074070253416626697512 + p * w;
            p = -0.0060336708714301490533 + p * w;
            p = 0.24015818242558961693 + p * w;
            p = 1.6536545626831027356 + p * w;
        } else if (w < 16.000000) {
            w = sqrt(w) - 3.250000;
            p = 2.2137376921775787049e-09;
            p = 9.0756561938885390979e-08 + p * w;
            p = -2.7517406297064545428e-07 + p * w;
            p = 1.8239629214389227755e-08 + p * w;
            p = 1.5027403968909827627e-06 + p * w;
            p = -4.013867526981545969e-06 + p * w;
            p = 2.9234449089955446044e-06 + p * w;
            p = 1.2475304481671778723e-05 + p * w;
            p = -4.7318229009055733981e-05 + p * w;
            p = 6.8284851459573175448e-05 + p * w;
            p = 2.4031110387097893999e-05 + p * w;
            p = -0.0003550375203628474796 + p * w;
            p = 0.00095328937973738049703 + p * w;
            p = -0.0016882755560235047313 + p * w;
            p = 0.0024914420961078508066 + p * w;
            p = -0.0037512085075692412107 + p * w;
            p = 0.005370914553590063617 + p * w;
            p = 1.0052589676941592334 + p * w;
            p = 3.0838856104922207635 + p * w;
        } else {
            w = sqrt(w) - 5.000000;
            p = -2.7109920616438573243e-11;
            p = -2.5556418169965252055e-10 + p * w;
            p = 1.5076572693500548083e-09 + p * w;
            p = -3.7894654401267369937e-09 + p * w;
            p = 7.6157012080783393804e-09 + p * w;
            p = -1.4960026627149240478e-08 + p * w;
            p = 2.9147953450901080826e-08 + p * w;
            p = -6.7711997758452339498e-08 + p * w;
            p = 2.2900482228026654717e-07 + p * w;
            p = -9.9298272942317002539e-07 + p * w;
            p = 4.5260625972231537039e-06 + p * w;
            p = -1.9681778105531670567e-05 + p * w;
            p = 7.5995277030017761139e-05 + p * w;
            p = -0.00021503011930044477347 + p * w;
            p = -0.00013871931833623122026 + p * w;
            p = 1.0103004648645343977 + p * w;
            p = 4.8499064014085844221 + p * w;
        }
        return p * x;
    }

    double standard_deviation(std::vector<double>::iterator first, std::vector<double>::iterator last) {
        auto m = Catch::Benchmark::Detail::mean(first, last);
        double variance = std::accumulate(first, last, 0., [m](double a, double b) {
            double diff = b - m;
            return a + diff * diff;
            }) / (last - first);
            return std::sqrt(variance);
    }

}

namespace Catch {
    namespace Benchmark {
        namespace Detail {

            double weighted_average_quantile(int k, int q, std::vector<double>::iterator first, std::vector<double>::iterator last) {
                auto count = last - first;
                double idx = (count - 1) * k / static_cast<double>(q);
                int j = static_cast<int>(idx);
                double g = idx - j;
                std::nth_element(first, first + j, last);
                auto xj = first[j];
                if (g == 0) return xj;

                auto xj1 = *std::min_element(first + (j + 1), last);
                return xj + g * (xj1 - xj);
            }


            double erfc_inv(double x) {
                return erf_inv(1.0 - x);
            }

            double normal_quantile(double p) {
                static const double ROOT_TWO = std::sqrt(2.0);

                double result = 0.0;
                assert(p >= 0 && p <= 1);
                if (p < 0 || p > 1) {
                    return result;
                }

                result = -erfc_inv(2.0 * p);
                // result *= normal distribution standard deviation (1.0) * sqrt(2)
                result *= /*sd * */ ROOT_TWO;
                // result += normal disttribution mean (0)
                return result;
            }


            double outlier_variance(Estimate<double> mean, Estimate<double> stddev, int n) {
                double sb = stddev.point;
                double mn = mean.point / n;
                double mg_min = mn / 2.;
                double sg = std::min(mg_min / 4., sb / std::sqrt(n));
                double sg2 = sg * sg;
                double sb2 = sb * sb;

                auto c_max = [n, mn, sb2, sg2](double x) -> double {
                    double k = mn - x;
                    double d = k * k;
                    double nd = n * d;
                    double k0 = -n * nd;
                    double k1 = sb2 - n * sg2 + nd;
                    double det = k1 * k1 - 4 * sg2 * k0;
                    return (int)(-2. * k0 / (k1 + std::sqrt(det)));
                };

                auto var_out = [n, sb2, sg2](double c) {
                    double nc = n - c;
                    return (nc / n) * (sb2 - nc * sg2);
                };

                return std::min(var_out(1), var_out(std::min(c_max(0.), c_max(mg_min)))) / sb2;
            }


            bootstrap_analysis analyse_samples(double confidence_level, int n_resamples, std::vector<double>::iterator first, std::vector<double>::iterator last) {
                CATCH_INTERNAL_START_WARNINGS_SUPPRESSION
                CATCH_INTERNAL_SUPPRESS_GLOBALS_WARNINGS
                static std::random_device entropy;
                CATCH_INTERNAL_STOP_WARNINGS_SUPPRESSION

                auto n = static_cast<int>(last - first); // seriously, one can't use integral types without hell in C++

                auto mean = &Detail::mean<std::vector<double>::iterator>;
                auto stddev = &standard_deviation;

#if defined(CATCH_CONFIG_USE_ASYNC)
                auto Estimate = [=](double(*f)(std::vector<double>::iterator, std::vector<double>::iterator)) {
                    auto seed = entropy();
                    return std::async(std::launch::async, [=] {
                        std::mt19937 rng(seed);
                        auto resampled = resample(rng, n_resamples, first, last, f);
                        return bootstrap(confidence_level, first, last, resampled, f);
                    });
                };

                auto mean_future = Estimate(mean);
                auto stddev_future = Estimate(stddev);

                auto mean_estimate = mean_future.get();
                auto stddev_estimate = stddev_future.get();
#else
                auto Estimate = [=](double(*f)(std::vector<double>::iterator, std::vector<double>::iterator)) {
                    auto seed = entropy();
                    std::mt19937 rng(seed);
                    auto resampled = resample(rng, n_resamples, first, last, f);
                    return bootstrap(confidence_level, first, last, resampled, f);
                };

                auto mean_estimate = Estimate(mean);
                auto stddev_estimate = Estimate(stddev);
#endif // CATCH_USE_ASYNC

                double outlier_variance = Detail::outlier_variance(mean_estimate, stddev_estimate, n);

                return { mean_estimate, stddev_estimate, outlier_variance };
            }
        } // namespace Detail
    } // namespace Benchmark
} // namespace Catch


/** \file
 * This is a special TU that combines what would otherwise be a very
 * small benchmarking-related TUs into one bigger TU.
 *
 * The reason for this is compilation performance improvements by
 * avoiding reparsing headers for many small TUs, instead having this
 * one TU include bit more, but having it all parsed only once.
 *
 * To avoid heavy-tail problem with compilation times, each "subpart"
 * of Catch2 has its own combined TU like this.
 */

////////////////////////////////////////////
// vvv formerly catch_chronometer.cpp vvv //
////////////////////////////////////////////


namespace Catch {
    namespace Benchmark {
        namespace Detail {
            ChronometerConcept::~ChronometerConcept() = default;
        } // namespace Detail
    } // namespace Benchmark
} // namespace Catch


///////////////////////////////////////////////////
// vvv formerly catch_benchmark_function.cpp vvv //
///////////////////////////////////////////////////


namespace Catch {
    namespace Benchmark {
        namespace Detail {
            BenchmarkFunction::callable::~callable() = default;
            } // namespace Detail
    } // namespace Benchmark
} // namespace Catch


////////////////////////////////////////////////
// vvv formerly catch_complete_invoke.cpp vvv //
////////////////////////////////////////////////


namespace Catch {
    namespace Benchmark {
        namespace Detail {
            CATCH_INTERNAL_START_WARNINGS_SUPPRESSION
            CATCH_INTERNAL_SUPPRESS_GLOBALS_WARNINGS
            const std::string benchmarkErrorMsg = "a benchmark failed to run successfully";
            CATCH_INTERNAL_STOP_WARNINGS_SUPPRESSION
        } // namespace Detail
    } // namespace Benchmark
} // namespace Catch




/////////////////////////////////////////////////
// vvv formerly catch_run_for_at_least.cpp vvv //
/////////////////////////////////////////////////

#include <exception>

namespace Catch {
    namespace Benchmark {
        namespace Detail {
            struct optimized_away_error : std::exception {
                const char* what() const noexcept override;
            };

            const char* optimized_away_error::what() const noexcept {
                return "could not measure benchmark, maybe it was optimized away";
            }

            void throw_optimized_away_error() {
                Catch::throw_exception(optimized_away_error{});
            }

        } // namespace Detail
    } // namespace Benchmark
} // namespace Catch



#include <cmath>
#include <limits>

namespace {

// Performs equivalent check of std::fabs(lhs - rhs) <= margin
// But without the subtraction to allow for INFINITY in comparison
bool marginComparison(double lhs, double rhs, double margin) {
    return (lhs + margin >= rhs) && (rhs + margin >= lhs);
}

}

namespace Catch {

    Approx::Approx ( double value )
    :   m_epsilon( std::numeric_limits<float>::epsilon()*100 ),
        m_margin( 0.0 ),
        m_scale( 0.0 ),
        m_value( value )
    {}

    Approx Approx::custom() {
        return Approx( 0 );
    }

    Approx Approx::operator-() const {
        auto temp(*this);
        temp.m_value = -temp.m_value;
        return temp;
    }


    std::string Approx::toString() const {
        ReusableStringStream rss;
        rss << "Approx( " << ::Catch::Detail::stringify( m_value ) << " )";
        return rss.str();
    }

    bool Approx::equalityComparisonImpl(const double other) const {
        // First try with fixed margin, then compute margin based on epsilon, scale and Approx's value
        // Thanks to Richard Harris for his help refining the scaled margin value
        return marginComparison(m_value, other, m_margin)
            || marginComparison(m_value, other, m_epsilon * (m_scale + std::fabs(std::isinf(m_value)? 0 : m_value)));
    }

    void Approx::setMargin(double newMargin) {
        CATCH_ENFORCE(newMargin >= 0,
            "Invalid Approx::margin: " << newMargin << '.'
            << " Approx::Margin has to be non-negative.");
        m_margin = newMargin;
    }

    void Approx::setEpsilon(double newEpsilon) {
        CATCH_ENFORCE(newEpsilon >= 0 && newEpsilon <= 1.0,
            "Invalid Approx::epsilon: " << newEpsilon << '.'
            << " Approx::epsilon has to be in [0, 1]");
        m_epsilon = newEpsilon;
    }

namespace literals {
    Approx operator "" _a(long double val) {
        return Approx(val);
    }
    Approx operator "" _a(unsigned long long val) {
        return Approx(val);
    }
} // end namespace literals

std::string StringMaker<Catch::Approx>::convert(Catch::Approx const& value) {
    return value.toString();
}

} // end namespace Catch



namespace Catch {

    AssertionResultData::AssertionResultData(ResultWas::OfType _resultType, LazyExpression const & _lazyExpression):
        lazyExpression(_lazyExpression),
        resultType(_resultType) {}

    std::string AssertionResultData::reconstructExpression() const {

        if( reconstructedExpression.empty() ) {
            if( lazyExpression ) {
                ReusableStringStream rss;
                rss << lazyExpression;
                reconstructedExpression = rss.str();
            }
        }
        return reconstructedExpression;
    }

    AssertionResult::AssertionResult( AssertionInfo const& info, AssertionResultData const& data )
    :   m_info( info ),
        m_resultData( data )
    {}

    // Result was a success
    bool AssertionResult::succeeded() const {
        return Catch::isOk( m_resultData.resultType );
    }

    // Result was a success, or failure is suppressed
    bool AssertionResult::isOk() const {
        return Catch::isOk( m_resultData.resultType ) || shouldSuppressFailure( m_info.resultDisposition );
    }

    ResultWas::OfType AssertionResult::getResultType() const {
        return m_resultData.resultType;
    }

    bool AssertionResult::hasExpression() const {
        return !m_info.capturedExpression.empty();
    }

    bool AssertionResult::hasMessage() const {
        return !m_resultData.message.empty();
    }

    std::string AssertionResult::getExpression() const {
        // Possibly overallocating by 3 characters should be basically free
        std::string expr; expr.reserve(m_info.capturedExpression.size() + 3);
        if (isFalseTest(m_info.resultDisposition)) {
            expr += "!(";
        }
        expr += m_info.capturedExpression;
        if (isFalseTest(m_info.resultDisposition)) {
            expr += ')';
        }
        return expr;
    }

    std::string AssertionResult::getExpressionInMacro() const {
        std::string expr;
        if( m_info.macroName.empty() )
            expr = static_cast<std::string>(m_info.capturedExpression);
        else {
            expr.reserve( m_info.macroName.size() + m_info.capturedExpression.size() + 4 );
            expr += m_info.macroName;
            expr += "( ";
            expr += m_info.capturedExpression;
            expr += " )";
        }
        return expr;
    }

    bool AssertionResult::hasExpandedExpression() const {
        return hasExpression() && getExpandedExpression() != getExpression();
    }

    std::string AssertionResult::getExpandedExpression() const {
        std::string expr = m_resultData.reconstructExpression();
        return expr.empty()
                ? getExpression()
                : expr;
    }

    std::string AssertionResult::getMessage() const {
        return m_resultData.message;
    }
    SourceLineInfo AssertionResult::getSourceInfo() const {
        return m_info.lineInfo;
    }

    StringRef AssertionResult::getTestMacroName() const {
        return m_info.macroName;
    }

} // end namespace Catch




namespace Catch {

    Config::Config( ConfigData const& data )
    :   m_data( data ),
        m_stream( openStream() )
    {
        // We need to trim filter specs to avoid trouble with superfluous
        // whitespace (esp. important for bdd macros, as those are manually
        // aligned with whitespace).

        for (auto& elem : m_data.testsOrTags) {
            elem = trim(elem);
        }
        for (auto& elem : m_data.sectionsToRun) {
            elem = trim(elem);
        }

        TestSpecParser parser(ITagAliasRegistry::get());
        if (!m_data.testsOrTags.empty()) {
            m_hasTestFilters = true;
            for (auto const& testOrTags : m_data.testsOrTags) {
                parser.parse(testOrTags);
            }
        }
        m_testSpec = parser.testSpec();
    }

    Config::~Config() = default;


    std::string const& Config::getFilename() const {
        return m_data.outputFilename ;
    }

    bool Config::listTests() const          { return m_data.listTests; }
    bool Config::listTags() const           { return m_data.listTags; }
    bool Config::listReporters() const      { return m_data.listReporters; }

    std::string Config::getProcessName() const { return m_data.processName; }
    std::string const& Config::getReporterName() const { return m_data.reporterName; }

    std::vector<std::string> const& Config::getTestsOrTags() const { return m_data.testsOrTags; }
    std::vector<std::string> const& Config::getSectionsToRun() const { return m_data.sectionsToRun; }

    TestSpec const& Config::testSpec() const { return m_testSpec; }
    bool Config::hasTestFilters() const { return m_hasTestFilters; }

    bool Config::showHelp() const { return m_data.showHelp; }

    // IConfig interface
    bool Config::allowThrows() const                   { return !m_data.noThrow; }
    std::ostream& Config::stream() const               { return m_stream->stream(); }
    std::string Config::name() const                   { return m_data.name.empty() ? m_data.processName : m_data.name; }
    bool Config::includeSuccessfulResults() const      { return m_data.showSuccessfulTests; }
    bool Config::warnAboutMissingAssertions() const    { return !!(m_data.warnings & WarnAbout::NoAssertions); }
    bool Config::warnAboutNoTests() const              { return !!(m_data.warnings & WarnAbout::NoTests); }
    ShowDurations Config::showDurations() const        { return m_data.showDurations; }
    double Config::minDuration() const                 { return m_data.minDuration; }
    TestRunOrder Config::runOrder() const              { return m_data.runOrder; }
    unsigned int Config::rngSeed() const               { return m_data.rngSeed; }
    UseColour Config::useColour() const                { return m_data.useColour; }
    bool Config::shouldDebugBreak() const              { return m_data.shouldDebugBreak; }
    int Config::abortAfter() const                     { return m_data.abortAfter; }
    bool Config::showInvisibles() const                { return m_data.showInvisibles; }
    Verbosity Config::verbosity() const                { return m_data.verbosity; }

    bool Config::benchmarkNoAnalysis() const                      { return m_data.benchmarkNoAnalysis; }
    int Config::benchmarkSamples() const                          { return m_data.benchmarkSamples; }
    double Config::benchmarkConfidenceInterval() const            { return m_data.benchmarkConfidenceInterval; }
    unsigned int Config::benchmarkResamples() const               { return m_data.benchmarkResamples; }
    std::chrono::milliseconds Config::benchmarkWarmupTime() const { return std::chrono::milliseconds(m_data.benchmarkWarmupTime); }

    IStream const* Config::openStream() {
        return Catch::makeStream(m_data.outputFilename);
    }

} // end namespace Catch



#include <cassert>
#include <stack>

namespace Catch {

    ////////////////////////////////////////////////////////////////////////////

    Catch::MessageBuilder::MessageBuilder( StringRef const& macroName,
                                           SourceLineInfo const& lineInfo,
                                           ResultWas::OfType type )
        :m_info(macroName, lineInfo, type) {}

    ////////////////////////////////////////////////////////////////////////////


    ScopedMessage::ScopedMessage( MessageBuilder const& builder ):
        m_info( builder.m_info ) {
        m_info.message = builder.m_stream.str();
        getResultCapture().pushScopedMessage( m_info );
    }

    ScopedMessage::ScopedMessage( ScopedMessage&& old ) noexcept:
        m_info( std::move( old.m_info ) ) {
        old.m_moved = true;
    }

    ScopedMessage::~ScopedMessage() {
        if ( !uncaught_exceptions() && !m_moved ){
            getResultCapture().popScopedMessage(m_info);
        }
    }


    Capturer::Capturer( StringRef macroName, SourceLineInfo const& lineInfo, ResultWas::OfType resultType, StringRef names ) {
        auto trimmed = [&] (size_t start, size_t end) {
            while (names[start] == ',' || isspace(static_cast<unsigned char>(names[start]))) {
                ++start;
            }
            while (names[end] == ',' || isspace(static_cast<unsigned char>(names[end]))) {
                --end;
            }
            return names.substr(start, end - start + 1);
        };
        auto skipq = [&] (size_t start, char quote) {
            for (auto i = start + 1; i < names.size() ; ++i) {
                if (names[i] == quote)
                    return i;
                if (names[i] == '\\')
                    ++i;
            }
            CATCH_INTERNAL_ERROR("CAPTURE parsing encountered unmatched quote");
        };

        size_t start = 0;
        std::stack<char> openings;
        for (size_t pos = 0; pos < names.size(); ++pos) {
            char c = names[pos];
            switch (c) {
            case '[':
            case '{':
            case '(':
            // It is basically impossible to disambiguate between
            // comparison and start of template args in this context
//            case '<':
                openings.push(c);
                break;
            case ']':
            case '}':
            case ')':
//           case '>':
                openings.pop();
                break;
            case '"':
            case '\'':
                pos = skipq(pos, c);
                break;
            case ',':
                if (start != pos && openings.empty()) {
                    m_messages.emplace_back(macroName, lineInfo, resultType);
                    m_messages.back().message = static_cast<std::string>(trimmed(start, pos));
                    m_messages.back().message += " := ";
                    start = pos;
                }
            }
        }
        assert(openings.empty() && "Mismatched openings");
        m_messages.emplace_back(macroName, lineInfo, resultType);
        m_messages.back().message = static_cast<std::string>(trimmed(start, names.size() - 1));
        m_messages.back().message += " := ";
    }
    Capturer::~Capturer() {
        if ( !uncaught_exceptions() ){
            assert( m_captured == m_messages.size() );
            for( size_t i = 0; i < m_captured; ++i  )
                m_resultCapture.popScopedMessage( m_messages[i] );
        }
    }

    void Capturer::captureValue( size_t index, std::string const& value ) {
        assert( index < m_messages.size() );
        m_messages[index].message += value;
        m_resultCapture.pushScopedMessage( m_messages[index] );
        m_captured++;
    }

} // end namespace Catch




namespace Catch {

    namespace {

        class RegistryHub : public IRegistryHub,
                            public IMutableRegistryHub,
                            private Detail::NonCopyable {

        public: // IRegistryHub
            RegistryHub() = default;
            IReporterRegistry const& getReporterRegistry() const override {
                return m_reporterRegistry;
            }
            ITestCaseRegistry const& getTestCaseRegistry() const override {
                return m_testCaseRegistry;
            }
            IExceptionTranslatorRegistry const& getExceptionTranslatorRegistry() const override {
                return m_exceptionTranslatorRegistry;
            }
            ITagAliasRegistry const& getTagAliasRegistry() const override {
                return m_tagAliasRegistry;
            }
            StartupExceptionRegistry const& getStartupExceptionRegistry() const override {
                return m_exceptionRegistry;
            }

        public: // IMutableRegistryHub
            void registerReporter( std::string const& name, IReporterFactoryPtr factory ) override {
                m_reporterRegistry.registerReporter( name, std::move(factory) );
            }
            void registerListener( IReporterFactoryPtr factory ) override {
                m_reporterRegistry.registerListener( std::move(factory) );
            }
            void registerTest( Detail::unique_ptr<TestCaseInfo>&& testInfo, Detail::unique_ptr<ITestInvoker>&& invoker ) override {
                m_testCaseRegistry.registerTest( std::move(testInfo), std::move(invoker) );
            }
            void registerTranslator( const IExceptionTranslator* translator ) override {
                m_exceptionTranslatorRegistry.registerTranslator( translator );
            }
            void registerTagAlias( std::string const& alias, std::string const& tag, SourceLineInfo const& lineInfo ) override {
                m_tagAliasRegistry.add( alias, tag, lineInfo );
            }
            void registerStartupException() noexcept override {
#if !defined(CATCH_CONFIG_DISABLE_EXCEPTIONS)
                m_exceptionRegistry.add(std::current_exception());
#else
                CATCH_INTERNAL_ERROR("Attempted to register active exception under CATCH_CONFIG_DISABLE_EXCEPTIONS!");
#endif
            }
            IMutableEnumValuesRegistry& getMutableEnumValuesRegistry() override {
                return m_enumValuesRegistry;
            }

        private:
            TestRegistry m_testCaseRegistry;
            ReporterRegistry m_reporterRegistry;
            ExceptionTranslatorRegistry m_exceptionTranslatorRegistry;
            TagAliasRegistry m_tagAliasRegistry;
            StartupExceptionRegistry m_exceptionRegistry;
            Detail::EnumValuesRegistry m_enumValuesRegistry;
        };
    }

    using RegistryHubSingleton = Singleton<RegistryHub, IRegistryHub, IMutableRegistryHub>;

    IRegistryHub const& getRegistryHub() {
        return RegistryHubSingleton::get();
    }
    IMutableRegistryHub& getMutableRegistryHub() {
        return RegistryHubSingleton::getMutable();
    }
    void cleanUp() {
        cleanupSingletons();
        cleanUpContext();
    }
    std::string translateActiveException() {
        return getRegistryHub().getExceptionTranslatorRegistry().translateActiveException();
    }


} // end namespace Catch



#include <algorithm>
#include <iomanip>
#include <set>

namespace Catch {

    namespace {
        const int MaxExitCode = 255;

        IStreamingReporterPtr createReporter(std::string const& reporterName, IConfig const* config) {
            auto reporter = Catch::getRegistryHub().getReporterRegistry().create(reporterName, config);
            CATCH_ENFORCE(reporter, "No reporter registered with name: '" << reporterName << "'");

            return reporter;
        }

        IStreamingReporterPtr makeReporter(Config const* config) {
            if (Catch::getRegistryHub().getReporterRegistry().getListeners().empty()) {
                return createReporter(config->getReporterName(), config);
            }

            // On older platforms, returning unique_ptr<ListeningReporter>
            // when the return type is unique_ptr<IStreamingReporter>
            // doesn't compile without a std::move call. However, this causes
            // a warning on newer platforms. Thus, we have to work around
            // it a bit and downcast the pointer manually.
            auto ret = Detail::unique_ptr<IStreamingReporter>(new ListeningReporter);
            auto& multi = static_cast<ListeningReporter&>(*ret);
            auto const& listeners = Catch::getRegistryHub().getReporterRegistry().getListeners();
            for (auto const& listener : listeners) {
                multi.addListener(listener->create(Catch::ReporterConfig(config)));
            }
            multi.addReporter(createReporter(config->getReporterName(), config));
            return ret;
        }

        class TestGroup {
        public:
            explicit TestGroup(IStreamingReporterPtr&& reporter, Config const* config):
                m_reporter(reporter.get()),
                m_config{config},
                m_context{config, std::move(reporter)} {

                auto const& allTestCases = getAllTestCasesSorted(*m_config);
                m_matches = m_config->testSpec().matchesByFilter(allTestCases, *m_config);
                auto const& invalidArgs = m_config->testSpec().getInvalidArgs();

                if (m_matches.empty() && invalidArgs.empty()) {
                    for (auto const& test : allTestCases)
                        if (!test.getTestCaseInfo().isHidden())
                            m_tests.emplace(&test);
                } else {
                    for (auto const& match : m_matches)
                        m_tests.insert(match.tests.begin(), match.tests.end());
                }
            }

            Totals execute() {
                auto const& invalidArgs = m_config->testSpec().getInvalidArgs();
                Totals totals;
                m_context.testGroupStarting(m_config->name(), 1, 1);
                for (auto const& testCase : m_tests) {
                    if (!m_context.aborting())
                        totals += m_context.runTest(*testCase);
                    else
                        m_reporter->skipTest(testCase->getTestCaseInfo());
                }

                for (auto const& match : m_matches) {
                    if (match.tests.empty()) {
                        m_reporter->noMatchingTestCases(match.name);
                        totals.error = -1;
                    }
                }

                if (!invalidArgs.empty()) {
                    for (auto const& invalidArg: invalidArgs)
                         m_reporter->reportInvalidArguments(invalidArg);
                }

                m_context.testGroupEnded(m_config->name(), totals, 1, 1);
                return totals;
            }

        private:
            using Tests = std::set<TestCaseHandle const*>;

            IStreamingReporter* m_reporter;
            Config const* m_config;
            RunContext m_context;
            Tests m_tests;
            TestSpec::Matches m_matches;
        };

        void applyFilenamesAsTags() {
            for (auto const& testInfo : getRegistryHub().getTestCaseRegistry().getAllInfos()) {
                testInfo->addFilenameTag();
            }
        }

    } // anon namespace

    Session::Session() {
        static bool alreadyInstantiated = false;
        if( alreadyInstantiated ) {
            CATCH_TRY { CATCH_INTERNAL_ERROR( "Only one instance of Catch::Session can ever be used" ); }
            CATCH_CATCH_ALL { getMutableRegistryHub().registerStartupException(); }
        }

        // There cannot be exceptions at startup in no-exception mode.
#if !defined(CATCH_CONFIG_DISABLE_EXCEPTIONS)
        const auto& exceptions = getRegistryHub().getStartupExceptionRegistry().getExceptions();
        if ( !exceptions.empty() ) {
            config();
            getCurrentMutableContext().setConfig(m_config.get());

            m_startupExceptions = true;
            Colour colourGuard( Colour::Red );
            Catch::cerr() << "Errors occurred during startup!" << '\n';
            // iterate over all exceptions and notify user
            for ( const auto& ex_ptr : exceptions ) {
                try {
                    std::rethrow_exception(ex_ptr);
                } catch ( std::exception const& ex ) {
                    Catch::cerr() << TextFlow::Column( ex.what() ).indent(2) << '\n';
                }
            }
        }
#endif

        alreadyInstantiated = true;
        m_cli = makeCommandLineParser( m_configData );
    }
    Session::~Session() {
        Catch::cleanUp();
    }

    void Session::showHelp() const {
        Catch::cout()
                << "\nCatch v" << libraryVersion() << "\n"
                << m_cli << std::endl
                << "For more detailed usage please see the project docs\n" << std::endl;
    }
    void Session::libIdentify() {
        Catch::cout()
                << std::left << std::setw(16) << "description: " << "A Catch2 test executable\n"
                << std::left << std::setw(16) << "category: " << "testframework\n"
                << std::left << std::setw(16) << "framework: " << "Catch Test\n"
                << std::left << std::setw(16) << "version: " << libraryVersion() << std::endl;
    }

    int Session::applyCommandLine( int argc, char const * const * argv ) {
        if( m_startupExceptions )
            return 1;

        auto result = m_cli.parse( Clara::Args( argc, argv ) );
        if( !result ) {
            config();
            getCurrentMutableContext().setConfig(m_config.get());
            Catch::cerr()
                << Colour( Colour::Red )
                << "\nError(s) in input:\n"
                << TextFlow::Column( result.errorMessage() ).indent( 2 )
                << "\n\n";
            Catch::cerr() << "Run with -? for usage\n" << std::endl;
            return MaxExitCode;
        }

        if( m_configData.showHelp )
            showHelp();
        if( m_configData.libIdentify )
            libIdentify();
        m_config.reset();
        return 0;
    }

#if defined(CATCH_CONFIG_WCHAR) && defined(_WIN32) && defined(UNICODE)
    int Session::applyCommandLine( int argc, wchar_t const * const * argv ) {

        char **utf8Argv = new char *[ argc ];

        for ( int i = 0; i < argc; ++i ) {
            int bufSize = WideCharToMultiByte( CP_UTF8, 0, argv[i], -1, nullptr, 0, nullptr, nullptr );

            utf8Argv[ i ] = new char[ bufSize ];

            WideCharToMultiByte( CP_UTF8, 0, argv[i], -1, utf8Argv[i], bufSize, nullptr, nullptr );
        }

        int returnCode = applyCommandLine( argc, utf8Argv );

        for ( int i = 0; i < argc; ++i )
            delete [] utf8Argv[ i ];

        delete [] utf8Argv;

        return returnCode;
    }
#endif

    void Session::useConfigData( ConfigData const& configData ) {
        m_configData = configData;
        m_config.reset();
    }

    int Session::run() {
        if( ( m_configData.waitForKeypress & WaitForKeypress::BeforeStart ) != 0 ) {
            Catch::cout() << "...waiting for enter/ return before starting" << std::endl;
            static_cast<void>(std::getchar());
        }
        int exitCode = runInternal();
        if( ( m_configData.waitForKeypress & WaitForKeypress::BeforeExit ) != 0 ) {
            Catch::cout() << "...waiting for enter/ return before exiting, with code: " << exitCode << std::endl;
            static_cast<void>(std::getchar());
        }
        return exitCode;
    }

    Clara::Parser const& Session::cli() const {
        return m_cli;
    }
    void Session::cli( Clara::Parser const& newParser ) {
        m_cli = newParser;
    }
    ConfigData& Session::configData() {
        return m_configData;
    }
    Config& Session::config() {
        if( !m_config )
            m_config = Detail::make_unique<Config>( m_configData );
        return *m_config;
    }

    int Session::runInternal() {
        if( m_startupExceptions )
            return 1;

        if (m_configData.showHelp || m_configData.libIdentify) {
            return 0;
        }

        CATCH_TRY {
            config(); // Force config to be constructed

            seedRng( *m_config );

            if (m_configData.filenamesAsTags) {
                applyFilenamesAsTags();
            }

            // Set up global config instance before we start calling into other functions
            getCurrentMutableContext().setConfig(m_config.get());

            // Create reporter(s) so we can route listings through them
            auto reporter = makeReporter(m_config.get());

            // Handle list request
            if (list(*reporter, *m_config)) {
                return 0;
            }

            TestGroup tests { std::move(reporter), m_config.get() };
            auto const totals = tests.execute();

            if( m_config->warnAboutNoTests() && totals.error == -1 )
                return 2;

            // Note that on unices only the lower 8 bits are usually used, clamping
            // the return value to 255 prevents false negative when some multiple
            // of 256 tests has failed
            return (std::min) (MaxExitCode, (std::max) (totals.error, static_cast<int>(totals.assertions.failed)));
        }
#if !defined(CATCH_CONFIG_DISABLE_EXCEPTIONS)
        catch( std::exception& ex ) {
            Catch::cerr() << ex.what() << std::endl;
            return MaxExitCode;
        }
#endif
    }

} // end namespace Catch



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



#include <algorithm>
#include <string>
#include <vector>

namespace Catch {

    TestSpec::Pattern::Pattern( std::string const& name )
    : m_name( name )
    {}

    TestSpec::Pattern::~Pattern() = default;

    std::string const& TestSpec::Pattern::name() const {
        return m_name;
    }


    TestSpec::NamePattern::NamePattern( std::string const& name, std::string const& filterString )
    : Pattern( filterString )
    , m_wildcardPattern( toLower( name ), CaseSensitive::No )
    {}

    bool TestSpec::NamePattern::matches( TestCaseInfo const& testCase ) const {
        return m_wildcardPattern.matches( testCase.name );
    }


    TestSpec::TagPattern::TagPattern( std::string const& tag, std::string const& filterString )
    : Pattern( filterString )
    , m_tag( toLower( tag ) )
    {}

    bool TestSpec::TagPattern::matches( TestCaseInfo const& testCase ) const {
        return std::find_if(begin(testCase.tags),
                            end(testCase.tags),
                            [&](Tag const& tag) {
                                return tag.lowerCased == m_tag;
                            }) != end(testCase.tags);
    }

    bool TestSpec::Filter::matches( TestCaseInfo const& testCase ) const {
        bool should_use = !testCase.isHidden();
        for (auto const& pattern : m_required) {
            should_use = true;
            if (!pattern->matches(testCase)) {
                return false;
            }
        }
        for (auto const& pattern : m_forbidden) {
            if (pattern->matches(testCase)) {
                return false;
            }
        }
        return should_use;
    }

    std::string TestSpec::Filter::name() const {
        std::string name;
        for (auto const& p : m_required) {
            name += p->name();
        }
        for (auto const& p : m_forbidden) {
            name += p->name();
        }
        return name;
    }


    bool TestSpec::hasFilters() const {
        return !m_filters.empty();
    }

    bool TestSpec::matches( TestCaseInfo const& testCase ) const {
        return std::any_of( m_filters.begin(), m_filters.end(), [&]( Filter const& f ){ return f.matches( testCase ); } );
    }

    TestSpec::Matches TestSpec::matchesByFilter( std::vector<TestCaseHandle> const& testCases, IConfig const& config ) const
    {
        Matches matches( m_filters.size() );
        std::transform( m_filters.begin(), m_filters.end(), matches.begin(), [&]( Filter const& filter ){
            std::vector<TestCaseHandle const*> currentMatches;
            for( auto const& test : testCases )
                if( isThrowSafe( test, config ) && filter.matches( test.getTestCaseInfo() ) )
                    currentMatches.emplace_back( &test );
            return FilterMatch{ filter.name(), currentMatches };
        } );
        return matches;
    }

    const TestSpec::vectorStrings& TestSpec::getInvalidArgs() const{
        return  (m_invalidArgs);
    }

}



#include <chrono>

static const uint64_t nanosecondsInSecond = 1000000000;

namespace Catch {

    auto getCurrentNanosecondsSinceEpoch() -> uint64_t {
        return std::chrono::duration_cast<std::chrono::nanoseconds>( std::chrono::high_resolution_clock::now().time_since_epoch() ).count();
    }

    namespace {
        auto estimateClockResolution() -> uint64_t {
            uint64_t sum = 0;
            static const uint64_t iterations = 1000000;

            auto startTime = getCurrentNanosecondsSinceEpoch();

            for( std::size_t i = 0; i < iterations; ++i ) {

                uint64_t ticks;
                uint64_t baseTicks = getCurrentNanosecondsSinceEpoch();
                do {
                    ticks = getCurrentNanosecondsSinceEpoch();
                } while( ticks == baseTicks );

                auto delta = ticks - baseTicks;
                sum += delta;

                // If we have been calibrating for over 3 seconds -- the clock
                // is terrible and we should move on.
                // TBD: How to signal that the measured resolution is probably wrong?
                if (ticks > startTime + 3 * nanosecondsInSecond) {
                    return sum / ( i + 1u );
                }
            }

            // We're just taking the mean, here. To do better we could take the std. dev and exclude outliers
            // - and potentially do more iterations if there's a high variance.
            return sum/iterations;
        }
    }
    auto getEstimatedClockResolution() -> uint64_t {
        static auto s_resolution = estimateClockResolution();
        return s_resolution;
    }

    void Timer::start() {
       m_nanoseconds = getCurrentNanosecondsSinceEpoch();
    }
    auto Timer::getElapsedNanoseconds() const -> uint64_t {
        return getCurrentNanosecondsSinceEpoch() - m_nanoseconds;
    }
    auto Timer::getElapsedMicroseconds() const -> uint64_t {
        return getElapsedNanoseconds()/1000;
    }
    auto Timer::getElapsedMilliseconds() const -> unsigned int {
        return static_cast<unsigned int>(getElapsedMicroseconds()/1000);
    }
    auto Timer::getElapsedSeconds() const -> double {
        return getElapsedMicroseconds()/1000000.0;
    }


} // namespace Catch


#if defined(__clang__)
#    pragma clang diagnostic push
#    pragma clang diagnostic ignored "-Wexit-time-destructors"
#    pragma clang diagnostic ignored "-Wglobal-constructors"
#endif



#include <cmath>
#include <iomanip>

namespace Catch {

namespace Detail {

    const std::string unprintableString = "{?}";

    namespace {
        const int hexThreshold = 255;

        struct Endianness {
            enum Arch { Big, Little };

            static Arch which() {
                int one = 1;
                // If the lowest byte we read is non-zero, we can assume
                // that little endian format is used.
                auto value = *reinterpret_cast<char*>(&one);
                return value ? Little : Big;
            }
        };

        template<typename T>
        std::string fpToString(T value, int precision) {
            if (Catch::isnan(value)) {
                return "nan";
            }

            ReusableStringStream rss;
            rss << std::setprecision(precision)
                << std::fixed
                << value;
            std::string d = rss.str();
            std::size_t i = d.find_last_not_of('0');
            if (i != std::string::npos && i != d.size() - 1) {
                if (d[i] == '.')
                    i++;
                d = d.substr(0, i + 1);
            }
            return d;
        }
    } // end unnamed namespace

    std::string rawMemoryToString( const void *object, std::size_t size ) {
        // Reverse order for little endian architectures
        int i = 0, end = static_cast<int>( size ), inc = 1;
        if( Endianness::which() == Endianness::Little ) {
            i = end-1;
            end = inc = -1;
        }

        unsigned char const *bytes = static_cast<unsigned char const *>(object);
        ReusableStringStream rss;
        rss << "0x" << std::setfill('0') << std::hex;
        for( ; i != end; i += inc )
             rss << std::setw(2) << static_cast<unsigned>(bytes[i]);
       return rss.str();
    }
} // end Detail namespace



//// ======================================================= ////
//
//   Out-of-line defs for full specialization of StringMaker
//
//// ======================================================= ////

std::string StringMaker<std::string>::convert(const std::string& str) {
    if (!getCurrentContext().getConfig()->showInvisibles()) {
        return '"' + str + '"';
    }

    std::string s("\"");
    for (char c : str) {
        switch (c) {
        case '\n':
            s.append("\\n");
            break;
        case '\t':
            s.append("\\t");
            break;
        default:
            s.push_back(c);
            break;
        }
    }
    s.append("\"");
    return s;
}

#ifdef CATCH_CONFIG_CPP17_STRING_VIEW
std::string StringMaker<std::string_view>::convert(std::string_view str) {
    return ::Catch::Detail::stringify(std::string{ str });
}
#endif

std::string StringMaker<char const*>::convert(char const* str) {
    if (str) {
        return ::Catch::Detail::stringify(std::string{ str });
    } else {
        return{ "{null string}" };
    }
}
std::string StringMaker<char*>::convert(char* str) {
    if (str) {
        return ::Catch::Detail::stringify(std::string{ str });
    } else {
        return{ "{null string}" };
    }
}

#ifdef CATCH_CONFIG_WCHAR
std::string StringMaker<std::wstring>::convert(const std::wstring& wstr) {
    std::string s;
    s.reserve(wstr.size());
    for (auto c : wstr) {
        s += (c <= 0xff) ? static_cast<char>(c) : '?';
    }
    return ::Catch::Detail::stringify(s);
}

# ifdef CATCH_CONFIG_CPP17_STRING_VIEW
std::string StringMaker<std::wstring_view>::convert(std::wstring_view str) {
    return StringMaker<std::wstring>::convert(std::wstring(str));
}
# endif

std::string StringMaker<wchar_t const*>::convert(wchar_t const * str) {
    if (str) {
        return ::Catch::Detail::stringify(std::wstring{ str });
    } else {
        return{ "{null string}" };
    }
}
std::string StringMaker<wchar_t *>::convert(wchar_t * str) {
    if (str) {
        return ::Catch::Detail::stringify(std::wstring{ str });
    } else {
        return{ "{null string}" };
    }
}
#endif

#if defined(CATCH_CONFIG_CPP17_BYTE)
#include <cstddef>
std::string StringMaker<std::byte>::convert(std::byte value) {
    return ::Catch::Detail::stringify(std::to_integer<unsigned long long>(value));
}
#endif // defined(CATCH_CONFIG_CPP17_BYTE)

std::string StringMaker<int>::convert(int value) {
    return ::Catch::Detail::stringify(static_cast<long long>(value));
}
std::string StringMaker<long>::convert(long value) {
    return ::Catch::Detail::stringify(static_cast<long long>(value));
}
std::string StringMaker<long long>::convert(long long value) {
    ReusableStringStream rss;
    rss << value;
    if (value > Detail::hexThreshold) {
        rss << " (0x" << std::hex << value << ')';
    }
    return rss.str();
}

std::string StringMaker<unsigned int>::convert(unsigned int value) {
    return ::Catch::Detail::stringify(static_cast<unsigned long long>(value));
}
std::string StringMaker<unsigned long>::convert(unsigned long value) {
    return ::Catch::Detail::stringify(static_cast<unsigned long long>(value));
}
std::string StringMaker<unsigned long long>::convert(unsigned long long value) {
    ReusableStringStream rss;
    rss << value;
    if (value > Detail::hexThreshold) {
        rss << " (0x" << std::hex << value << ')';
    }
    return rss.str();
}

std::string StringMaker<signed char>::convert(signed char value) {
    if (value == '\r') {
        return "'\\r'";
    } else if (value == '\f') {
        return "'\\f'";
    } else if (value == '\n') {
        return "'\\n'";
    } else if (value == '\t') {
        return "'\\t'";
    } else if ('\0' <= value && value < ' ') {
        return ::Catch::Detail::stringify(static_cast<unsigned int>(value));
    } else {
        char chstr[] = "' '";
        chstr[1] = value;
        return chstr;
    }
}
std::string StringMaker<char>::convert(char c) {
    return ::Catch::Detail::stringify(static_cast<signed char>(c));
}
std::string StringMaker<unsigned char>::convert(unsigned char c) {
    return ::Catch::Detail::stringify(static_cast<char>(c));
}

int StringMaker<float>::precision = 5;

std::string StringMaker<float>::convert(float value) {
    return Detail::fpToString(value, precision) + 'f';
}

int StringMaker<double>::precision = 10;

std::string StringMaker<double>::convert(double value) {
    return Detail::fpToString(value, precision);
}

} // end namespace Catch

#if defined(__clang__)
#    pragma clang diagnostic pop
#endif




namespace Catch {

    Counts Counts::operator - ( Counts const& other ) const {
        Counts diff;
        diff.passed = passed - other.passed;
        diff.failed = failed - other.failed;
        diff.failedButOk = failedButOk - other.failedButOk;
        return diff;
    }

    Counts& Counts::operator += ( Counts const& other ) {
        passed += other.passed;
        failed += other.failed;
        failedButOk += other.failedButOk;
        return *this;
    }

    std::size_t Counts::total() const {
        return passed + failed + failedButOk;
    }
    bool Counts::allPassed() const {
        return failed == 0 && failedButOk == 0;
    }
    bool Counts::allOk() const {
        return failed == 0;
    }

    Totals Totals::operator - ( Totals const& other ) const {
        Totals diff;
        diff.assertions = assertions - other.assertions;
        diff.testCases = testCases - other.testCases;
        return diff;
    }

    Totals& Totals::operator += ( Totals const& other ) {
        assertions += other.assertions;
        testCases += other.testCases;
        return *this;
    }

    Totals Totals::delta( Totals const& prevTotals ) const {
        Totals diff = *this - prevTotals;
        if( diff.assertions.failed > 0 )
            ++diff.testCases.failed;
        else if( diff.assertions.failedButOk > 0 )
            ++diff.testCases.failedButOk;
        else
            ++diff.testCases.passed;
        return diff;
    }

}


#include <ostream>

namespace Catch {

    Version::Version
        (   unsigned int _majorVersion,
            unsigned int _minorVersion,
            unsigned int _patchNumber,
            char const * const _branchName,
            unsigned int _buildNumber )
    :   majorVersion( _majorVersion ),
        minorVersion( _minorVersion ),
        patchNumber( _patchNumber ),
        branchName( _branchName ),
        buildNumber( _buildNumber )
    {}

    std::ostream& operator << ( std::ostream& os, Version const& version ) {
        os  << version.majorVersion << '.'
            << version.minorVersion << '.'
            << version.patchNumber;
        // branchName is never null -> 0th char is \0 if it is empty
        if (version.branchName[0]) {
            os << '-' << version.branchName
               << '.' << version.buildNumber;
        }
        return os;
    }

    Version const& libraryVersion() {
        static Version version( 3, 0, 0, "preview", 3 );
        return version;
    }

}


/** \file
 * This is a special TU that combines what would otherwise be a very
 * small generator-related TUs into one bigger TU.
 *
 * The reason for this is compilation performance improvements by
 * avoiding reparsing headers for many small TUs, instead having this
 * one TU include bit more, but having it all parsed only once.
 *
 * To avoid heavy-tail problem with compilation times, each "subpart"
 * of Catch2 has its own combined TU like this.
 */

////////////////////////////////////////////////////
// vvv formerly catch_generator_exception.cpp vvv //
////////////////////////////////////////////////////


namespace Catch {

    const char* GeneratorException::what() const noexcept {
        return m_msg;
    }

} // end namespace Catch


///////////////////////////////////////////
// vvv formerly catch_generators.cpp vvv //
///////////////////////////////////////////


namespace Catch {

    IGeneratorTracker::~IGeneratorTracker() = default;

namespace Generators {

namespace Detail {

    [[noreturn]]
    void throw_generator_exception(char const* msg) {
        Catch::throw_exception(GeneratorException{ msg });
    }
} // end namespace Detail

    GeneratorUntypedBase::~GeneratorUntypedBase() = default;

    auto acquireGeneratorTracker(StringRef generatorName, SourceLineInfo const& lineInfo ) -> IGeneratorTracker& {
        return getResultCapture().acquireGeneratorTracker( generatorName, lineInfo );
    }

} // namespace Generators
} // namespace Catch


/** \file
 * This is a special TU that combines what would otherwise be a very
 * small interfaces-related TUs into one bigger TU.
 *
 * The reason for this is compilation performance improvements by
 * avoiding reparsing headers for many small TUs, instead having this
 * one TU include bit more, but having it all parsed only once.
 *
 * To avoid heavy-tail problem with compilation times, each "subpart"
 * of Catch2 has its own combined TU like this.
 */

///////////////////////////////////////////////////
// vvv formerly catch_interfaces_capture.cpp vvv //
///////////////////////////////////////////////////


namespace Catch {
    IResultCapture::~IResultCapture() = default;
}


//////////////////////////////////////////////////
// vvv formerly catch_interfaces_config.cpp vvv //
//////////////////////////////////////////////////


namespace Catch {
    IConfig::~IConfig() = default;
}


/////////////////////////////////////////////////////
// vvv formerly catch_interfaces_exception.cpp vvv //
/////////////////////////////////////////////////////


namespace Catch {
    IExceptionTranslator::~IExceptionTranslator() = default;
    IExceptionTranslatorRegistry::~IExceptionTranslatorRegistry() = default;
}


////////////////////////////////////////////////////////
// vvv formerly catch_interfaces_registry_hub.cpp vvv //
////////////////////////////////////////////////////////


namespace Catch {
    IRegistryHub::~IRegistryHub() = default;
    IMutableRegistryHub::~IMutableRegistryHub() = default;
}


//////////////////////////////////////////////////
// vvv formerly catch_interfaces_runner.cpp vvv //
//////////////////////////////////////////////////


namespace Catch {
    IRunner::~IRunner() = default;
}


////////////////////////////////////////////////////
// vvv formerly catch_interfaces_testcase.cpp vvv //
////////////////////////////////////////////////////


namespace Catch {
    ITestInvoker::~ITestInvoker() = default;
    ITestCaseRegistry::~ITestCaseRegistry() = default;
}


namespace Catch {
    IReporterRegistry::~IReporterRegistry() = default;
}



namespace Catch {
    IReporterFactory::~IReporterFactory() = default;
}



#include <algorithm>
#include <iomanip>

namespace Catch {

    ReporterConfig::ReporterConfig( IConfig const* _fullConfig )
    :   m_stream( &_fullConfig->stream() ), m_fullConfig( _fullConfig ) {}

    ReporterConfig::ReporterConfig( IConfig const* _fullConfig, std::ostream& _stream )
    :   m_stream( &_stream ), m_fullConfig( _fullConfig ) {}

    std::ostream& ReporterConfig::stream() const { return *m_stream; }
    IConfig const * ReporterConfig::fullConfig() const { return m_fullConfig; }


    TestRunInfo::TestRunInfo( std::string const& _name ) : name( _name ) {}

    GroupInfo::GroupInfo(  std::string const& _name,
                           std::size_t _groupIndex,
                           std::size_t _groupsCount )
    :   name( _name ),
        groupIndex( _groupIndex ),
        groupsCounts( _groupsCount )
    {}

     AssertionStats::AssertionStats( AssertionResult const& _assertionResult,
                                     std::vector<MessageInfo> const& _infoMessages,
                                     Totals const& _totals )
    :   assertionResult( _assertionResult ),
        infoMessages( _infoMessages ),
        totals( _totals )
    {
        assertionResult.m_resultData.lazyExpression.m_transientExpression = _assertionResult.m_resultData.lazyExpression.m_transientExpression;

        if( assertionResult.hasMessage() ) {
            // Copy message into messages list.
            // !TBD This should have been done earlier, somewhere
            MessageBuilder builder( assertionResult.getTestMacroName(), assertionResult.getSourceInfo(), assertionResult.getResultType() );
            builder << assertionResult.getMessage();
            builder.m_info.message = builder.m_stream.str();

            infoMessages.push_back( builder.m_info );
        }
    }

    SectionStats::SectionStats(  SectionInfo const& _sectionInfo,
                                 Counts const& _assertions,
                                 double _durationInSeconds,
                                 bool _missingAssertions )
    :   sectionInfo( _sectionInfo ),
        assertions( _assertions ),
        durationInSeconds( _durationInSeconds ),
        missingAssertions( _missingAssertions )
    {}


    TestCaseStats::TestCaseStats(  TestCaseInfo const& _testInfo,
                                   Totals const& _totals,
                                   std::string const& _stdOut,
                                   std::string const& _stdErr,
                                   bool _aborting )
    : testInfo( &_testInfo ),
        totals( _totals ),
        stdOut( _stdOut ),
        stdErr( _stdErr ),
        aborting( _aborting )
    {}


    TestGroupStats::TestGroupStats( GroupInfo const& _groupInfo,
                                    Totals const& _totals,
                                    bool _aborting )
    :   groupInfo( _groupInfo ),
        totals( _totals ),
        aborting( _aborting )
    {}

    TestGroupStats::TestGroupStats( GroupInfo const& _groupInfo )
    :   groupInfo( _groupInfo ),
        aborting( false )
    {}


    TestRunStats::TestRunStats(   TestRunInfo const& _runInfo,
                    Totals const& _totals,
                    bool _aborting )
    :   runInfo( _runInfo ),
        totals( _totals ),
        aborting( _aborting )
    {}

    void IStreamingReporter::fatalErrorEncountered( StringRef ) {}

    void IStreamingReporter::listReporters(std::vector<ReporterDescription> const& descriptions, IConfig const& config) {
        Catch::cout() << "Available reporters:\n";
        const auto maxNameLen = std::max_element(descriptions.begin(), descriptions.end(),
            [](ReporterDescription const& lhs, ReporterDescription const& rhs) { return lhs.name.size() < rhs.name.size(); })
            ->name.size();

        for (auto const& desc : descriptions) {
            if (config.verbosity() == Verbosity::Quiet) {
                Catch::cout()
                    << TextFlow::Column(desc.name)
                    .indent(2)
                    .width(5 + maxNameLen) << '\n';
            } else {
                Catch::cout()
                    << TextFlow::Column(desc.name + ":")
                    .indent(2)
                    .width(5 + maxNameLen)
                    + TextFlow::Column(desc.description)
                    .initialIndent(0)
                    .indent(2)
                    .width(CATCH_CONFIG_CONSOLE_WIDTH - maxNameLen - 8)
                    << '\n';
            }
        }
        Catch::cout() << std::endl;
    }

    void IStreamingReporter::listTests(std::vector<TestCaseHandle> const& tests, IConfig const& config) {
        if (config.hasTestFilters()) {
            Catch::cout() << "Matching test cases:\n";
        } else {
            Catch::cout() << "All available test cases:\n";
        }

        for (auto const& test : tests) {
            auto const& testCaseInfo = test.getTestCaseInfo();
            Colour::Code colour = testCaseInfo.isHidden()
                ? Colour::SecondaryText
                : Colour::None;
            Colour colourGuard(colour);

            Catch::cout() << TextFlow::Column(testCaseInfo.name).initialIndent(2).indent(4) << '\n';
            if (config.verbosity() >= Verbosity::High) {
                Catch::cout() << TextFlow::Column(Catch::Detail::stringify(testCaseInfo.lineInfo)).indent(4) << std::endl;
            }
            if (!testCaseInfo.tags.empty() && config.verbosity() > Verbosity::Quiet) {
                Catch::cout() << TextFlow::Column(testCaseInfo.tagsAsString()).indent(6) << '\n';
            }
        }

        if (!config.hasTestFilters()) {
            Catch::cout() << pluralise(tests.size(), "test case") << '\n' << std::endl;
        } else {
            Catch::cout() << pluralise(tests.size(), "matching test case") << '\n' << std::endl;
        }
    }

    void IStreamingReporter::listTags(std::vector<TagInfo> const& tags, IConfig const& config) {
        if (config.hasTestFilters()) {
            Catch::cout() << "Tags for matching test cases:\n";
        } else {
            Catch::cout() << "All available tags:\n";
        }

        for (auto const& tagCount : tags) {
            ReusableStringStream rss;
            rss << "  " << std::setw(2) << tagCount.count << "  ";
            auto str = rss.str();
            auto wrapper = TextFlow::Column(tagCount.all())
                .initialIndent(0)
                .indent(str.size())
                .width(CATCH_CONFIG_CONSOLE_WIDTH - 10);
            Catch::cout() << str << wrapper << '\n';
        }
        Catch::cout() << pluralise(tags.size(), "tag") << '\n' << std::endl;
    }

} // end namespace Catch



namespace Catch {

    AssertionHandler::AssertionHandler
        (   StringRef const& macroName,
            SourceLineInfo const& lineInfo,
            StringRef capturedExpression,
            ResultDisposition::Flags resultDisposition )
    :   m_assertionInfo{ macroName, lineInfo, capturedExpression, resultDisposition },
        m_resultCapture( getResultCapture() )
    {}

    void AssertionHandler::handleExpr( ITransientExpression const& expr ) {
        m_resultCapture.handleExpr( m_assertionInfo, expr, m_reaction );
    }
    void AssertionHandler::handleMessage(ResultWas::OfType resultType, StringRef const& message) {
        m_resultCapture.handleMessage( m_assertionInfo, resultType, message, m_reaction );
    }

    auto AssertionHandler::allowThrows() const -> bool {
        return getCurrentContext().getConfig()->allowThrows();
    }

    void AssertionHandler::complete() {
        setCompleted();
        if( m_reaction.shouldDebugBreak ) {

            // If you find your debugger stopping you here then go one level up on the
            // call-stack for the code that caused it (typically a failed assertion)

            // (To go back to the test and change execution, jump over the throw, next)
            CATCH_BREAK_INTO_DEBUGGER();
        }
        if (m_reaction.shouldThrow) {
#if !defined(CATCH_CONFIG_DISABLE_EXCEPTIONS)
            throw Catch::TestFailureException();
#else
            CATCH_ERROR( "Test failure requires aborting test!" );
#endif
        }
    }
    void AssertionHandler::setCompleted() {
        m_completed = true;
    }

    void AssertionHandler::handleUnexpectedInflightException() {
        m_resultCapture.handleUnexpectedInflightException( m_assertionInfo, Catch::translateActiveException(), m_reaction );
    }

    void AssertionHandler::handleExceptionThrownAsExpected() {
        m_resultCapture.handleNonExpr(m_assertionInfo, ResultWas::Ok, m_reaction);
    }
    void AssertionHandler::handleExceptionNotThrownAsExpected() {
        m_resultCapture.handleNonExpr(m_assertionInfo, ResultWas::Ok, m_reaction);
    }

    void AssertionHandler::handleUnexpectedExceptionNotThrown() {
        m_resultCapture.handleUnexpectedExceptionNotThrown( m_assertionInfo, m_reaction );
    }

    void AssertionHandler::handleThrowingCallSkipped() {
        m_resultCapture.handleNonExpr(m_assertionInfo, ResultWas::Ok, m_reaction);
    }

    // This is the overload that takes a string and infers the Equals matcher from it
    // The more general overload, that takes any string matcher, is in catch_capture_matchers.cpp
    void handleExceptionMatchExpr( AssertionHandler& handler, std::string const& str, StringRef const& matcherString  ) {
        handleExceptionMatchExpr( handler, Matchers::Equals( str ), matcherString );
    }

} // namespace Catch


#include <algorithm>

namespace {
    bool isOptPrefix( char c ) {
        return c == '-'
#ifdef CATCH_PLATFORM_WINDOWS
               || c == '/'
#endif
            ;
    }

    std::string normaliseOpt( std::string const& optName ) {
#ifdef CATCH_PLATFORM_WINDOWS
        if ( optName[0] == '/' )
            return "-" + optName.substr( 1 );
        else
#endif
            return optName;
    }

} // namespace

namespace Catch {
    namespace Clara {
        namespace Detail {

            void TokenStream::loadBuffer() {
                m_tokenBuffer.clear();

                // Skip any empty strings
                while ( it != itEnd && it->empty() ) {
                    ++it;
                }

                if ( it != itEnd ) {
                    auto const& next = *it;
                    if ( isOptPrefix( next[0] ) ) {
                        auto delimiterPos = next.find_first_of( " :=" );
                        if ( delimiterPos != std::string::npos ) {
                            m_tokenBuffer.push_back(
                                { TokenType::Option,
                                  next.substr( 0, delimiterPos ) } );
                            m_tokenBuffer.push_back(
                                { TokenType::Argument,
                                  next.substr( delimiterPos + 1 ) } );
                        } else {
                            if ( next[1] != '-' && next.size() > 2 ) {
                                std::string opt = "- ";
                                for ( size_t i = 1; i < next.size(); ++i ) {
                                    opt[1] = next[i];
                                    m_tokenBuffer.push_back(
                                        { TokenType::Option, opt } );
                                }
                            } else {
                                m_tokenBuffer.push_back(
                                    { TokenType::Option, next } );
                            }
                        }
                    } else {
                        m_tokenBuffer.push_back(
                            { TokenType::Argument, next } );
                    }
                }
            }

            TokenStream::TokenStream( Args const& args ):
                TokenStream( args.m_args.begin(), args.m_args.end() ) {}

            TokenStream::TokenStream( Iterator it_, Iterator itEnd_ ):
                it( it_ ), itEnd( itEnd_ ) {
                loadBuffer();
            }

            TokenStream& TokenStream::operator++() {
                if ( m_tokenBuffer.size() >= 2 ) {
                    m_tokenBuffer.erase( m_tokenBuffer.begin() );
                } else {
                    if ( it != itEnd )
                        ++it;
                    loadBuffer();
                }
                return *this;
            }

            ParserResult convertInto( std::string const& source,
                                      std::string& target ) {
                target = source;
                return ParserResult::ok( ParseResultType::Matched );
            }

            ParserResult convertInto( std::string const& source,
                                      bool& target ) {
                std::string srcLC = toLower( source );

                if ( srcLC == "y" || srcLC == "1" || srcLC == "true" ||
                     srcLC == "yes" || srcLC == "on" ) {
                    target = true;
                } else if ( srcLC == "n" || srcLC == "0" || srcLC == "false" ||
                            srcLC == "no" || srcLC == "off" ) {
                    target = false;
                } else {
                    return ParserResult::runtimeError(
                        "Expected a boolean value but did not recognise: '" +
                        source + "'" );
                }
                return ParserResult::ok( ParseResultType::Matched );
            }

            size_t ParserBase::cardinality() const { return 1; }

            InternalParseResult ParserBase::parse( Args const& args ) const {
                return parse( args.exeName(), TokenStream( args ) );
            }

            ParseState::ParseState( ParseResultType type,
                                    TokenStream const& remainingTokens ):
                m_type( type ), m_remainingTokens( remainingTokens ) {}

            ParserResult BoundFlagRef::setFlag( bool flag ) {
                m_ref = flag;
                return ParserResult::ok( ParseResultType::Matched );
            }

            ResultBase::~ResultBase() = default;

            bool BoundRef::isContainer() const { return false; }

            bool BoundRef::isFlag() const { return false; }

            bool BoundFlagRefBase::isFlag() const { return true; }

} // namespace Detail

        Detail::InternalParseResult Arg::parse(std::string const&,
                                               Detail::TokenStream const& tokens) const {
            auto validationResult = validate();
            if (!validationResult)
                return Detail::InternalParseResult(validationResult);

            auto remainingTokens = tokens;
            auto const& token = *remainingTokens;
            if (token.type != Detail::TokenType::Argument)
                return Detail::InternalParseResult::ok(Detail::ParseState(
                    ParseResultType::NoMatch, remainingTokens));

            assert(!m_ref->isFlag());
            auto valueRef =
                static_cast<Detail::BoundValueRefBase*>(m_ref.get());

            auto result = valueRef->setValue(remainingTokens->token);
            if (!result)
                return Detail::InternalParseResult(result);
            else
                return Detail::InternalParseResult::ok(Detail::ParseState(
                    ParseResultType::Matched, ++remainingTokens));
        }

        Opt::Opt(bool& ref) :
            ParserRefImpl(std::make_shared<Detail::BoundFlagRef>(ref)) {}

        std::vector<Detail::HelpColumns> Opt::getHelpColumns() const {
            std::ostringstream oss;
            bool first = true;
            for (auto const& opt : m_optNames) {
                if (first)
                    first = false;
                else
                    oss << ", ";
                oss << opt;
            }
            if (!m_hint.empty())
                oss << " <" << m_hint << '>';
            return { { oss.str(), m_description } };
        }

        bool Opt::isMatch(std::string const& optToken) const {
            auto normalisedToken = normaliseOpt(optToken);
            for (auto const& name : m_optNames) {
                if (normaliseOpt(name) == normalisedToken)
                    return true;
            }
            return false;
        }

        Detail::InternalParseResult Opt::parse(std::string const&,
                                       Detail::TokenStream const& tokens) const {
            auto validationResult = validate();
            if (!validationResult)
                return Detail::InternalParseResult(validationResult);

            auto remainingTokens = tokens;
            if (remainingTokens &&
                remainingTokens->type == Detail::TokenType::Option) {
                auto const& token = *remainingTokens;
                if (isMatch(token.token)) {
                    if (m_ref->isFlag()) {
                        auto flagRef =
                            static_cast<Detail::BoundFlagRefBase*>(
                                m_ref.get());
                        auto result = flagRef->setFlag(true);
                        if (!result)
                            return Detail::InternalParseResult(result);
                        if (result.value() ==
                            ParseResultType::ShortCircuitAll)
                            return Detail::InternalParseResult::ok(Detail::ParseState(
                                result.value(), remainingTokens));
                    } else {
                        auto valueRef =
                            static_cast<Detail::BoundValueRefBase*>(
                                m_ref.get());
                        ++remainingTokens;
                        if (!remainingTokens)
                            return Detail::InternalParseResult::runtimeError(
                                "Expected argument following " +
                                token.token);
                        auto const& argToken = *remainingTokens;
                        if (argToken.type != Detail::TokenType::Argument)
                            return Detail::InternalParseResult::runtimeError(
                                "Expected argument following " +
                                token.token);
                        auto result = valueRef->setValue(argToken.token);
                        if (!result)
                            return Detail::InternalParseResult(result);
                        if (result.value() ==
                            ParseResultType::ShortCircuitAll)
                            return Detail::InternalParseResult::ok(Detail::ParseState(
                                result.value(), remainingTokens));
                    }
                    return Detail::InternalParseResult::ok(Detail::ParseState(
                        ParseResultType::Matched, ++remainingTokens));
                }
            }
            return Detail::InternalParseResult::ok(
                Detail::ParseState(ParseResultType::NoMatch, remainingTokens));
        }

        Detail::Result Opt::validate() const {
            if (m_optNames.empty())
                return Detail::Result::logicError("No options supplied to Opt");
            for (auto const& name : m_optNames) {
                if (name.empty())
                    return Detail::Result::logicError(
                        "Option name cannot be empty");
#ifdef CATCH_PLATFORM_WINDOWS
                if (name[0] != '-' && name[0] != '/')
                    return Detail::Result::logicError(
                        "Option name must begin with '-' or '/'");
#else
                if (name[0] != '-')
                    return Detail::Result::logicError(
                        "Option name must begin with '-'");
#endif
            }
            return ParserRefImpl::validate();
        }

        ExeName::ExeName() :
            m_name(std::make_shared<std::string>("<executable>")) {}

        ExeName::ExeName(std::string& ref) : ExeName() {
            m_ref = std::make_shared<Detail::BoundValueRef<std::string>>(ref);
        }

        Detail::InternalParseResult
            ExeName::parse(std::string const&,
                           Detail::TokenStream const& tokens) const {
            return Detail::InternalParseResult::ok(
                Detail::ParseState(ParseResultType::NoMatch, tokens));
        }

        ParserResult ExeName::set(std::string const& newName) {
            auto lastSlash = newName.find_last_of("\\/");
            auto filename = (lastSlash == std::string::npos)
                ? newName
                : newName.substr(lastSlash + 1);

            *m_name = filename;
            if (m_ref)
                return m_ref->setValue(filename);
            else
                return ParserResult::ok(ParseResultType::Matched);
        }




        Parser& Parser::operator|=( Parser const& other ) {
            m_options.insert( m_options.end(),
                              other.m_options.begin(),
                              other.m_options.end() );
            m_args.insert(
                m_args.end(), other.m_args.begin(), other.m_args.end() );
            return *this;
        }

        std::vector<Detail::HelpColumns> Parser::getHelpColumns() const {
            std::vector<Detail::HelpColumns> cols;
            for ( auto const& o : m_options ) {
                auto childCols = o.getHelpColumns();
                cols.insert( cols.end(), childCols.begin(), childCols.end() );
            }
            return cols;
        }

        void Parser::writeToStream( std::ostream& os ) const {
            if ( !m_exeName.name().empty() ) {
                os << "usage:\n"
                   << "  " << m_exeName.name() << ' ';
                bool required = true, first = true;
                for ( auto const& arg : m_args ) {
                    if ( first )
                        first = false;
                    else
                        os << ' ';
                    if ( arg.isOptional() && required ) {
                        os << '[';
                        required = false;
                    }
                    os << '<' << arg.hint() << '>';
                    if ( arg.cardinality() == 0 )
                        os << " ... ";
                }
                if ( !required )
                    os << ']';
                if ( !m_options.empty() )
                    os << " options";
                os << "\n\nwhere options are:\n";
            }

            auto rows = getHelpColumns();
            size_t consoleWidth = CATCH_CONFIG_CONSOLE_WIDTH;
            size_t optWidth = 0;
            for ( auto const& cols : rows )
                optWidth = ( std::max )( optWidth, cols.left.size() + 2 );

            optWidth = ( std::min )( optWidth, consoleWidth / 2 );

            for ( auto const& cols : rows ) {
                auto row = TextFlow::Column( cols.left )
                               .width( optWidth )
                               .indent( 2 ) +
                           TextFlow::Spacer( 4 ) +
                           TextFlow::Column( cols.right )
                               .width( consoleWidth - 7 - optWidth );
                os << row << '\n';
            }
        }

        Detail::Result Parser::validate() const {
            for ( auto const& opt : m_options ) {
                auto result = opt.validate();
                if ( !result )
                    return result;
            }
            for ( auto const& arg : m_args ) {
                auto result = arg.validate();
                if ( !result )
                    return result;
            }
            return Detail::Result::ok();
        }

        Detail::InternalParseResult
        Parser::parse( std::string const& exeName,
                       Detail::TokenStream const& tokens ) const {

            struct ParserInfo {
                ParserBase const* parser = nullptr;
                size_t count = 0;
            };
            std::vector<ParserInfo> parseInfos;
            parseInfos.reserve( m_options.size() + m_args.size() );
            for ( auto const& opt : m_options ) {
                parseInfos.push_back( { &opt, 0 } );
            }
            for ( auto const& arg : m_args ) {
                parseInfos.push_back( { &arg, 0 } );
            }

            m_exeName.set( exeName );

            auto result = Detail::InternalParseResult::ok(
                Detail::ParseState( ParseResultType::NoMatch, tokens ) );
            while ( result.value().remainingTokens() ) {
                bool tokenParsed = false;

                for ( auto& parseInfo : parseInfos ) {
                    if ( parseInfo.parser->cardinality() == 0 ||
                         parseInfo.count < parseInfo.parser->cardinality() ) {
                        result = parseInfo.parser->parse(
                            exeName, result.value().remainingTokens() );
                        if ( !result )
                            return result;
                        if ( result.value().type() !=
                             ParseResultType::NoMatch ) {
                            tokenParsed = true;
                            ++parseInfo.count;
                            break;
                        }
                    }
                }

                if ( result.value().type() == ParseResultType::ShortCircuitAll )
                    return result;
                if ( !tokenParsed )
                    return Detail::InternalParseResult::runtimeError(
                        "Unrecognised token: " +
                        result.value().remainingTokens()->token );
            }
            // !TBD Check missing required options
            return result;
        }

        Args::Args(int argc, char const* const* argv) :
            m_exeName(argv[0]), m_args(argv + 1, argv + argc) {}

        Args::Args(std::initializer_list<std::string> args) :
            m_exeName(*args.begin()),
            m_args(args.begin() + 1, args.end()) {}


        Help::Help( bool& showHelpFlag ):
            Opt( [&]( bool flag ) {
                showHelpFlag = flag;
                return ParserResult::ok( ParseResultType::ShortCircuitAll );
            } ) {
            static_cast<Opt&> ( *this )(
                "display usage information" )["-?"]["-h"]["--help"]
                .optional();
        }

    } // namespace Clara
} // namespace Catch


/** \file
 * This is a special TU that combines what would otherwise be a very
 * small top-level TUs into one bigger TU.
 *
 * The reason for this is compilation performance improvements by
 * avoiding reparsing headers for many small TUs, instead having this
 * one TU include bit more, but having it all parsed only once.
 *
 * To avoid heavy-tail problem with compilation times, each "subpart"
 * of Catch2 has its own combined TU like this.
 */


////////////////////////////////////////////////////////
// vvv formerly catch_tag_alias_autoregistrar.cpp vvv //
////////////////////////////////////////////////////////


namespace Catch {

    RegistrarForTagAliases::RegistrarForTagAliases(char const* alias, char const* tag, SourceLineInfo const& lineInfo) {
        CATCH_TRY {
            getMutableRegistryHub().registerTagAlias(alias, tag, lineInfo);
        } CATCH_CATCH_ALL {
            // Do not throw when constructing global objects, instead register the exception to be processed later
            getMutableRegistryHub().registerStartupException();
        }
    }

}


//////////////////////////////////////////
// vvv formerly catch_polyfills.cpp vvv //
//////////////////////////////////////////

#include <cmath>

namespace Catch {

#if !defined(CATCH_CONFIG_POLYFILL_ISNAN)
    bool isnan(float f) {
        return std::isnan(f);
    }
    bool isnan(double d) {
        return std::isnan(d);
    }
#else
    // For now we only use this for embarcadero
    bool isnan(float f) {
        return std::_isnan(f);
    }
    bool isnan(double d) {
        return std::_isnan(d);
    }
#endif

} // end namespace Catch


////////////////////////////////////////////////////
// vvv formerly catch_uncaught_exceptions.cpp vvv //
////////////////////////////////////////////////////


#include <exception>

namespace Catch {
    bool uncaught_exceptions() {
#if defined(CATCH_CONFIG_DISABLE_EXCEPTIONS)
        return false;
#elif defined(CATCH_CONFIG_CPP17_UNCAUGHT_EXCEPTIONS)
        return std::uncaught_exceptions() > 0;
#else
        return std::uncaught_exception();
#endif
  }
} // end namespace Catch


////////////////////////////////////////////
// vvv formerly catch_errno_guard.cpp vvv //
////////////////////////////////////////////

#include <cerrno>

namespace Catch {
        ErrnoGuard::ErrnoGuard():m_oldErrno(errno){}
        ErrnoGuard::~ErrnoGuard() { errno = m_oldErrno; }
}


///////////////////////////////////////////
// vvv formerly catch_decomposer.cpp vvv //
///////////////////////////////////////////

namespace Catch {

    ITransientExpression::~ITransientExpression() = default;

    void formatReconstructedExpression( std::ostream &os, std::string const& lhs, StringRef op, std::string const& rhs ) {
        if( lhs.size() + rhs.size() < 40 &&
                lhs.find('\n') == std::string::npos &&
                rhs.find('\n') == std::string::npos )
            os << lhs << ' ' << op << ' ' << rhs;
        else
            os << lhs << '\n' << op << '\n' << rhs;
    }
}


///////////////////////////////////////////////////////////
// vvv formerly catch_startup_exception_registry.cpp vvv //
///////////////////////////////////////////////////////////

namespace Catch {
#if !defined(CATCH_CONFIG_DISABLE_EXCEPTIONS)
    void StartupExceptionRegistry::add( std::exception_ptr const& exception ) noexcept {
        CATCH_TRY {
            m_exceptions.push_back(exception);
        } CATCH_CATCH_ALL {
            // If we run out of memory during start-up there's really not a lot more we can do about it
            std::terminate();
        }
    }

    std::vector<std::exception_ptr> const& StartupExceptionRegistry::getExceptions() const noexcept {
        return m_exceptions;
    }
#endif

} // end namespace Catch


//////////////////////////////////////////////
// vvv formerly catch_leak_detector.cpp vvv //
//////////////////////////////////////////////


#ifdef CATCH_CONFIG_WINDOWS_CRTDBG
#include <crtdbg.h>

namespace Catch {

    LeakDetector::LeakDetector() {
        int flag = _CrtSetDbgFlag(_CRTDBG_REPORT_FLAG);
        flag |= _CRTDBG_LEAK_CHECK_DF;
        flag |= _CRTDBG_ALLOC_MEM_DF;
        _CrtSetDbgFlag(flag);
        _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE | _CRTDBG_MODE_DEBUG);
        _CrtSetReportFile(_CRT_WARN, _CRTDBG_FILE_STDERR);
        // Change this to leaking allocation's number to break there
        _CrtSetBreakAlloc(-1);
    }
}

#else // ^^ Windows crt debug heap enabled // Windows crt debug heap disabled vv

    Catch::LeakDetector::LeakDetector() {}

#endif // CATCH_CONFIG_WINDOWS_CRTDBG

Catch::LeakDetector::~LeakDetector() {
    Catch::cleanUp();
}


/////////////////////////////////////////////
// vvv formerly catch_message_info.cpp vvv //
/////////////////////////////////////////////


namespace Catch {

    MessageInfo::MessageInfo(   StringRef const& _macroName,
                                SourceLineInfo const& _lineInfo,
                                ResultWas::OfType _type )
    :   macroName( _macroName ),
        lineInfo( _lineInfo ),
        type( _type ),
        sequence( ++globalCount )
    {}

    // This may need protecting if threading support is added
    unsigned int MessageInfo::globalCount = 0;

} // end namespace Catch




//////////////////////////////////////////
// vvv formerly catch_lazy_expr.cpp vvv //
//////////////////////////////////////////

namespace Catch {

    auto operator << (std::ostream& os, LazyExpression const& lazyExpr) -> std::ostream& {
        if (lazyExpr.m_isNegated)
            os << "!";

        if (lazyExpr) {
            if (lazyExpr.m_isNegated && lazyExpr.m_transientExpression->isBinaryExpression())
                os << "(" << *lazyExpr.m_transientExpression << ")";
            else
                os << *lazyExpr.m_transientExpression;
        } else {
            os << "{** error - unchecked empty expression requested **}";
        }
        return os;
    }

} // namespace Catch




#include <fstream>
#include <ctime>

namespace Catch {

    Clara::Parser makeCommandLineParser( ConfigData& config ) {

        using namespace Clara;

        auto const setWarning = [&]( std::string const& warning ) {
                auto warningSet = [&]() {
                    if( warning == "NoAssertions" )
                        return WarnAbout::NoAssertions;

                    if ( warning == "NoTests" )
                        return WarnAbout::NoTests;

                    return WarnAbout::Nothing;
                }();

                if (warningSet == WarnAbout::Nothing)
                    return ParserResult::runtimeError( "Unrecognised warning: '" + warning + "'" );
                config.warnings = static_cast<WarnAbout::What>( config.warnings | warningSet );
                return ParserResult::ok( ParseResultType::Matched );
            };
        auto const loadTestNamesFromFile = [&]( std::string const& filename ) {
                std::ifstream f( filename.c_str() );
                if( !f.is_open() )
                    return ParserResult::runtimeError( "Unable to load input file: '" + filename + "'" );

                std::string line;
                while( std::getline( f, line ) ) {
                    line = trim(line);
                    if( !line.empty() && !startsWith( line, '#' ) ) {
                        if( !startsWith( line, '"' ) )
                            line = '"' + line + '"';
                        config.testsOrTags.push_back( line );
                        config.testsOrTags.emplace_back( "," );
                    }
                }
                //Remove comma in the end
                if(!config.testsOrTags.empty())
                    config.testsOrTags.erase( config.testsOrTags.end()-1 );

                return ParserResult::ok( ParseResultType::Matched );
            };
        auto const setTestOrder = [&]( std::string const& order ) {
                if( startsWith( "declared", order ) )
                    config.runOrder = TestRunOrder::Declared;
                else if( startsWith( "lexical", order ) )
                    config.runOrder = TestRunOrder::LexicographicallySorted;
                else if( startsWith( "random", order ) )
                    config.runOrder = TestRunOrder::Randomized;
                else
                    return ParserResult::runtimeError( "Unrecognised ordering: '" + order + "'" );
                return ParserResult::ok( ParseResultType::Matched );
            };
        auto const setRngSeed = [&]( std::string const& seed ) {
                if( seed != "time" )
                    return Clara::Detail::convertInto( seed, config.rngSeed );
                config.rngSeed = static_cast<unsigned int>( std::time(nullptr) );
                return ParserResult::ok( ParseResultType::Matched );
            };
        auto const setColourUsage = [&]( std::string const& useColour ) {
                    auto mode = toLower( useColour );

                    if( mode == "yes" )
                        config.useColour = UseColour::Yes;
                    else if( mode == "no" )
                        config.useColour = UseColour::No;
                    else if( mode == "auto" )
                        config.useColour = UseColour::Auto;
                    else
                        return ParserResult::runtimeError( "colour mode must be one of: auto, yes or no. '" + useColour + "' not recognised" );
                return ParserResult::ok( ParseResultType::Matched );
            };
        auto const setWaitForKeypress = [&]( std::string const& keypress ) {
                auto keypressLc = toLower( keypress );
                if (keypressLc == "never")
                    config.waitForKeypress = WaitForKeypress::Never;
                else if( keypressLc == "start" )
                    config.waitForKeypress = WaitForKeypress::BeforeStart;
                else if( keypressLc == "exit" )
                    config.waitForKeypress = WaitForKeypress::BeforeExit;
                else if( keypressLc == "both" )
                    config.waitForKeypress = WaitForKeypress::BeforeStartAndExit;
                else
                    return ParserResult::runtimeError( "keypress argument must be one of: never, start, exit or both. '" + keypress + "' not recognised" );
            return ParserResult::ok( ParseResultType::Matched );
            };
        auto const setVerbosity = [&]( std::string const& verbosity ) {
            auto lcVerbosity = toLower( verbosity );
            if( lcVerbosity == "quiet" )
                config.verbosity = Verbosity::Quiet;
            else if( lcVerbosity == "normal" )
                config.verbosity = Verbosity::Normal;
            else if( lcVerbosity == "high" )
                config.verbosity = Verbosity::High;
            else
                return ParserResult::runtimeError( "Unrecognised verbosity, '" + verbosity + "'" );
            return ParserResult::ok( ParseResultType::Matched );
        };
        auto const setReporter = [&]( std::string const& reporter ) {
            IReporterRegistry::FactoryMap const& factories = getRegistryHub().getReporterRegistry().getFactories();

            auto lcReporter = toLower( reporter );
            auto result = factories.find( lcReporter );

            if( factories.end() != result )
                config.reporterName = lcReporter;
            else
                return ParserResult::runtimeError( "Unrecognized reporter, '" + reporter + "'. Check available with --list-reporters" );
            return ParserResult::ok( ParseResultType::Matched );
        };

        auto cli
            = ExeName( config.processName )
            | Help( config.showHelp )
            | Opt( config.listTests )
                ["-l"]["--list-tests"]
                ( "list all/matching test cases" )
            | Opt( config.listTags )
                ["-t"]["--list-tags"]
                ( "list all/matching tags" )
            | Opt( config.showSuccessfulTests )
                ["-s"]["--success"]
                ( "include successful tests in output" )
            | Opt( config.shouldDebugBreak )
                ["-b"]["--break"]
                ( "break into debugger on failure" )
            | Opt( config.noThrow )
                ["-e"]["--nothrow"]
                ( "skip exception tests" )
            | Opt( config.showInvisibles )
                ["-i"]["--invisibles"]
                ( "show invisibles (tabs, newlines)" )
            | Opt( config.outputFilename, "filename" )
                ["-o"]["--out"]
                ( "output filename" )
            | Opt( setReporter, "name" )
                ["-r"]["--reporter"]
                ( "reporter to use (defaults to console)" )
            | Opt( config.name, "name" )
                ["-n"]["--name"]
                ( "suite name" )
            | Opt( [&]( bool ){ config.abortAfter = 1; } )
                ["-a"]["--abort"]
                ( "abort at first failure" )
            | Opt( [&]( int x ){ config.abortAfter = x; }, "no. failures" )
                ["-x"]["--abortx"]
                ( "abort after x failures" )
            | Opt( setWarning, "warning name" )
                ["-w"]["--warn"]
                ( "enable warnings" )
            | Opt( [&]( bool flag ) { config.showDurations = flag ? ShowDurations::Always : ShowDurations::Never; }, "yes|no" )
                ["-d"]["--durations"]
                ( "show test durations" )
            | Opt( config.minDuration, "seconds" )
                ["-D"]["--min-duration"]
                ( "show test durations for tests taking at least the given number of seconds" )
            | Opt( loadTestNamesFromFile, "filename" )
                ["-f"]["--input-file"]
                ( "load test names to run from a file" )
            | Opt( config.filenamesAsTags )
                ["-#"]["--filenames-as-tags"]
                ( "adds a tag for the filename" )
            | Opt( config.sectionsToRun, "section name" )
                ["-c"]["--section"]
                ( "specify section to run" )
            | Opt( setVerbosity, "quiet|normal|high" )
                ["-v"]["--verbosity"]
                ( "set output verbosity" )
            | Opt( config.listReporters )
                ["--list-reporters"]
                ( "list all reporters" )
            | Opt( setTestOrder, "decl|lex|rand" )
                ["--order"]
                ( "test case order (defaults to decl)" )
            | Opt( setRngSeed, "'time'|number" )
                ["--rng-seed"]
                ( "set a specific seed for random numbers" )
            | Opt( setColourUsage, "yes|no" )
                ["--use-colour"]
                ( "should output be colourised" )
            | Opt( config.libIdentify )
                ["--libidentify"]
                ( "report name and version according to libidentify standard" )
            | Opt( setWaitForKeypress, "never|start|exit|both" )
                ["--wait-for-keypress"]
                ( "waits for a keypress before exiting" )
            | Opt( config.benchmarkSamples, "samples" )
                ["--benchmark-samples"]
                ( "number of samples to collect (default: 100)" )
            | Opt( config.benchmarkResamples, "resamples" )
                ["--benchmark-resamples"]
                ( "number of resamples for the bootstrap (default: 100000)" )
            | Opt( config.benchmarkConfidenceInterval, "confidence interval" )
                ["--benchmark-confidence-interval"]
                ( "confidence interval for the bootstrap (between 0 and 1, default: 0.95)" )
            | Opt( config.benchmarkNoAnalysis )
                ["--benchmark-no-analysis"]
                ( "perform only measurements; do not perform any analysis" )
            | Opt( config.benchmarkWarmupTime, "benchmarkWarmupTime" )
                ["--benchmark-warmup-time"]
                ( "amount of time in milliseconds spent on warming up each test (default: 100)" )
            | Arg( config.testsOrTags, "test name|pattern|tags" )
                ( "which test or tests to use" );

        return cli;
    }

} // end namespace Catch



#include <cstring>
#include <ostream>

namespace Catch {

    bool SourceLineInfo::operator == ( SourceLineInfo const& other ) const noexcept {
        return line == other.line && (file == other.file || std::strcmp(file, other.file) == 0);
    }
    bool SourceLineInfo::operator < ( SourceLineInfo const& other ) const noexcept {
        // We can assume that the same file will usually have the same pointer.
        // Thus, if the pointers are the same, there is no point in calling the strcmp
        return line < other.line || ( line == other.line && file != other.file && (std::strcmp(file, other.file) < 0));
    }

    std::ostream& operator << ( std::ostream& os, SourceLineInfo const& info ) {
#ifndef __GNUG__
        os << info.file << '(' << info.line << ')';
#else
        os << info.file << ':' << info.line;
#endif
        return os;
    }

} // end namespace Catch


#if defined(__clang__)
#    pragma clang diagnostic push
#    pragma clang diagnostic ignored "-Wexit-time-destructors"
#endif



#include <ostream>

namespace Catch {
    namespace {

        struct IColourImpl {
            virtual ~IColourImpl() = default;
            virtual void use( Colour::Code _colourCode ) = 0;
        };

        struct NoColourImpl : IColourImpl {
            void use( Colour::Code ) override {}

            static IColourImpl* instance() {
                static NoColourImpl s_instance;
                return &s_instance;
            }
        };

    } // anon namespace
} // namespace Catch

#if !defined( CATCH_CONFIG_COLOUR_NONE ) && !defined( CATCH_CONFIG_COLOUR_WINDOWS ) && !defined( CATCH_CONFIG_COLOUR_ANSI )
#   ifdef CATCH_PLATFORM_WINDOWS
#       define CATCH_CONFIG_COLOUR_WINDOWS
#   else
#       define CATCH_CONFIG_COLOUR_ANSI
#   endif
#endif


#if defined ( CATCH_CONFIG_COLOUR_WINDOWS ) /////////////////////////////////////////

namespace Catch {
namespace {

    class Win32ColourImpl : public IColourImpl {
    public:
        Win32ColourImpl() : stdoutHandle( GetStdHandle(STD_OUTPUT_HANDLE) )
        {
            CONSOLE_SCREEN_BUFFER_INFO csbiInfo;
            GetConsoleScreenBufferInfo( stdoutHandle, &csbiInfo );
            originalForegroundAttributes = csbiInfo.wAttributes & ~( BACKGROUND_GREEN | BACKGROUND_RED | BACKGROUND_BLUE | BACKGROUND_INTENSITY );
            originalBackgroundAttributes = csbiInfo.wAttributes & ~( FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY );
        }

        void use( Colour::Code _colourCode ) override {
            switch( _colourCode ) {
                case Colour::None:      return setTextAttribute( originalForegroundAttributes );
                case Colour::White:     return setTextAttribute( FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_BLUE );
                case Colour::Red:       return setTextAttribute( FOREGROUND_RED );
                case Colour::Green:     return setTextAttribute( FOREGROUND_GREEN );
                case Colour::Blue:      return setTextAttribute( FOREGROUND_BLUE );
                case Colour::Cyan:      return setTextAttribute( FOREGROUND_BLUE | FOREGROUND_GREEN );
                case Colour::Yellow:    return setTextAttribute( FOREGROUND_RED | FOREGROUND_GREEN );
                case Colour::Grey:      return setTextAttribute( 0 );

                case Colour::LightGrey:     return setTextAttribute( FOREGROUND_INTENSITY );
                case Colour::BrightRed:     return setTextAttribute( FOREGROUND_INTENSITY | FOREGROUND_RED );
                case Colour::BrightGreen:   return setTextAttribute( FOREGROUND_INTENSITY | FOREGROUND_GREEN );
                case Colour::BrightWhite:   return setTextAttribute( FOREGROUND_INTENSITY | FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_BLUE );
                case Colour::BrightYellow:  return setTextAttribute( FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN );

                case Colour::Bright: CATCH_INTERNAL_ERROR( "not a colour" );

                default:
                    CATCH_ERROR( "Unknown colour requested" );
            }
        }

    private:
        void setTextAttribute( WORD _textAttribute ) {
            SetConsoleTextAttribute( stdoutHandle, _textAttribute | originalBackgroundAttributes );
        }
        HANDLE stdoutHandle;
        WORD originalForegroundAttributes;
        WORD originalBackgroundAttributes;
    };

    IColourImpl* platformColourInstance() {
        static Win32ColourImpl s_instance;

        auto const* config = getCurrentContext().getConfig();
        UseColour colourMode = config?
            config->useColour() : UseColour::Auto;
        if( colourMode == UseColour::Auto )
            colourMode = UseColour::Yes;
        return colourMode == UseColour::Yes
            ? &s_instance
            : NoColourImpl::instance();
    }

} // end anon namespace
} // end namespace Catch

#elif defined( CATCH_CONFIG_COLOUR_ANSI ) //////////////////////////////////////

#include <unistd.h>

namespace Catch {
namespace {

    // use POSIX/ ANSI console terminal codes
    // Thanks to Adam Strzelecki for original contribution
    // (http://github.com/nanoant)
    // https://github.com/philsquared/Catch/pull/131
    class PosixColourImpl : public IColourImpl {
    public:
        void use( Colour::Code _colourCode ) override {
            switch( _colourCode ) {
                case Colour::None:
                case Colour::White:     return setColour( "[0m" );
                case Colour::Red:       return setColour( "[0;31m" );
                case Colour::Green:     return setColour( "[0;32m" );
                case Colour::Blue:      return setColour( "[0;34m" );
                case Colour::Cyan:      return setColour( "[0;36m" );
                case Colour::Yellow:    return setColour( "[0;33m" );
                case Colour::Grey:      return setColour( "[1;30m" );

                case Colour::LightGrey:     return setColour( "[0;37m" );
                case Colour::BrightRed:     return setColour( "[1;31m" );
                case Colour::BrightGreen:   return setColour( "[1;32m" );
                case Colour::BrightWhite:   return setColour( "[1;37m" );
                case Colour::BrightYellow:  return setColour( "[1;33m" );

                case Colour::Bright: CATCH_INTERNAL_ERROR( "not a colour" );
                default: CATCH_INTERNAL_ERROR( "Unknown colour requested" );
            }
        }
        static IColourImpl* instance() {
            static PosixColourImpl s_instance;
            return &s_instance;
        }

    private:
        void setColour( const char* _escapeCode ) {
            // The escape sequence must be flushed to console, otherwise if
            // stdin and stderr are intermixed, we'd get accidentally coloured output.
            getCurrentContext().getConfig()->stream()
                << '\033' << _escapeCode << std::flush;
        }
    };

    bool useColourOnPlatform() {
        return
#if defined(CATCH_PLATFORM_MAC) || defined(CATCH_PLATFORM_IPHONE)
            !isDebuggerActive() &&
#endif
#if !(defined(__DJGPP__) && defined(__STRICT_ANSI__))
            isatty(STDOUT_FILENO)
#else
            false
#endif
            ;
    }
    IColourImpl* platformColourInstance() {
        ErrnoGuard guard;
        auto const* config = getCurrentContext().getConfig();
        UseColour colourMode = config
            ? config->useColour()
            : UseColour::Auto;
        if( colourMode == UseColour::Auto )
            colourMode = useColourOnPlatform()
                ? UseColour::Yes
                : UseColour::No;
        return colourMode == UseColour::Yes
            ? PosixColourImpl::instance()
            : NoColourImpl::instance();
    }

} // end anon namespace
} // end namespace Catch

#else  // not Windows or ANSI ///////////////////////////////////////////////

namespace Catch {

    static IColourImpl* platformColourInstance() { return NoColourImpl::instance(); }

} // end namespace Catch

#endif // Windows/ ANSI/ None

namespace Catch {

    Colour::Colour( Code _colourCode ) { use( _colourCode ); }
    Colour::Colour( Colour&& other ) noexcept {
        m_moved = other.m_moved;
        other.m_moved = true;
    }
    Colour& Colour::operator=( Colour&& other ) noexcept {
        m_moved = other.m_moved;
        other.m_moved  = true;
        return *this;
    }

    Colour::~Colour(){ if( !m_moved ) use( None ); }

    void Colour::use( Code _colourCode ) {
        static IColourImpl* impl = platformColourInstance();
        // Strictly speaking, this cannot possibly happen.
        // However, under some conditions it does happen (see #1626),
        // and this change is small enough that we can let practicality
        // triumph over purity in this case.
        if (impl != nullptr) {
            impl->use( _colourCode );
        }
    }

    std::ostream& operator << ( std::ostream& os, Colour const& ) {
        return os;
    }

} // end namespace Catch

#if defined(__clang__)
#    pragma clang diagnostic pop
#endif




namespace Catch {

    class Context : public IMutableContext, private Detail::NonCopyable {

    public: // IContext
        IResultCapture* getResultCapture() override {
            return m_resultCapture;
        }
        IRunner* getRunner() override {
            return m_runner;
        }

        IConfig const* getConfig() const override {
            return m_config;
        }

        ~Context() override;

    public: // IMutableContext
        void setResultCapture( IResultCapture* resultCapture ) override {
            m_resultCapture = resultCapture;
        }
        void setRunner( IRunner* runner ) override {
            m_runner = runner;
        }
        void setConfig( IConfig const* config ) override {
            m_config = config;
        }

        friend IMutableContext& getCurrentMutableContext();

    private:
        IConfig const* m_config = nullptr;
        IRunner* m_runner = nullptr;
        IResultCapture* m_resultCapture = nullptr;
    };

    IMutableContext *IMutableContext::currentContext = nullptr;

    void IMutableContext::createContext()
    {
        currentContext = new Context();
    }

    void cleanUpContext() {
        delete IMutableContext::currentContext;
        IMutableContext::currentContext = nullptr;
    }
    IContext::~IContext() = default;
    IMutableContext::~IMutableContext() = default;
    Context::~Context() = default;


    SimplePcg32& rng() {
        static SimplePcg32 s_rng;
        return s_rng;
    }

}



#if defined(CATCH_CONFIG_ANDROID_LOGWRITE)
#include <android/log.h>

    namespace Catch {
        void writeToDebugConsole( std::string const& text ) {
            __android_log_write( ANDROID_LOG_DEBUG, "Catch", text.c_str() );
        }
    }

#elif defined(CATCH_PLATFORM_WINDOWS)

    namespace Catch {
        void writeToDebugConsole( std::string const& text ) {
            ::OutputDebugStringA( text.c_str() );
        }
    }

#else

    namespace Catch {
        void writeToDebugConsole( std::string const& text ) {
            // !TBD: Need a version for Mac/ XCode and other IDEs
            Catch::cout() << text;
        }
    }

#endif // Platform



#if defined(CATCH_PLATFORM_MAC) || defined(CATCH_PLATFORM_IPHONE)

#  include <cassert>
#  include <sys/types.h>
#  include <unistd.h>
#  include <cstddef>
#  include <ostream>

#ifdef __apple_build_version__
    // These headers will only compile with AppleClang (XCode)
    // For other compilers (Clang, GCC, ... ) we need to exclude them
#  include <sys/sysctl.h>
#endif

    namespace Catch {
        #ifdef __apple_build_version__
        // The following function is taken directly from the following technical note:
        // https://developer.apple.com/library/archive/qa/qa1361/_index.html

        // Returns true if the current process is being debugged (either
        // running under the debugger or has a debugger attached post facto).
        bool isDebuggerActive(){
            int                 mib[4];
            struct kinfo_proc   info;
            std::size_t         size;

            // Initialize the flags so that, if sysctl fails for some bizarre
            // reason, we get a predictable result.

            info.kp_proc.p_flag = 0;

            // Initialize mib, which tells sysctl the info we want, in this case
            // we're looking for information about a specific process ID.

            mib[0] = CTL_KERN;
            mib[1] = KERN_PROC;
            mib[2] = KERN_PROC_PID;
            mib[3] = getpid();

            // Call sysctl.

            size = sizeof(info);
            if( sysctl(mib, sizeof(mib) / sizeof(*mib), &info, &size, nullptr, 0) != 0 ) {
                Catch::cerr() << "\n** Call to sysctl failed - unable to determine if debugger is active **\n" << std::endl;
                return false;
            }

            // We're being debugged if the P_TRACED flag is set.

            return ( (info.kp_proc.p_flag & P_TRACED) != 0 );
        }
        #else
        bool isDebuggerActive() {
            // We need to find another way to determine this for non-appleclang compilers on macOS
            return false;
        }
        #endif
    } // namespace Catch

#elif defined(CATCH_PLATFORM_LINUX)
    #include <fstream>
    #include <string>

    namespace Catch{
        // The standard POSIX way of detecting a debugger is to attempt to
        // ptrace() the process, but this needs to be done from a child and not
        // this process itself to still allow attaching to this process later
        // if wanted, so is rather heavy. Under Linux we have the PID of the
        // "debugger" (which doesn't need to be gdb, of course, it could also
        // be strace, for example) in /proc/$PID/status, so just get it from
        // there instead.
        bool isDebuggerActive(){
            // Libstdc++ has a bug, where std::ifstream sets errno to 0
            // This way our users can properly assert over errno values
            ErrnoGuard guard;
            std::ifstream in("/proc/self/status");
            for( std::string line; std::getline(in, line); ) {
                static const int PREFIX_LEN = 11;
                if( line.compare(0, PREFIX_LEN, "TracerPid:\t") == 0 ) {
                    // We're traced if the PID is not 0 and no other PID starts
                    // with 0 digit, so it's enough to check for just a single
                    // character.
                    return line.length() > PREFIX_LEN && line[PREFIX_LEN] != '0';
                }
            }

            return false;
        }
    } // namespace Catch
#elif defined(_MSC_VER)
    extern "C" __declspec(dllimport) int __stdcall IsDebuggerPresent();
    namespace Catch {
        bool isDebuggerActive() {
            return IsDebuggerPresent() != 0;
        }
    }
#elif defined(__MINGW32__)
    extern "C" __declspec(dllimport) int __stdcall IsDebuggerPresent();
    namespace Catch {
        bool isDebuggerActive() {
            return IsDebuggerPresent() != 0;
        }
    }
#else
    namespace Catch {
       bool isDebuggerActive() { return false; }
    }
#endif // Platform



#include <stdexcept>


namespace Catch {
#if defined(CATCH_CONFIG_DISABLE_EXCEPTIONS) && !defined(CATCH_CONFIG_DISABLE_EXCEPTIONS_CUSTOM_HANDLER)
    [[noreturn]]
    void throw_exception(std::exception const& e) {
        Catch::cerr() << "Catch will terminate because it needed to throw an exception.\n"
                      << "The message was: " << e.what() << '\n';
        std::terminate();
    }
#endif

    [[noreturn]]
    void throw_logic_error(std::string const& msg) {
        throw_exception(std::logic_error(msg));
    }

    [[noreturn]]
    void throw_domain_error(std::string const& msg) {
        throw_exception(std::domain_error(msg));
    }

    [[noreturn]]
    void throw_runtime_error(std::string const& msg) {
        throw_exception(std::runtime_error(msg));
    }



} // namespace Catch;



#include <cassert>

namespace Catch {

    IMutableEnumValuesRegistry::~IMutableEnumValuesRegistry() {}

    namespace Detail {

        namespace {
            // Extracts the actual name part of an enum instance
            // In other words, it returns the Blue part of Bikeshed::Colour::Blue
            StringRef extractInstanceName(StringRef enumInstance) {
                // Find last occurence of ":"
                size_t name_start = enumInstance.size();
                while (name_start > 0 && enumInstance[name_start - 1] != ':') {
                    --name_start;
                }
                return enumInstance.substr(name_start, enumInstance.size() - name_start);
            }
        }

        std::vector<StringRef> parseEnums( StringRef enums ) {
            auto enumValues = splitStringRef( enums, ',' );
            std::vector<StringRef> parsed;
            parsed.reserve( enumValues.size() );
            for( auto const& enumValue : enumValues ) {
                parsed.push_back(trim(extractInstanceName(enumValue)));
            }
            return parsed;
        }

        EnumInfo::~EnumInfo() {}

        StringRef EnumInfo::lookup( int value ) const {
            for( auto const& valueToName : m_values ) {
                if( valueToName.first == value )
                    return valueToName.second;
            }
            return "{** unexpected enum value **}"_sr;
        }

        Catch::Detail::unique_ptr<EnumInfo> makeEnumInfo( StringRef enumName, StringRef allValueNames, std::vector<int> const& values ) {
            auto enumInfo = Catch::Detail::make_unique<EnumInfo>();
            enumInfo->m_name = enumName;
            enumInfo->m_values.reserve( values.size() );

            const auto valueNames = Catch::Detail::parseEnums( allValueNames );
            assert( valueNames.size() == values.size() );
            std::size_t i = 0;
            for( auto value : values )
                enumInfo->m_values.emplace_back(value, valueNames[i++]);

            return enumInfo;
        }

        EnumInfo const& EnumValuesRegistry::registerEnum( StringRef enumName, StringRef allValueNames, std::vector<int> const& values ) {
            m_enumInfos.push_back(makeEnumInfo(enumName, allValueNames, values));
            return *m_enumInfos.back();
        }

    } // Detail
} // Catch




namespace Catch {

    ExceptionTranslatorRegistry::~ExceptionTranslatorRegistry() {
    }

    void ExceptionTranslatorRegistry::registerTranslator( const IExceptionTranslator* translator ) {
        m_translators.push_back( Detail::unique_ptr<const IExceptionTranslator>( translator ) );
    }

#if !defined(CATCH_CONFIG_DISABLE_EXCEPTIONS)
    std::string ExceptionTranslatorRegistry::translateActiveException() const {
        try {
            // Compiling a mixed mode project with MSVC means that CLR
            // exceptions will be caught in (...) as well. However, these
            // do not fill-in std::current_exception and thus lead to crash
            // when attempting rethrow.
            // /EHa switch also causes structured exceptions to be caught
            // here, but they fill-in current_exception properly, so
            // at worst the output should be a little weird, instead of
            // causing a crash.
            if (std::current_exception() == nullptr) {
                return "Non C++ exception. Possibly a CLR exception.";
            }
            return tryTranslators();
        }
        catch( TestFailureException& ) {
            std::rethrow_exception(std::current_exception());
        }
        catch( std::exception& ex ) {
            return ex.what();
        }
        catch( std::string& msg ) {
            return msg;
        }
        catch( const char* msg ) {
            return msg;
        }
        catch(...) {
            return "Unknown exception";
        }
    }

    std::string ExceptionTranslatorRegistry::tryTranslators() const {
        if (m_translators.empty()) {
            std::rethrow_exception(std::current_exception());
        } else {
            return m_translators[0]->translate(m_translators.begin() + 1, m_translators.end());
        }
    }

#else // ^^ Exceptions are enabled // Exceptions are disabled vv
    std::string ExceptionTranslatorRegistry::translateActiveException() const {
        CATCH_INTERNAL_ERROR("Attempted to translate active exception under CATCH_CONFIG_DISABLE_EXCEPTIONS!");
    }

    std::string ExceptionTranslatorRegistry::tryTranslators() const {
        CATCH_INTERNAL_ERROR("Attempted to use exception translators under CATCH_CONFIG_DISABLE_EXCEPTIONS!");
    }
#endif


}




#if defined(__GNUC__)
#    pragma GCC diagnostic push
#    pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#endif

#if defined( CATCH_CONFIG_WINDOWS_SEH ) || defined( CATCH_CONFIG_POSIX_SIGNALS )

namespace {
    // Report the error condition
    void reportFatal( char const * const message ) {
        Catch::getCurrentContext().getResultCapture()->handleFatalErrorCondition( message );
    }
}

#endif // signals/SEH handling

#if defined( CATCH_CONFIG_WINDOWS_SEH )

namespace Catch {
    struct SignalDefs { DWORD id; const char* name; };

    // There is no 1-1 mapping between signals and windows exceptions.
    // Windows can easily distinguish between SO and SigSegV,
    // but SigInt, SigTerm, etc are handled differently.
    static SignalDefs signalDefs[] = {
        { static_cast<DWORD>(EXCEPTION_ILLEGAL_INSTRUCTION),  "SIGILL - Illegal instruction signal" },
        { static_cast<DWORD>(EXCEPTION_STACK_OVERFLOW), "SIGSEGV - Stack overflow" },
        { static_cast<DWORD>(EXCEPTION_ACCESS_VIOLATION), "SIGSEGV - Segmentation violation signal" },
        { static_cast<DWORD>(EXCEPTION_INT_DIVIDE_BY_ZERO), "Divide by zero error" },
    };

    LONG CALLBACK FatalConditionHandler::handleVectoredException(PEXCEPTION_POINTERS ExceptionInfo) {
        for (auto const& def : signalDefs) {
            if (ExceptionInfo->ExceptionRecord->ExceptionCode == def.id) {
                reportFatal(def.name);
            }
        }
        // If its not an exception we care about, pass it along.
        // This stops us from eating debugger breaks etc.
        return EXCEPTION_CONTINUE_SEARCH;
    }

    FatalConditionHandler::FatalConditionHandler() {
        isSet = true;
        // 32k seems enough for Catch to handle stack overflow,
        // but the value was found experimentally, so there is no strong guarantee
        guaranteeSize = 32 * 1024;
        exceptionHandlerHandle = nullptr;
        // Register as first handler in current chain
        exceptionHandlerHandle = AddVectoredExceptionHandler(1, handleVectoredException);
        // Pass in guarantee size to be filled
        SetThreadStackGuarantee(&guaranteeSize);
    }

    void FatalConditionHandler::reset() {
        if (isSet) {
            RemoveVectoredExceptionHandler(exceptionHandlerHandle);
            SetThreadStackGuarantee(&guaranteeSize);
            exceptionHandlerHandle = nullptr;
            isSet = false;
        }
    }

bool FatalConditionHandler::isSet = false;
ULONG FatalConditionHandler::guaranteeSize = 0;
PVOID FatalConditionHandler::exceptionHandlerHandle = nullptr;


} // namespace Catch

#elif defined( CATCH_CONFIG_POSIX_SIGNALS )

namespace Catch {

    struct SignalDefs {
        int id;
        const char* name;
    };

    // 32kb for the alternate stack seems to be sufficient. However, this value
    // is experimentally determined, so that's not guaranteed.
    static constexpr std::size_t sigStackSize = 32768 >= MINSIGSTKSZ ? 32768 : MINSIGSTKSZ;

    static SignalDefs signalDefs[] = {
        { SIGINT,  "SIGINT - Terminal interrupt signal" },
        { SIGILL,  "SIGILL - Illegal instruction signal" },
        { SIGFPE,  "SIGFPE - Floating point error signal" },
        { SIGSEGV, "SIGSEGV - Segmentation violation signal" },
        { SIGTERM, "SIGTERM - Termination request signal" },
        { SIGABRT, "SIGABRT - Abort (abnormal termination) signal" }
    };


    void FatalConditionHandler::handleSignal( int sig ) {
        char const * name = "<unknown signal>";
        for (auto const& def : signalDefs) {
            if (sig == def.id) {
                name = def.name;
                break;
            }
        }
        reset();
        reportFatal(name);
        raise( sig );
    }

    FatalConditionHandler::FatalConditionHandler() {
        isSet = true;
        stack_t sigStack;
        sigStack.ss_sp = altStackMem;
        sigStack.ss_size = sigStackSize;
        sigStack.ss_flags = 0;
        sigaltstack(&sigStack, &oldSigStack);
        struct sigaction sa = { };

        sa.sa_handler = handleSignal;
        sa.sa_flags = SA_ONSTACK;
        for (std::size_t i = 0; i < sizeof(signalDefs)/sizeof(SignalDefs); ++i) {
            sigaction(signalDefs[i].id, &sa, &oldSigActions[i]);
        }
    }

    void FatalConditionHandler::reset() {
        if( isSet ) {
            // Set signals back to previous values -- hopefully nobody overwrote them in the meantime
            for( std::size_t i = 0; i < sizeof(signalDefs)/sizeof(SignalDefs); ++i ) {
                sigaction(signalDefs[i].id, &oldSigActions[i], nullptr);
            }
            // Return the old stack
            sigaltstack(&oldSigStack, nullptr);
            isSet = false;
        }
    }

    bool FatalConditionHandler::isSet = false;
    struct sigaction FatalConditionHandler::oldSigActions[sizeof(signalDefs)/sizeof(SignalDefs)] = {};
    stack_t FatalConditionHandler::oldSigStack = {};
    char FatalConditionHandler::altStackMem[sigStackSize] = {};


} // namespace Catch

#endif // signals/SEH handling

#if defined(__GNUC__)
#    pragma GCC diagnostic pop
#endif





namespace Catch {
    namespace {

        void listTests(IStreamingReporter& reporter, IConfig const& config) {
            auto const& testSpec = config.testSpec();
            auto matchedTestCases = filterTests(getAllTestCasesSorted(config), testSpec, config);
            reporter.listTests(matchedTestCases, config);
        }

        void listTags(IStreamingReporter& reporter, IConfig const& config) {
            auto const& testSpec = config.testSpec();
            std::vector<TestCaseHandle> matchedTestCases = filterTests(getAllTestCasesSorted(config), testSpec, config);

            std::map<StringRef, TagInfo> tagCounts;
            for (auto const& testCase : matchedTestCases) {
                for (auto const& tagName : testCase.getTestCaseInfo().tags) {
                    auto it = tagCounts.find(tagName.lowerCased);
                    if (it == tagCounts.end())
                        it = tagCounts.insert(std::make_pair(tagName.lowerCased, TagInfo())).first;
                    it->second.add(tagName.original);
                }
            }

            std::vector<TagInfo> infos; infos.reserve(tagCounts.size());
            for (auto& tagc : tagCounts) {
                infos.push_back(std::move(tagc.second));
            }

            reporter.listTags(infos, config);
        }

        void listReporters(IStreamingReporter& reporter, IConfig const& config) {
            std::vector<ReporterDescription> descriptions;

            IReporterRegistry::FactoryMap const& factories = getRegistryHub().getReporterRegistry().getFactories();
            descriptions.reserve(factories.size());
            for (auto const& fac : factories) {
                descriptions.push_back({ fac.first, fac.second->getDescription() });
            }

            reporter.listReporters(descriptions, config);
        }

    } // end anonymous namespace

    void TagInfo::add( StringRef spelling ) {
        ++count;
        spellings.insert( spelling );
    }

    std::string TagInfo::all() const {
        // 2 per tag for brackets '[' and ']'
        size_t size =  spellings.size() * 2;
        for (auto const& spelling : spellings) {
            size += spelling.size();
        }

        std::string out; out.reserve(size);
        for (auto const& spelling : spellings) {
            out += '[';
            out += spelling;
            out += ']';
        }
        return out;
    }

    bool list( IStreamingReporter& reporter, Config const& config ) {
        bool listed = false;
        if (config.listTests()) {
            listed = true;
            listTests(reporter, config);
        }
        if (config.listTags()) {
            listed = true;
            listTags(reporter, config);
        }
        if (config.listReporters()) {
            listed = true;
            listReporters(reporter, config);
        }
        return listed;
    }

} // end namespace Catch



namespace Catch {
    CATCH_INTERNAL_START_WARNINGS_SUPPRESSION
    CATCH_INTERNAL_SUPPRESS_GLOBALS_WARNINGS
    LeakDetector leakDetector;
    CATCH_INTERNAL_STOP_WARNINGS_SUPPRESSION
}

#if defined(CATCH_CONFIG_WCHAR) && defined(CATCH_PLATFORM_WINDOWS) && defined(_UNICODE) && !defined(DO_NOT_USE_WMAIN)
// Standard C/C++ Win32 Unicode wmain entry point
extern "C" int wmain (int argc, wchar_t * argv[], wchar_t * []) {
#else
// Standard C/C++ main entry point
int main (int argc, char * argv[]) {
#endif

    // We want to force the linker not to discard the global variable
    // and its constructor, as it (optionally) registers leak detector
    (void)&Catch::leakDetector;

    return Catch::Session().run( argc, argv );
}



#include <cstdio>
#include <cstring>
#include <sstream>

#if defined(CATCH_CONFIG_NEW_CAPTURE)
    #if defined(_MSC_VER)
    #include <io.h>      //_dup and _dup2
    #define dup _dup
    #define dup2 _dup2
    #define fileno _fileno
    #else
    #include <unistd.h>  // dup and dup2
    #endif
#endif


namespace Catch {

    RedirectedStream::RedirectedStream( std::ostream& originalStream, std::ostream& redirectionStream )
    :   m_originalStream( originalStream ),
        m_redirectionStream( redirectionStream ),
        m_prevBuf( m_originalStream.rdbuf() )
    {
        m_originalStream.rdbuf( m_redirectionStream.rdbuf() );
    }

    RedirectedStream::~RedirectedStream() {
        m_originalStream.rdbuf( m_prevBuf );
    }

    RedirectedStdOut::RedirectedStdOut() : m_cout( Catch::cout(), m_rss.get() ) {}
    auto RedirectedStdOut::str() const -> std::string { return m_rss.str(); }

    RedirectedStdErr::RedirectedStdErr()
    :   m_cerr( Catch::cerr(), m_rss.get() ),
        m_clog( Catch::clog(), m_rss.get() )
    {}
    auto RedirectedStdErr::str() const -> std::string { return m_rss.str(); }

    RedirectedStreams::RedirectedStreams(std::string& redirectedCout, std::string& redirectedCerr)
    :   m_redirectedCout(redirectedCout),
        m_redirectedCerr(redirectedCerr)
    {}

    RedirectedStreams::~RedirectedStreams() {
        m_redirectedCout += m_redirectedStdOut.str();
        m_redirectedCerr += m_redirectedStdErr.str();
    }

#if defined(CATCH_CONFIG_NEW_CAPTURE)

#if defined(_MSC_VER)
    TempFile::TempFile() {
        if (tmpnam_s(m_buffer)) {
            CATCH_RUNTIME_ERROR("Could not get a temp filename");
        }
        if (fopen_s(&m_file, m_buffer, "w+")) {
            char buffer[100];
            if (strerror_s(buffer, errno)) {
                CATCH_RUNTIME_ERROR("Could not translate errno to a string");
            }
            CATCH_RUNTIME_ERROR("Could not open the temp file: '" << m_buffer << "' because: " << buffer);
        }
    }
#else
    TempFile::TempFile() {
        m_file = std::tmpfile();
        if (!m_file) {
            CATCH_RUNTIME_ERROR("Could not create a temp file.");
        }
    }

#endif

    TempFile::~TempFile() {
         // TBD: What to do about errors here?
         std::fclose(m_file);
         // We manually create the file on Windows only, on Linux
         // it will be autodeleted
#if defined(_MSC_VER)
         std::remove(m_buffer);
#endif
    }


    FILE* TempFile::getFile() {
        return m_file;
    }

    std::string TempFile::getContents() {
        std::stringstream sstr;
        char buffer[100] = {};
        std::rewind(m_file);
        while (std::fgets(buffer, sizeof(buffer), m_file)) {
            sstr << buffer;
        }
        return sstr.str();
    }

    OutputRedirect::OutputRedirect(std::string& stdout_dest, std::string& stderr_dest) :
        m_originalStdout(dup(1)),
        m_originalStderr(dup(2)),
        m_stdoutDest(stdout_dest),
        m_stderrDest(stderr_dest) {
        dup2(fileno(m_stdoutFile.getFile()), 1);
        dup2(fileno(m_stderrFile.getFile()), 2);
    }

    OutputRedirect::~OutputRedirect() {
        Catch::cout() << std::flush;
        fflush(stdout);
        // Since we support overriding these streams, we flush cerr
        // even though std::cerr is unbuffered
        Catch::cerr() << std::flush;
        Catch::clog() << std::flush;
        fflush(stderr);

        dup2(m_originalStdout, 1);
        dup2(m_originalStderr, 2);

        m_stdoutDest += m_stdoutFile.getContents();
        m_stderrDest += m_stderrFile.getContents();
    }

#endif // CATCH_CONFIG_NEW_CAPTURE

} // namespace Catch

#if defined(CATCH_CONFIG_NEW_CAPTURE)
    #if defined(_MSC_VER)
    #undef dup
    #undef dup2
    #undef fileno
    #endif
#endif



namespace Catch {

namespace {

#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable:4146) // we negate uint32 during the rotate
#endif
        // Safe rotr implementation thanks to John Regehr
        uint32_t rotate_right(uint32_t val, uint32_t count) {
            const uint32_t mask = 31;
            count &= mask;
            return (val >> count) | (val << (-count & mask));
        }

#if defined(_MSC_VER)
#pragma warning(pop)
#endif

}


    SimplePcg32::SimplePcg32(result_type seed_) {
        seed(seed_);
    }


    void SimplePcg32::seed(result_type seed_) {
        m_state = 0;
        (*this)();
        m_state += seed_;
        (*this)();
    }

    void SimplePcg32::discard(uint64_t skip) {
        // We could implement this to run in O(log n) steps, but this
        // should suffice for our use case.
        for (uint64_t s = 0; s < skip; ++s) {
            static_cast<void>((*this)());
        }
    }

    SimplePcg32::result_type SimplePcg32::operator()() {
        // prepare the output value
        const uint32_t xorshifted = static_cast<uint32_t>(((m_state >> 18u) ^ m_state) >> 27u);
        const auto output = rotate_right(xorshifted, m_state >> 59u);

        // advance state
        m_state = m_state * 6364136223846793005ULL + s_inc;

        return output;
    }

    bool operator==(SimplePcg32 const& lhs, SimplePcg32 const& rhs) {
        return lhs.m_state == rhs.m_state;
    }

    bool operator!=(SimplePcg32 const& lhs, SimplePcg32 const& rhs) {
        return lhs.m_state != rhs.m_state;
    }
}




namespace Catch {

    ReporterRegistry::ReporterRegistry() {
        // Because it is impossible to move out of initializer list,
        // we have to add the elements manually
        m_factories["automake"] = Detail::make_unique<ReporterFactory<AutomakeReporter>>();
        m_factories["compact"] = Detail::make_unique<ReporterFactory<CompactReporter>>();
        m_factories["console"] = Detail::make_unique<ReporterFactory<ConsoleReporter>>();
        m_factories["junit"] = Detail::make_unique<ReporterFactory<JunitReporter>>();
        m_factories["sonarqube"] = Detail::make_unique<ReporterFactory<SonarQubeReporter>>();
        m_factories["tap"] = Detail::make_unique<ReporterFactory<TAPReporter>>();
        m_factories["teamcity"] = Detail::make_unique<ReporterFactory<TeamCityReporter>>();
        m_factories["xml"] = Detail::make_unique<ReporterFactory<XmlReporter>>();
    }

    ReporterRegistry::~ReporterRegistry() = default;


    IStreamingReporterPtr ReporterRegistry::create( std::string const& name, IConfig const* config ) const {
        auto it =  m_factories.find( name );
        if( it == m_factories.end() )
            return nullptr;
        return it->second->create( ReporterConfig( config ) );
    }

    void ReporterRegistry::registerReporter( std::string const& name, IReporterFactoryPtr factory ) {
        m_factories.emplace(name, std::move(factory));
    }
    void ReporterRegistry::registerListener( IReporterFactoryPtr factory ) {
        m_listeners.push_back( std::move(factory) );
    }

    IReporterRegistry::FactoryMap const& ReporterRegistry::getFactories() const {
        return m_factories;
    }
    IReporterRegistry::Listeners const& ReporterRegistry::getListeners() const {
        return m_listeners;
    }

}



namespace Catch {

    bool isOk( ResultWas::OfType resultType ) {
        return ( resultType & ResultWas::FailureBit ) == 0;
    }
    bool isJustInfo( int flags ) {
        return flags == ResultWas::Info;
    }

    ResultDisposition::Flags operator | ( ResultDisposition::Flags lhs, ResultDisposition::Flags rhs ) {
        return static_cast<ResultDisposition::Flags>( static_cast<int>( lhs ) | static_cast<int>( rhs ) );
    }

    bool shouldContinueOnFailure( int flags )    { return ( flags & ResultDisposition::ContinueOnFailure ) != 0; }
    bool shouldSuppressFailure( int flags )      { return ( flags & ResultDisposition::SuppressFail ) != 0; }

} // end namespace Catch




#include <cassert>
#include <algorithm>

namespace Catch {

    namespace Generators {
        struct GeneratorTracker : TestCaseTracking::TrackerBase, IGeneratorTracker {
            GeneratorBasePtr m_generator;

            GeneratorTracker( TestCaseTracking::NameAndLocation const& nameAndLocation, TrackerContext& ctx, ITracker* parent )
            :   TrackerBase( nameAndLocation, ctx, parent )
            {}
            ~GeneratorTracker();

            static GeneratorTracker& acquire( TrackerContext& ctx, TestCaseTracking::NameAndLocation const& nameAndLocation ) {
                std::shared_ptr<GeneratorTracker> tracker;

                ITracker& currentTracker = ctx.currentTracker();
                // Under specific circumstances, the generator we want
                // to acquire is also the current tracker. If this is
                // the case, we have to avoid looking through current
                // tracker's children, and instead return the current
                // tracker.
                // A case where this check is important is e.g.
                //     for (int i = 0; i < 5; ++i) {
                //         int n = GENERATE(1, 2);
                //     }
                //
                // without it, the code above creates 5 nested generators.
                if (currentTracker.nameAndLocation() == nameAndLocation) {
                    auto thisTracker = currentTracker.parent().findChild(nameAndLocation);
                    assert(thisTracker);
                    assert(thisTracker->isGeneratorTracker());
                    tracker = std::static_pointer_cast<GeneratorTracker>(thisTracker);
                } else if ( TestCaseTracking::ITrackerPtr childTracker = currentTracker.findChild( nameAndLocation ) ) {
                    assert( childTracker );
                    assert( childTracker->isGeneratorTracker() );
                    tracker = std::static_pointer_cast<GeneratorTracker>( childTracker );
                } else {
                    tracker = std::make_shared<GeneratorTracker>( nameAndLocation, ctx, &currentTracker );
                    currentTracker.addChild( tracker );
                }

                if( !tracker->isComplete() ) {
                    tracker->open();
                }

                return *tracker;
            }

            // TrackerBase interface
            bool isGeneratorTracker() const override { return true; }
            auto hasGenerator() const -> bool override {
                return !!m_generator;
            }
            void close() override {
                TrackerBase::close();
                // If a generator has a child (it is followed by a section)
                // and none of its children have started, then we must wait
                // until later to start consuming its values.
                // This catches cases where `GENERATE` is placed between two
                // `SECTION`s.
                // **The check for m_children.empty cannot be removed**.
                // doing so would break `GENERATE` _not_ followed by `SECTION`s.
                const bool should_wait_for_child =
                    !m_children.empty() &&
                    std::find_if( m_children.begin(),
                                  m_children.end(),
                                  []( TestCaseTracking::ITrackerPtr tracker ) {
                                      return tracker->hasStarted();
                                  } ) == m_children.end();

                // This check is a bit tricky, because m_generator->next()
                // has a side-effect, where it consumes generator's current
                // value, but we do not want to invoke the side-effect if
                // this generator is still waiting for any child to start.
                if ( should_wait_for_child ||
                     ( m_runState == CompletedSuccessfully &&
                       m_generator->next() ) ) {
                    m_children.clear();
                    m_runState = Executing;
                }
            }

            // IGeneratorTracker interface
            auto getGenerator() const -> GeneratorBasePtr const& override {
                return m_generator;
            }
            void setGenerator( GeneratorBasePtr&& generator ) override {
                m_generator = std::move( generator );
            }
        };
        GeneratorTracker::~GeneratorTracker() {}
    }

    RunContext::RunContext(IConfig const* _config, IStreamingReporterPtr&& reporter)
    :   m_runInfo(_config->name()),
        m_context(getCurrentMutableContext()),
        m_config(_config),
        m_reporter(std::move(reporter)),
        m_lastAssertionInfo{ StringRef(), SourceLineInfo("",0), StringRef(), ResultDisposition::Normal },
        m_includeSuccessfulResults( m_config->includeSuccessfulResults() || m_reporter->getPreferences().shouldReportAllAssertions )
    {
        m_context.setRunner(this);
        m_context.setResultCapture(this);
        m_reporter->testRunStarting(m_runInfo);
    }

    RunContext::~RunContext() {
        m_reporter->testRunEnded(TestRunStats(m_runInfo, m_totals, aborting()));
    }

    void RunContext::testGroupStarting(std::string const& testSpec, std::size_t groupIndex, std::size_t groupsCount) {
        m_reporter->testGroupStarting(GroupInfo(testSpec, groupIndex, groupsCount));
    }

    void RunContext::testGroupEnded(std::string const& testSpec, Totals const& totals, std::size_t groupIndex, std::size_t groupsCount) {
        m_reporter->testGroupEnded(TestGroupStats(GroupInfo(testSpec, groupIndex, groupsCount), totals, aborting()));
    }

    Totals RunContext::runTest(TestCaseHandle const& testCase) {
        Totals prevTotals = m_totals;

        std::string redirectedCout;
        std::string redirectedCerr;

        auto const& testInfo = testCase.getTestCaseInfo();

        m_reporter->testCaseStarting(testInfo);

        m_activeTestCase = &testCase;


        ITracker& rootTracker = m_trackerContext.startRun();
        assert(rootTracker.isSectionTracker());
        static_cast<SectionTracker&>(rootTracker).addInitialFilters(m_config->getSectionsToRun());
        do {
            m_trackerContext.startCycle();
            m_testCaseTracker = &SectionTracker::acquire(m_trackerContext, TestCaseTracking::NameAndLocation(testInfo.name, testInfo.lineInfo));
            runCurrentTest(redirectedCout, redirectedCerr);
        } while (!m_testCaseTracker->isSuccessfullyCompleted() && !aborting());

        Totals deltaTotals = m_totals.delta(prevTotals);
        if (testInfo.expectedToFail() && deltaTotals.testCases.passed > 0) {
            deltaTotals.assertions.failed++;
            deltaTotals.testCases.passed--;
            deltaTotals.testCases.failed++;
        }
        m_totals.testCases += deltaTotals.testCases;
        m_reporter->testCaseEnded(TestCaseStats(testInfo,
                                  deltaTotals,
                                  redirectedCout,
                                  redirectedCerr,
                                  aborting()));

        m_activeTestCase = nullptr;
        m_testCaseTracker = nullptr;

        return deltaTotals;
    }


    void RunContext::assertionEnded(AssertionResult const & result) {
        if (result.getResultType() == ResultWas::Ok) {
            m_totals.assertions.passed++;
            m_lastAssertionPassed = true;
        } else if (!result.isOk()) {
            m_lastAssertionPassed = false;
            if( m_activeTestCase->getTestCaseInfo().okToFail() )
                m_totals.assertions.failedButOk++;
            else
                m_totals.assertions.failed++;
        }
        else {
            m_lastAssertionPassed = true;
        }

        // We have no use for the return value (whether messages should be cleared), because messages were made scoped
        // and should be let to clear themselves out.
        static_cast<void>(m_reporter->assertionEnded(AssertionStats(result, m_messages, m_totals)));

        if (result.getResultType() != ResultWas::Warning)
            m_messageScopes.clear();

        // Reset working state
        resetAssertionInfo();
        m_lastResult = result;
    }
    void RunContext::resetAssertionInfo() {
        m_lastAssertionInfo.macroName = StringRef();
        m_lastAssertionInfo.capturedExpression = "{Unknown expression after the reported line}"_sr;
    }

    bool RunContext::sectionStarted(SectionInfo const & sectionInfo, Counts & assertions) {
        ITracker& sectionTracker = SectionTracker::acquire(m_trackerContext, TestCaseTracking::NameAndLocation(sectionInfo.name, sectionInfo.lineInfo));
        if (!sectionTracker.isOpen())
            return false;
        m_activeSections.push_back(&sectionTracker);

        m_lastAssertionInfo.lineInfo = sectionInfo.lineInfo;

        m_reporter->sectionStarting(sectionInfo);

        assertions = m_totals.assertions;

        return true;
    }
    auto RunContext::acquireGeneratorTracker( StringRef generatorName, SourceLineInfo const& lineInfo ) -> IGeneratorTracker& {
        using namespace Generators;
        GeneratorTracker& tracker = GeneratorTracker::acquire(m_trackerContext,
                                                              TestCaseTracking::NameAndLocation( static_cast<std::string>(generatorName), lineInfo ) );
        m_lastAssertionInfo.lineInfo = lineInfo;
        return tracker;
    }

    bool RunContext::testForMissingAssertions(Counts& assertions) {
        if (assertions.total() != 0)
            return false;
        if (!m_config->warnAboutMissingAssertions())
            return false;
        if (m_trackerContext.currentTracker().hasChildren())
            return false;
        m_totals.assertions.failed++;
        assertions.failed++;
        return true;
    }

    void RunContext::sectionEnded(SectionEndInfo const & endInfo) {
        Counts assertions = m_totals.assertions - endInfo.prevAssertions;
        bool missingAssertions = testForMissingAssertions(assertions);

        if (!m_activeSections.empty()) {
            m_activeSections.back()->close();
            m_activeSections.pop_back();
        }

        m_reporter->sectionEnded(SectionStats(endInfo.sectionInfo, assertions, endInfo.durationInSeconds, missingAssertions));
        m_messages.clear();
        m_messageScopes.clear();
    }

    void RunContext::sectionEndedEarly(SectionEndInfo const & endInfo) {
        if (m_unfinishedSections.empty())
            m_activeSections.back()->fail();
        else
            m_activeSections.back()->close();
        m_activeSections.pop_back();

        m_unfinishedSections.push_back(endInfo);
    }

    void RunContext::benchmarkPreparing(std::string const& name) {
        m_reporter->benchmarkPreparing(name);
    }
    void RunContext::benchmarkStarting( BenchmarkInfo const& info ) {
        m_reporter->benchmarkStarting( info );
    }
    void RunContext::benchmarkEnded( BenchmarkStats<> const& stats ) {
        m_reporter->benchmarkEnded( stats );
    }
    void RunContext::benchmarkFailed(std::string const & error) {
        m_reporter->benchmarkFailed(error);
    }

    void RunContext::pushScopedMessage(MessageInfo const & message) {
        m_messages.push_back(message);
    }

    void RunContext::popScopedMessage(MessageInfo const & message) {
        m_messages.erase(std::remove(m_messages.begin(), m_messages.end(), message), m_messages.end());
    }

    void RunContext::emplaceUnscopedMessage( MessageBuilder const& builder ) {
        m_messageScopes.emplace_back( builder );
    }

    std::string RunContext::getCurrentTestName() const {
        return m_activeTestCase
            ? m_activeTestCase->getTestCaseInfo().name
            : std::string();
    }

    const AssertionResult * RunContext::getLastResult() const {
        return &(*m_lastResult);
    }

    void RunContext::exceptionEarlyReported() {
        m_shouldReportUnexpected = false;
    }

    void RunContext::handleFatalErrorCondition( StringRef message ) {
        // First notify reporter that bad things happened
        m_reporter->fatalErrorEncountered(message);

        // Don't rebuild the result -- the stringification itself can cause more fatal errors
        // Instead, fake a result data.
        AssertionResultData tempResult( ResultWas::FatalErrorCondition, { false } );
        tempResult.message = static_cast<std::string>(message);
        AssertionResult result(m_lastAssertionInfo, tempResult);

        assertionEnded(result);

        handleUnfinishedSections();

        // Recreate section for test case (as we will lose the one that was in scope)
        auto const& testCaseInfo = m_activeTestCase->getTestCaseInfo();
        SectionInfo testCaseSection(testCaseInfo.lineInfo, testCaseInfo.name);

        Counts assertions;
        assertions.failed = 1;
        SectionStats testCaseSectionStats(testCaseSection, assertions, 0, false);
        m_reporter->sectionEnded(testCaseSectionStats);

        auto const& testInfo = m_activeTestCase->getTestCaseInfo();

        Totals deltaTotals;
        deltaTotals.testCases.failed = 1;
        deltaTotals.assertions.failed = 1;
        m_reporter->testCaseEnded(TestCaseStats(testInfo,
                                  deltaTotals,
                                  std::string(),
                                  std::string(),
                                  false));
        m_totals.testCases.failed++;
        testGroupEnded(std::string(), m_totals, 1, 1);
        m_reporter->testRunEnded(TestRunStats(m_runInfo, m_totals, false));
    }

    bool RunContext::lastAssertionPassed() {
         return m_lastAssertionPassed;
    }

    void RunContext::assertionPassed() {
        m_lastAssertionPassed = true;
        ++m_totals.assertions.passed;
        resetAssertionInfo();
        m_messageScopes.clear();
    }

    bool RunContext::aborting() const {
        return m_totals.assertions.failed >= static_cast<std::size_t>(m_config->abortAfter());
    }

    void RunContext::runCurrentTest(std::string & redirectedCout, std::string & redirectedCerr) {
        auto const& testCaseInfo = m_activeTestCase->getTestCaseInfo();
        SectionInfo testCaseSection(testCaseInfo.lineInfo, testCaseInfo.name);
        m_reporter->sectionStarting(testCaseSection);
        Counts prevAssertions = m_totals.assertions;
        double duration = 0;
        m_shouldReportUnexpected = true;
        m_lastAssertionInfo = { "TEST_CASE"_sr, testCaseInfo.lineInfo, StringRef(), ResultDisposition::Normal };

        seedRng(*m_config);

        Timer timer;
        CATCH_TRY {
            if (m_reporter->getPreferences().shouldRedirectStdOut) {
#if !defined(CATCH_CONFIG_EXPERIMENTAL_REDIRECT)
                RedirectedStreams redirectedStreams(redirectedCout, redirectedCerr);

                timer.start();
                invokeActiveTestCase();
#else
                OutputRedirect r(redirectedCout, redirectedCerr);
                timer.start();
                invokeActiveTestCase();
#endif
            } else {
                timer.start();
                invokeActiveTestCase();
            }
            duration = timer.getElapsedSeconds();
        } CATCH_CATCH_ANON (TestFailureException&) {
            // This just means the test was aborted due to failure
        } CATCH_CATCH_ALL {
            // Under CATCH_CONFIG_FAST_COMPILE, unexpected exceptions under REQUIRE assertions
            // are reported without translation at the point of origin.
            if( m_shouldReportUnexpected ) {
                AssertionReaction dummyReaction;
                handleUnexpectedInflightException( m_lastAssertionInfo, translateActiveException(), dummyReaction );
            }
        }
        Counts assertions = m_totals.assertions - prevAssertions;
        bool missingAssertions = testForMissingAssertions(assertions);

        m_testCaseTracker->close();
        handleUnfinishedSections();
        m_messages.clear();
        m_messageScopes.clear();

        SectionStats testCaseSectionStats(testCaseSection, assertions, duration, missingAssertions);
        m_reporter->sectionEnded(testCaseSectionStats);
    }

    void RunContext::invokeActiveTestCase() {
        // We need to register a handler for signals/structured exceptions
        // before running the tests themselves, or the binary can crash
        // without failed test being reported.
        FatalConditionHandler _;
        m_activeTestCase->invoke();
    }

    void RunContext::handleUnfinishedSections() {
        // If sections ended prematurely due to an exception we stored their
        // infos here so we can tear them down outside the unwind process.
        for (auto it = m_unfinishedSections.rbegin(),
             itEnd = m_unfinishedSections.rend();
             it != itEnd;
             ++it)
            sectionEnded(*it);
        m_unfinishedSections.clear();
    }

    void RunContext::handleExpr(
        AssertionInfo const& info,
        ITransientExpression const& expr,
        AssertionReaction& reaction
    ) {
        m_reporter->assertionStarting( info );

        bool negated = isFalseTest( info.resultDisposition );
        bool result = expr.getResult() != negated;

        if( result ) {
            if (!m_includeSuccessfulResults) {
                assertionPassed();
            }
            else {
                reportExpr(info, ResultWas::Ok, &expr, negated);
            }
        }
        else {
            reportExpr(info, ResultWas::ExpressionFailed, &expr, negated );
            populateReaction( reaction );
        }
    }
    void RunContext::reportExpr(
            AssertionInfo const &info,
            ResultWas::OfType resultType,
            ITransientExpression const *expr,
            bool negated ) {

        m_lastAssertionInfo = info;
        AssertionResultData data( resultType, LazyExpression( negated ) );

        AssertionResult assertionResult{ info, data };
        assertionResult.m_resultData.lazyExpression.m_transientExpression = expr;

        assertionEnded( assertionResult );
    }

    void RunContext::handleMessage(
            AssertionInfo const& info,
            ResultWas::OfType resultType,
            StringRef const& message,
            AssertionReaction& reaction
    ) {
        m_reporter->assertionStarting( info );

        m_lastAssertionInfo = info;

        AssertionResultData data( resultType, LazyExpression( false ) );
        data.message = static_cast<std::string>(message);
        AssertionResult assertionResult{ m_lastAssertionInfo, data };
        assertionEnded( assertionResult );
        if( !assertionResult.isOk() )
            populateReaction( reaction );
    }
    void RunContext::handleUnexpectedExceptionNotThrown(
            AssertionInfo const& info,
            AssertionReaction& reaction
    ) {
        handleNonExpr(info, Catch::ResultWas::DidntThrowException, reaction);
    }

    void RunContext::handleUnexpectedInflightException(
            AssertionInfo const& info,
            std::string const& message,
            AssertionReaction& reaction
    ) {
        m_lastAssertionInfo = info;

        AssertionResultData data( ResultWas::ThrewException, LazyExpression( false ) );
        data.message = message;
        AssertionResult assertionResult{ info, data };
        assertionEnded( assertionResult );
        populateReaction( reaction );
    }

    void RunContext::populateReaction( AssertionReaction& reaction ) {
        reaction.shouldDebugBreak = m_config->shouldDebugBreak();
        reaction.shouldThrow = aborting() || (m_lastAssertionInfo.resultDisposition & ResultDisposition::Normal);
    }

    void RunContext::handleIncomplete(
            AssertionInfo const& info
    ) {
        m_lastAssertionInfo = info;

        AssertionResultData data( ResultWas::ThrewException, LazyExpression( false ) );
        data.message = "Exception translation was disabled by CATCH_CONFIG_FAST_COMPILE";
        AssertionResult assertionResult{ info, data };
        assertionEnded( assertionResult );
    }
    void RunContext::handleNonExpr(
            AssertionInfo const &info,
            ResultWas::OfType resultType,
            AssertionReaction &reaction
    ) {
        m_lastAssertionInfo = info;

        AssertionResultData data( resultType, LazyExpression( false ) );
        AssertionResult assertionResult{ info, data };
        assertionEnded( assertionResult );

        if( !assertionResult.isOk() )
            populateReaction( reaction );
    }


    IResultCapture& getResultCapture() {
        if (auto* capture = getCurrentContext().getResultCapture())
            return *capture;
        else
            CATCH_INTERNAL_ERROR("No result capture instance");
    }

    void seedRng(IConfig const& config) {
        if (config.rngSeed() != 0) {
            std::srand(config.rngSeed());
            rng().seed(config.rngSeed());
        }
    }

    unsigned int rngSeed() {
        return getCurrentContext().getConfig()->rngSeed();
    }

}



#include <utility>

namespace Catch {

    Section::Section( SectionInfo&& info ):
        m_info( std::move( info ) ),
        m_sectionIncluded(
            getResultCapture().sectionStarted( m_info, m_assertions ) ) {
        // Non-"included" sections will not use the timing information
        // anyway, so don't bother with the potential syscall.
        if (m_sectionIncluded) {
            m_timer.start();
        }
    }

    Section::~Section() {
        if( m_sectionIncluded ) {
            SectionEndInfo endInfo{ m_info, m_assertions, m_timer.getElapsedSeconds() };
            if( uncaught_exceptions() )
                getResultCapture().sectionEndedEarly( endInfo );
            else
                getResultCapture().sectionEnded( endInfo );
        }
    }

    // This indicates whether the section should be executed or not
    Section::operator bool() const {
        return m_sectionIncluded;
    }


} // end namespace Catch



#include <vector>

namespace Catch {

    namespace {
        static auto getSingletons() -> std::vector<ISingleton*>*& {
            static std::vector<ISingleton*>* g_singletons = nullptr;
            if( !g_singletons )
                g_singletons = new std::vector<ISingleton*>();
            return g_singletons;
        }
    }

    ISingleton::~ISingleton() {}

    void addSingleton(ISingleton* singleton ) {
        getSingletons()->push_back( singleton );
    }
    void cleanupSingletons() {
        auto& singletons = getSingletons();
        for( auto singleton : *singletons )
            delete singleton;
        delete singletons;
        singletons = nullptr;
    }

} // namespace Catch



#include <cstdio>
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>

namespace Catch {

    Catch::IStream::~IStream() = default;

namespace Detail {
    namespace {
        template<typename WriterF, std::size_t bufferSize=256>
        class StreamBufImpl : public std::streambuf {
            char data[bufferSize];
            WriterF m_writer;

        public:
            StreamBufImpl() {
                setp( data, data + sizeof(data) );
            }

            ~StreamBufImpl() noexcept {
                StreamBufImpl::sync();
            }

        private:
            int overflow( int c ) override {
                sync();

                if( c != EOF ) {
                    if( pbase() == epptr() )
                        m_writer( std::string( 1, static_cast<char>( c ) ) );
                    else
                        sputc( static_cast<char>( c ) );
                }
                return 0;
            }

            int sync() override {
                if( pbase() != pptr() ) {
                    m_writer( std::string( pbase(), static_cast<std::string::size_type>( pptr() - pbase() ) ) );
                    setp( pbase(), epptr() );
                }
                return 0;
            }
        };

        ///////////////////////////////////////////////////////////////////////////

        struct OutputDebugWriter {

            void operator()( std::string const&str ) {
                writeToDebugConsole( str );
            }
        };

        ///////////////////////////////////////////////////////////////////////////

        class FileStream : public IStream {
            mutable std::ofstream m_ofs;
        public:
            FileStream( StringRef filename ) {
                m_ofs.open( filename.c_str() );
                CATCH_ENFORCE( !m_ofs.fail(), "Unable to open file: '" << filename << "'" );
            }
            ~FileStream() override = default;
        public: // IStream
            std::ostream& stream() const override {
                return m_ofs;
            }
        };

        ///////////////////////////////////////////////////////////////////////////

        class CoutStream : public IStream {
            mutable std::ostream m_os;
        public:
            // Store the streambuf from cout up-front because
            // cout may get redirected when running tests
            CoutStream() : m_os( Catch::cout().rdbuf() ) {}
            ~CoutStream() override = default;

        public: // IStream
            std::ostream& stream() const override { return m_os; }
        };

        ///////////////////////////////////////////////////////////////////////////

        class DebugOutStream : public IStream {
            Detail::unique_ptr<StreamBufImpl<OutputDebugWriter>> m_streamBuf;
            mutable std::ostream m_os;
        public:
            DebugOutStream()
            :   m_streamBuf( Detail::make_unique<StreamBufImpl<OutputDebugWriter>>() ),
                m_os( m_streamBuf.get() )
            {}

            ~DebugOutStream() override = default;

        public: // IStream
            std::ostream& stream() const override { return m_os; }
        };

    } // unnamed namespace
} // namespace Detail

    ///////////////////////////////////////////////////////////////////////////

    auto makeStream( StringRef const &filename ) -> IStream const* {
        if( filename.empty() )
            return new Detail::CoutStream();
        else if( filename[0] == '%' ) {
            if( filename == "%debug" )
                return new Detail::DebugOutStream();
            else
                CATCH_ERROR( "Unrecognised stream: '" << filename << "'" );
        }
        else
            return new Detail::FileStream( filename );
    }


    // This class encapsulates the idea of a pool of ostringstreams that can be reused.
    struct StringStreams {
        std::vector<Detail::unique_ptr<std::ostringstream>> m_streams;
        std::vector<std::size_t> m_unused;
        std::ostringstream m_referenceStream; // Used for copy state/ flags from

        auto add() -> std::size_t {
            if( m_unused.empty() ) {
                m_streams.push_back( Detail::unique_ptr<std::ostringstream>( new std::ostringstream ) );
                return m_streams.size()-1;
            }
            else {
                auto index = m_unused.back();
                m_unused.pop_back();
                return index;
            }
        }

        void release( std::size_t index ) {
            m_streams[index]->copyfmt( m_referenceStream ); // Restore initial flags and other state
            m_unused.push_back(index);
        }
    };

    ReusableStringStream::ReusableStringStream()
    :   m_index( Singleton<StringStreams>::getMutable().add() ),
        m_oss( Singleton<StringStreams>::getMutable().m_streams[m_index].get() )
    {}

    ReusableStringStream::~ReusableStringStream() {
        static_cast<std::ostringstream*>( m_oss )->str("");
        m_oss->clear();
        Singleton<StringStreams>::getMutable().release( m_index );
    }

    std::string ReusableStringStream::str() const {
        return static_cast<std::ostringstream*>( m_oss )->str();
    }

    void ReusableStringStream::str( std::string const& str ) {
        static_cast<std::ostringstream*>( m_oss )->str( str );
    }


    ///////////////////////////////////////////////////////////////////////////


#ifndef CATCH_CONFIG_NOSTDOUT // If you #define this you must implement these functions
    std::ostream& cout() { return std::cout; }
    std::ostream& cerr() { return std::cerr; }
    std::ostream& clog() { return std::clog; }
#endif
}



#include <algorithm>
#include <ostream>
#include <cstring>
#include <cctype>
#include <vector>

namespace Catch {

    namespace {
        char toLowerCh(char c) {
            return static_cast<char>( std::tolower( static_cast<unsigned char>(c) ) );
        }
    }

    bool startsWith( std::string const& s, std::string const& prefix ) {
        return s.size() >= prefix.size() && std::equal(prefix.begin(), prefix.end(), s.begin());
    }
    bool startsWith( std::string const& s, char prefix ) {
        return !s.empty() && s[0] == prefix;
    }
    bool endsWith( std::string const& s, std::string const& suffix ) {
        return s.size() >= suffix.size() && std::equal(suffix.rbegin(), suffix.rend(), s.rbegin());
    }
    bool endsWith( std::string const& s, char suffix ) {
        return !s.empty() && s[s.size()-1] == suffix;
    }
    bool contains( std::string const& s, std::string const& infix ) {
        return s.find( infix ) != std::string::npos;
    }
    void toLowerInPlace( std::string& s ) {
        std::transform( s.begin(), s.end(), s.begin(), toLowerCh );
    }
    std::string toLower( std::string const& s ) {
        std::string lc = s;
        toLowerInPlace( lc );
        return lc;
    }
    std::string trim( std::string const& str ) {
        static char const* whitespaceChars = "\n\r\t ";
        std::string::size_type start = str.find_first_not_of( whitespaceChars );
        std::string::size_type end = str.find_last_not_of( whitespaceChars );

        return start != std::string::npos ? str.substr( start, 1+end-start ) : std::string();
    }

    StringRef trim(StringRef ref) {
        const auto is_ws = [](char c) {
            return c == ' ' || c == '\t' || c == '\n' || c == '\r';
        };
        size_t real_begin = 0;
        while (real_begin < ref.size() && is_ws(ref[real_begin])) { ++real_begin; }
        size_t real_end = ref.size();
        while (real_end > real_begin && is_ws(ref[real_end - 1])) { --real_end; }

        return ref.substr(real_begin, real_end - real_begin);
    }

    bool replaceInPlace( std::string& str, std::string const& replaceThis, std::string const& withThis ) {
        bool replaced = false;
        std::size_t i = str.find( replaceThis );
        while( i != std::string::npos ) {
            replaced = true;
            str = str.substr( 0, i ) + withThis + str.substr( i+replaceThis.size() );
            if( i < str.size()-withThis.size() )
                i = str.find( replaceThis, i+withThis.size() );
            else
                i = std::string::npos;
        }
        return replaced;
    }

    std::vector<StringRef> splitStringRef( StringRef str, char delimiter ) {
        std::vector<StringRef> subStrings;
        std::size_t start = 0;
        for(std::size_t pos = 0; pos < str.size(); ++pos ) {
            if( str[pos] == delimiter ) {
                if( pos - start > 1 )
                    subStrings.push_back( str.substr( start, pos-start ) );
                start = pos+1;
            }
        }
        if( start < str.size() )
            subStrings.push_back( str.substr( start, str.size()-start ) );
        return subStrings;
    }

    pluralise::pluralise( std::size_t count, std::string const& label )
    :   m_count( count ),
        m_label( label )
    {}

    std::ostream& operator << ( std::ostream& os, pluralise const& pluraliser ) {
        os << pluraliser.m_count << ' ' << pluraliser.m_label;
        if( pluraliser.m_count != 1 )
            os << 's';
        return os;
    }

}



#include <algorithm>
#include <ostream>
#include <cstring>
#include <cstdint>

namespace Catch {
    StringRef::StringRef( char const* rawChars ) noexcept
    : StringRef( rawChars, static_cast<StringRef::size_type>(std::strlen(rawChars) ) )
    {}

    auto StringRef::c_str() const -> char const* {
        CATCH_ENFORCE(isNullTerminated(), "Called StringRef::c_str() on a non-null-terminated instance");
        return m_start;
    }

    auto StringRef::operator == ( StringRef const& other ) const noexcept -> bool {
        return m_size == other.m_size
            && (std::memcmp( m_start, other.m_start, m_size ) == 0);
    }

    bool StringRef::operator<(StringRef const& rhs) const noexcept {
        if (m_size < rhs.m_size) {
            return strncmp(m_start, rhs.m_start, m_size) <= 0;
        }
        return strncmp(m_start, rhs.m_start, rhs.m_size) < 0;
    }

    auto operator << ( std::ostream& os, StringRef const& str ) -> std::ostream& {
        return os.write(str.data(), str.size());
    }

    std::string operator+(StringRef lhs, StringRef rhs) {
        std::string ret;
        ret.reserve(lhs.size() + rhs.size());
        ret += lhs;
        ret += rhs;
        return ret;
    }

    auto operator+=( std::string& lhs, StringRef const& rhs ) -> std::string& {
        lhs.append(rhs.data(), rhs.size());
        return lhs;
    }

} // namespace Catch



namespace Catch {

    TagAliasRegistry::~TagAliasRegistry() {}

    TagAlias const* TagAliasRegistry::find( std::string const& alias ) const {
        auto it = m_registry.find( alias );
        if( it != m_registry.end() )
            return &(it->second);
        else
            return nullptr;
    }

    std::string TagAliasRegistry::expandAliases( std::string const& unexpandedTestSpec ) const {
        std::string expandedTestSpec = unexpandedTestSpec;
        for( auto const& registryKvp : m_registry ) {
            std::size_t pos = expandedTestSpec.find( registryKvp.first );
            if( pos != std::string::npos ) {
                expandedTestSpec =  expandedTestSpec.substr( 0, pos ) +
                                    registryKvp.second.tag +
                                    expandedTestSpec.substr( pos + registryKvp.first.size() );
            }
        }
        return expandedTestSpec;
    }

    void TagAliasRegistry::add( std::string const& alias, std::string const& tag, SourceLineInfo const& lineInfo ) {
        CATCH_ENFORCE( startsWith(alias, "[@") && endsWith(alias, ']'),
                      "error: tag alias, '" << alias << "' is not of the form [@alias name].\n" << lineInfo );

        CATCH_ENFORCE( m_registry.insert(std::make_pair(alias, TagAlias(tag, lineInfo))).second,
                      "error: tag alias, '" << alias << "' already registered.\n"
                      << "\tFirst seen at: " << find(alias)->lineInfo << "\n"
                      << "\tRedefined at: " << lineInfo );
    }

    ITagAliasRegistry::~ITagAliasRegistry() {}

    ITagAliasRegistry const& ITagAliasRegistry::get() {
        return getRegistryHub().getTagAliasRegistry();
    }

} // end namespace Catch




#include <algorithm>
#include <set>

namespace Catch {

namespace {
    struct HashTest {
        explicit HashTest(SimplePcg32& rng_inst) {
            basis = rng_inst();
            basis <<= 32;
            basis |= rng_inst();
        }

        uint64_t basis;

        uint64_t operator()(TestCaseInfo const& t) const {
            // Modified FNV-1a hash
            static constexpr uint64_t prime = 1099511628211;
            uint64_t hash = basis;
            for (const char c : t.name) {
                hash ^= c;
                hash *= prime;
            }
            return hash;
        }
    };
} // end anonymous namespace

    std::vector<TestCaseHandle> sortTests( IConfig const& config, std::vector<TestCaseHandle> const& unsortedTestCases ) {
        switch (config.runOrder()) {
        case TestRunOrder::Declared:
            return unsortedTestCases;

        case TestRunOrder::LexicographicallySorted: {
            std::vector<TestCaseHandle> sorted = unsortedTestCases;
            std::sort(sorted.begin(), sorted.end());
            return sorted;
        }
        case TestRunOrder::Randomized: {
            seedRng(config);
            HashTest h(rng());
            std::vector<std::pair<uint64_t, TestCaseHandle>> indexed_tests;
            indexed_tests.reserve(unsortedTestCases.size());

            for (auto const& handle : unsortedTestCases) {
                indexed_tests.emplace_back(h(handle.getTestCaseInfo()), handle);
            }

            std::sort(indexed_tests.begin(), indexed_tests.end());

            std::vector<TestCaseHandle> randomized;
            randomized.reserve(indexed_tests.size());

            for (auto const& indexed : indexed_tests) {
                randomized.push_back(indexed.second);
            }

            return randomized;
        }
        }

        CATCH_INTERNAL_ERROR("Unknown test order value!");
    }

    bool isThrowSafe( TestCaseHandle const& testCase, IConfig const& config ) {
        return !testCase.getTestCaseInfo().throws() || config.allowThrows();
    }

    bool matchTest( TestCaseHandle const& testCase, TestSpec const& testSpec, IConfig const& config ) {
        return testSpec.matches( testCase.getTestCaseInfo() ) && isThrowSafe( testCase, config );
    }

    void enforceNoDuplicateTestCases( std::vector<TestCaseHandle> const& functions ) {
        std::set<TestCaseHandle> seenFunctions;
        for( auto const& function : functions ) {
            auto prev = seenFunctions.insert( function );
            CATCH_ENFORCE( prev.second,
                    "error: TEST_CASE( \"" << function.getTestCaseInfo().name << "\" ) already defined.\n"
                    << "\tFirst seen at " << prev.first->getTestCaseInfo().lineInfo << "\n"
                    << "\tRedefined at " << function.getTestCaseInfo().lineInfo );
        }
    }

    std::vector<TestCaseHandle> filterTests( std::vector<TestCaseHandle> const& testCases, TestSpec const& testSpec, IConfig const& config ) {
        std::vector<TestCaseHandle> filtered;
        filtered.reserve( testCases.size() );
        for (auto const& testCase : testCases) {
            if ((!testSpec.hasFilters() && !testCase.getTestCaseInfo().isHidden()) ||
                (testSpec.hasFilters() && matchTest(testCase, testSpec, config))) {
                filtered.push_back(testCase);
            }
        }
        return filtered;
    }
    std::vector<TestCaseHandle> const& getAllTestCasesSorted( IConfig const& config ) {
        return getRegistryHub().getTestCaseRegistry().getAllTestsSorted( config );
    }

    void TestRegistry::registerTest(Detail::unique_ptr<TestCaseInfo> testInfo, Detail::unique_ptr<ITestInvoker> testInvoker) {
        m_handles.emplace_back(testInfo.get(), testInvoker.get());
        m_viewed_test_infos.push_back(testInfo.get());
        m_owned_test_infos.push_back(std::move(testInfo));
        m_invokers.push_back(std::move(testInvoker));
    }

    std::vector<TestCaseInfo*> const& TestRegistry::getAllInfos() const {
        return m_viewed_test_infos;
    }

    std::vector<TestCaseHandle> const& TestRegistry::getAllTests() const {
        return m_handles;
    }
    std::vector<TestCaseHandle> const& TestRegistry::getAllTestsSorted( IConfig const& config ) const {
        if( m_sortedFunctions.empty() )
            enforceNoDuplicateTestCases( m_handles );

        if(  m_currentSortOrder != config.runOrder() || m_sortedFunctions.empty() ) {
            m_sortedFunctions = sortTests( config, m_handles );
            m_currentSortOrder = config.runOrder();
        }
        return m_sortedFunctions;
    }



    ///////////////////////////////////////////////////////////////////////////
    void TestInvokerAsFunction::invoke() const {
        m_testAsFunction();
    }

    std::string extractClassName( StringRef const& classOrQualifiedMethodName ) {
        std::string className(classOrQualifiedMethodName);
        if( startsWith( className, '&' ) )
        {
            std::size_t lastColons = className.rfind( "::" );
            std::size_t penultimateColons = className.rfind( "::", lastColons-1 );
            if( penultimateColons == std::string::npos )
                penultimateColons = 1;
            className = className.substr( penultimateColons, lastColons-penultimateColons );
        }
        return className;
    }

} // end namespace Catch




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



namespace Catch {

    Detail::unique_ptr<ITestInvoker> makeTestInvoker( void(*testAsFunction)() ) {
        return Detail::unique_ptr<ITestInvoker>( new TestInvokerAsFunction( testAsFunction ));
    }

    AutoReg::AutoReg( Detail::unique_ptr<ITestInvoker> invoker, SourceLineInfo const& lineInfo, StringRef const& classOrMethod, NameAndTags const& nameAndTags ) noexcept {
        CATCH_TRY {
            getMutableRegistryHub()
                    .registerTest(
                        makeTestCaseInfo(
                            extractClassName( classOrMethod ),
                            nameAndTags,
                            lineInfo),
                        std::move(invoker)
                    );
        } CATCH_CATCH_ALL {
            // Do not throw when constructing global objects, instead register the exception to be processed later
            getMutableRegistryHub().registerStartupException();
        }
    }
}





namespace Catch {

    TestSpecParser::TestSpecParser( ITagAliasRegistry const& tagAliases ) : m_tagAliases( &tagAliases ) {}

    TestSpecParser& TestSpecParser::parse( std::string const& arg ) {
        m_mode = None;
        m_exclusion = false;
        m_arg = m_tagAliases->expandAliases( arg );
        m_escapeChars.clear();
        m_substring.reserve(m_arg.size());
        m_patternName.reserve(m_arg.size());
        m_realPatternPos = 0;

        for( m_pos = 0; m_pos < m_arg.size(); ++m_pos )
          //if visitChar fails
           if( !visitChar( m_arg[m_pos] ) ){
               m_testSpec.m_invalidArgs.push_back(arg);
               break;
           }
        endMode();
        return *this;
    }
    TestSpec TestSpecParser::testSpec() {
        addFilter();
        return std::move(m_testSpec);
    }
    bool TestSpecParser::visitChar( char c ) {
        if( (m_mode != EscapedName) && (c == '\\') ) {
            escape();
            addCharToPattern(c);
            return true;
        }else if((m_mode != EscapedName) && (c == ',') )  {
            return separate();
        }

        switch( m_mode ) {
        case None:
            if( processNoneChar( c ) )
                return true;
            break;
        case Name:
            processNameChar( c );
            break;
        case EscapedName:
            endMode();
            addCharToPattern(c);
            return true;
        default:
        case Tag:
        case QuotedName:
            if( processOtherChar( c ) )
                return true;
            break;
        }

        m_substring += c;
        if( !isControlChar( c ) ) {
            m_patternName += c;
            m_realPatternPos++;
        }
        return true;
    }
    // Two of the processing methods return true to signal the caller to return
    // without adding the given character to the current pattern strings
    bool TestSpecParser::processNoneChar( char c ) {
        switch( c ) {
        case ' ':
            return true;
        case '~':
            m_exclusion = true;
            return false;
        case '[':
            startNewMode( Tag );
            return false;
        case '"':
            startNewMode( QuotedName );
            return false;
        default:
            startNewMode( Name );
            return false;
        }
    }
    void TestSpecParser::processNameChar( char c ) {
        if( c == '[' ) {
            if( m_substring == "exclude:" )
                m_exclusion = true;
            else
                endMode();
            startNewMode( Tag );
        }
    }
    bool TestSpecParser::processOtherChar( char c ) {
        if( !isControlChar( c ) )
            return false;
        m_substring += c;
        endMode();
        return true;
    }
    void TestSpecParser::startNewMode( Mode mode ) {
        m_mode = mode;
    }
    void TestSpecParser::endMode() {
        switch( m_mode ) {
        case Name:
        case QuotedName:
            return addNamePattern();
        case Tag:
            return addTagPattern();
        case EscapedName:
            revertBackToLastMode();
            return;
        case None:
        default:
            return startNewMode( None );
        }
    }
    void TestSpecParser::escape() {
        saveLastMode();
        m_mode = EscapedName;
        m_escapeChars.push_back(m_realPatternPos);
    }
    bool TestSpecParser::isControlChar( char c ) const {
        switch( m_mode ) {
            default:
                return false;
            case None:
                return c == '~';
            case Name:
                return c == '[';
            case EscapedName:
                return true;
            case QuotedName:
                return c == '"';
            case Tag:
                return c == '[' || c == ']';
        }
    }

    void TestSpecParser::addFilter() {
        if( !m_currentFilter.m_required.empty() || !m_currentFilter.m_forbidden.empty() ) {
            m_testSpec.m_filters.push_back( std::move(m_currentFilter) );
            m_currentFilter = TestSpec::Filter();
        }
    }

    void TestSpecParser::saveLastMode() {
      lastMode = m_mode;
    }

    void TestSpecParser::revertBackToLastMode() {
      m_mode = lastMode;
    }

    bool TestSpecParser::separate() {
      if( (m_mode==QuotedName) || (m_mode==Tag) ){
         //invalid argument, signal failure to previous scope.
         m_mode = None;
         m_pos = m_arg.size();
         m_substring.clear();
         m_patternName.clear();
         m_realPatternPos = 0;
         return false;
      }
      endMode();
      addFilter();
      return true; //success
    }

    std::string TestSpecParser::preprocessPattern() {
        std::string token = m_patternName;
        for (std::size_t i = 0; i < m_escapeChars.size(); ++i)
            token = token.substr(0, m_escapeChars[i] - i) + token.substr(m_escapeChars[i] - i + 1);
        m_escapeChars.clear();
        if (startsWith(token, "exclude:")) {
            m_exclusion = true;
            token = token.substr(8);
        }

        m_patternName.clear();
        m_realPatternPos = 0;

        return token;
    }

    void TestSpecParser::addNamePattern() {
        auto token = preprocessPattern();

        if (!token.empty()) {
            if (m_exclusion) {
                m_currentFilter.m_forbidden.emplace_back(Detail::make_unique<TestSpec::NamePattern>(token, m_substring));
            } else {
                m_currentFilter.m_required.emplace_back(Detail::make_unique<TestSpec::NamePattern>(token, m_substring));
            }
        }
        m_substring.clear();
        m_exclusion = false;
        m_mode = None;
    }

    void TestSpecParser::addTagPattern() {
        auto token = preprocessPattern();

        if (!token.empty()) {
            // If the tag pattern is the "hide and tag" shorthand (e.g. [.foo])
            // we have to create a separate hide tag and shorten the real one
            if (token.size() > 1 && token[0] == '.') {
                token.erase(token.begin());
                if (m_exclusion) {
                    m_currentFilter.m_forbidden.emplace_back(Detail::make_unique<TestSpec::TagPattern>(".", m_substring));
                    m_currentFilter.m_forbidden.emplace_back(Detail::make_unique<TestSpec::TagPattern>(token, m_substring));
                } else {
                    m_currentFilter.m_required.emplace_back(Detail::make_unique<TestSpec::TagPattern>(".", m_substring));
                    m_currentFilter.m_required.emplace_back(Detail::make_unique<TestSpec::TagPattern>(token, m_substring));
                }
            }
            if (m_exclusion) {
                m_currentFilter.m_forbidden.emplace_back(Detail::make_unique<TestSpec::TagPattern>(token, m_substring));
            } else {
                m_currentFilter.m_required.emplace_back(Detail::make_unique<TestSpec::TagPattern>(token, m_substring));
            }
        }
        m_substring.clear();
        m_exclusion = false;
        m_mode = None;
    }

    TestSpec parseTestSpec( std::string const& arg ) {
        return TestSpecParser( ITagAliasRegistry::get() ).parse( arg ).testSpec();
    }

} // namespace Catch


#include <cstring>
#include <ostream>

namespace {
    bool isWhitespace( char c ) {
        return c == ' ' || c == '\t' || c == '\n' || c == '\r';
    }

    bool isBreakableBefore( char c ) {
        static const char chars[] = "[({<|";
        return std::memchr( chars, c, sizeof( chars ) - 1 ) != nullptr;
    }

    bool isBreakableAfter( char c ) {
        static const char chars[] = "])}>.,:;*+-=&/\\";
        return std::memchr( chars, c, sizeof( chars ) - 1 ) != nullptr;
    }

    bool isBoundary( std::string const& line, size_t at ) {
        assert( at > 0 );
        assert( at <= line.size() );

        return at == line.size() ||
               ( isWhitespace( line[at] ) && !isWhitespace( line[at - 1] ) ) ||
               isBreakableBefore( line[at] ) ||
               isBreakableAfter( line[at - 1] );
    }

} // namespace

namespace Catch {
    namespace TextFlow {

        void Column::iterator::calcLength() {
            m_suffix = false;
            auto width = m_column.m_width - indent();
            m_end = m_pos;
            std::string const& current_line = m_column.m_string;
            if ( current_line[m_pos] == '\n' ) {
                ++m_end;
            }
            while ( m_end < current_line.size() &&
                    current_line[m_end] != '\n' ) {
                ++m_end;
            }

            if ( m_end < m_pos + width ) {
                m_len = m_end - m_pos;
            } else {
                size_t len = width;
                while ( len > 0 && !isBoundary( current_line, m_pos + len ) ) {
                    --len;
                }
                while ( len > 0 &&
                        isWhitespace( current_line[m_pos + len - 1] ) ) {
                    --len;
                }

                if ( len > 0 ) {
                    m_len = len;
                } else {
                    m_suffix = true;
                    m_len = width - 1;
                }
            }
        }

        size_t Column::iterator::indent() const {
            auto initial =
                m_pos == 0 ? m_column.m_initialIndent : std::string::npos;
            return initial == std::string::npos ? m_column.m_indent : initial;
        }

        std::string
        Column::iterator::addIndentAndSuffix( size_t position,
                                              size_t length ) const {
            std::string ret;
            const auto desired_indent = indent();
            ret.reserve( desired_indent + length + m_suffix );
            ret.append( desired_indent, ' ' );
            ret.append( m_column.m_string, position, length );
            if ( m_suffix ) {
                ret.push_back( '-' );
            }

            return ret;
        }

        Column::iterator::iterator( Column const& column ): m_column( column ) {
            assert( m_column.m_width > m_column.m_indent );
            assert( m_column.m_initialIndent == std::string::npos ||
                    m_column.m_width > m_column.m_initialIndent );
            calcLength();
            if ( m_len == 0 ) {
                m_pos = m_column.m_string.size();
            }
        }

        std::string Column::iterator::operator*() const {
            assert( m_pos <= m_end );
            return addIndentAndSuffix( m_pos, m_len );
        }

        Column::iterator& Column::iterator::operator++() {
            m_pos += m_len;
            std::string const& current_line = m_column.m_string;
            if ( m_pos < current_line.size() && current_line[m_pos] == '\n' ) {
                m_pos += 1;
            } else {
                while ( m_pos < current_line.size() &&
                        isWhitespace( current_line[m_pos] ) ) {
                    ++m_pos;
                }
            }

            if ( m_pos != current_line.size() ) {
                calcLength();
            }
            return *this;
        }

        Column::iterator Column::iterator::operator++( int ) {
            iterator prev( *this );
            operator++();
            return prev;
        }

        std::ostream& operator<<( std::ostream& os, Column const& col ) {
            bool first = true;
            for ( auto line : col ) {
                if ( first ) {
                    first = false;
                } else {
                    os << '\n';
                }
                os << line;
            }
            return os;
        }

        Column Spacer( size_t spaceWidth ) {
            Column ret{ "" };
            ret.width( spaceWidth );
            return ret;
        }

        Columns::iterator::iterator( Columns const& columns, EndTag ):
            m_columns( columns.m_columns ), m_activeIterators( 0 ) {

            m_iterators.reserve( m_columns.size() );
            for ( auto const& col : m_columns ) {
                m_iterators.push_back( col.end() );
            }
        }

        Columns::iterator::iterator( Columns const& columns ):
            m_columns( columns.m_columns ),
            m_activeIterators( m_columns.size() ) {

            m_iterators.reserve( m_columns.size() );
            for ( auto const& col : m_columns ) {
                m_iterators.push_back( col.begin() );
            }
        }

        std::string Columns::iterator::operator*() const {
            std::string row, padding;

            for ( size_t i = 0; i < m_columns.size(); ++i ) {
                const auto width = m_columns[i].width();
                if ( m_iterators[i] != m_columns[i].end() ) {
                    std::string col = *m_iterators[i];
                    row += padding;
                    row += col;

                    padding.clear();
                    if ( col.size() < width ) {
                        padding.append( width - col.size(), ' ' );
                    }
                } else {
                    padding.append( width, ' ' );
                }
            }
            return row;
        }

        Columns::iterator& Columns::iterator::operator++() {
            for ( size_t i = 0; i < m_columns.size(); ++i ) {
                if ( m_iterators[i] != m_columns[i].end() ) {
                    ++m_iterators[i];
                }
            }
            return *this;
        }

        Columns::iterator Columns::iterator::operator++( int ) {
            iterator prev( *this );
            operator++();
            return prev;
        }

        std::ostream& operator<<( std::ostream& os, Columns const& cols ) {
            bool first = true;
            for ( auto line : cols ) {
                if ( first ) {
                    first = false;
                } else {
                    os << '\n';
                }
                os << line;
            }
            return os;
        }

        Columns Column::operator+( Column const& other ) {
            Columns cols;
            cols += *this;
            cols += other;
            return cols;
        }

        Columns& Columns::operator+=( Column const& col ) {
            m_columns.push_back( col );
            return *this;
        }

        Columns Columns::operator+( Column const& col ) {
            Columns combined = *this;
            combined += col;
            return combined;
        }

    } // namespace TextFlow
} // namespace Catch



namespace Catch {

    WildcardPattern::WildcardPattern( std::string const& pattern,
                                      CaseSensitive caseSensitivity )
    :   m_caseSensitivity( caseSensitivity ),
        m_pattern( normaliseString( pattern ) )
    {
        if( startsWith( m_pattern, '*' ) ) {
            m_pattern = m_pattern.substr( 1 );
            m_wildcard = WildcardAtStart;
        }
        if( endsWith( m_pattern, '*' ) ) {
            m_pattern = m_pattern.substr( 0, m_pattern.size()-1 );
            m_wildcard = static_cast<WildcardPosition>( m_wildcard | WildcardAtEnd );
        }
    }

    bool WildcardPattern::matches( std::string const& str ) const {
        switch( m_wildcard ) {
            case NoWildcard:
                return m_pattern == normaliseString( str );
            case WildcardAtStart:
                return endsWith( normaliseString( str ), m_pattern );
            case WildcardAtEnd:
                return startsWith( normaliseString( str ), m_pattern );
            case WildcardAtBothEnds:
                return contains( normaliseString( str ), m_pattern );
            default:
                CATCH_INTERNAL_ERROR( "Unknown enum" );
        }
    }

    std::string WildcardPattern::normaliseString( std::string const& str ) const {
        return trim( m_caseSensitivity == CaseSensitive::No ? toLower( str ) : str );
    }
}




#include <iomanip>
#include <type_traits>

namespace Catch {

namespace {

    size_t trailingBytes(unsigned char c) {
        if ((c & 0xE0) == 0xC0) {
            return 2;
        }
        if ((c & 0xF0) == 0xE0) {
            return 3;
        }
        if ((c & 0xF8) == 0xF0) {
            return 4;
        }
        CATCH_INTERNAL_ERROR("Invalid multibyte utf-8 start byte encountered");
    }

    uint32_t headerValue(unsigned char c) {
        if ((c & 0xE0) == 0xC0) {
            return c & 0x1F;
        }
        if ((c & 0xF0) == 0xE0) {
            return c & 0x0F;
        }
        if ((c & 0xF8) == 0xF0) {
            return c & 0x07;
        }
        CATCH_INTERNAL_ERROR("Invalid multibyte utf-8 start byte encountered");
    }

    void hexEscapeChar(std::ostream& os, unsigned char c) {
        std::ios_base::fmtflags f(os.flags());
        os << "\\x"
            << std::uppercase << std::hex << std::setfill('0') << std::setw(2)
            << static_cast<int>(c);
        os.flags(f);
    }

    bool shouldNewline(XmlFormatting fmt) {
        return !!(static_cast<std::underlying_type_t<XmlFormatting>>(fmt & XmlFormatting::Newline));
    }

    bool shouldIndent(XmlFormatting fmt) {
        return !!(static_cast<std::underlying_type_t<XmlFormatting>>(fmt & XmlFormatting::Indent));
    }

} // anonymous namespace

    XmlFormatting operator | (XmlFormatting lhs, XmlFormatting rhs) {
        return static_cast<XmlFormatting>(
            static_cast<std::underlying_type_t<XmlFormatting>>(lhs) |
            static_cast<std::underlying_type_t<XmlFormatting>>(rhs)
        );
    }

    XmlFormatting operator & (XmlFormatting lhs, XmlFormatting rhs) {
        return static_cast<XmlFormatting>(
            static_cast<std::underlying_type_t<XmlFormatting>>(lhs) &
            static_cast<std::underlying_type_t<XmlFormatting>>(rhs)
        );
    }


    XmlEncode::XmlEncode( std::string const& str, ForWhat forWhat )
    :   m_str( str ),
        m_forWhat( forWhat )
    {}

    void XmlEncode::encodeTo( std::ostream& os ) const {
        // Apostrophe escaping not necessary if we always use " to write attributes
        // (see: http://www.w3.org/TR/xml/#syntax)

        for( std::size_t idx = 0; idx < m_str.size(); ++ idx ) {
            unsigned char c = m_str[idx];
            switch (c) {
            case '<':   os << "&lt;"; break;
            case '&':   os << "&amp;"; break;

            case '>':
                // See: http://www.w3.org/TR/xml/#syntax
                if (idx > 2 && m_str[idx - 1] == ']' && m_str[idx - 2] == ']')
                    os << "&gt;";
                else
                    os << c;
                break;

            case '\"':
                if (m_forWhat == ForAttributes)
                    os << "&quot;";
                else
                    os << c;
                break;

            default:
                // Check for control characters and invalid utf-8

                // Escape control characters in standard ascii
                // see http://stackoverflow.com/questions/404107/why-are-control-characters-illegal-in-xml-1-0
                if (c < 0x09 || (c > 0x0D && c < 0x20) || c == 0x7F) {
                    hexEscapeChar(os, c);
                    break;
                }

                // Plain ASCII: Write it to stream
                if (c < 0x7F) {
                    os << c;
                    break;
                }

                // UTF-8 territory
                // Check if the encoding is valid and if it is not, hex escape bytes.
                // Important: We do not check the exact decoded values for validity, only the encoding format
                // First check that this bytes is a valid lead byte:
                // This means that it is not encoded as 1111 1XXX
                // Or as 10XX XXXX
                if (c <  0xC0 ||
                    c >= 0xF8) {
                    hexEscapeChar(os, c);
                    break;
                }

                auto encBytes = trailingBytes(c);
                // Are there enough bytes left to avoid accessing out-of-bounds memory?
                if (idx + encBytes - 1 >= m_str.size()) {
                    hexEscapeChar(os, c);
                    break;
                }
                // The header is valid, check data
                // The next encBytes bytes must together be a valid utf-8
                // This means: bitpattern 10XX XXXX and the extracted value is sane (ish)
                bool valid = true;
                uint32_t value = headerValue(c);
                for (std::size_t n = 1; n < encBytes; ++n) {
                    unsigned char nc = m_str[idx + n];
                    valid &= ((nc & 0xC0) == 0x80);
                    value = (value << 6) | (nc & 0x3F);
                }

                if (
                    // Wrong bit pattern of following bytes
                    (!valid) ||
                    // Overlong encodings
                    (value < 0x80) ||
                    (0x80 <= value && value < 0x800   && encBytes > 2) ||
                    (0x800 < value && value < 0x10000 && encBytes > 3) ||
                    // Encoded value out of range
                    (value >= 0x110000)
                    ) {
                    hexEscapeChar(os, c);
                    break;
                }

                // If we got here, this is in fact a valid(ish) utf-8 sequence
                for (std::size_t n = 0; n < encBytes; ++n) {
                    os << m_str[idx + n];
                }
                idx += encBytes - 1;
                break;
            }
        }
    }

    std::ostream& operator << ( std::ostream& os, XmlEncode const& xmlEncode ) {
        xmlEncode.encodeTo( os );
        return os;
    }

    XmlWriter::ScopedElement::ScopedElement( XmlWriter* writer, XmlFormatting fmt )
    :   m_writer( writer ),
        m_fmt(fmt)
    {}

    XmlWriter::ScopedElement::ScopedElement( ScopedElement&& other ) noexcept
    :   m_writer( other.m_writer ),
        m_fmt(other.m_fmt)
    {
        other.m_writer = nullptr;
        other.m_fmt = XmlFormatting::None;
    }
    XmlWriter::ScopedElement& XmlWriter::ScopedElement::operator=( ScopedElement&& other ) noexcept {
        if ( m_writer ) {
            m_writer->endElement();
        }
        m_writer = other.m_writer;
        other.m_writer = nullptr;
        m_fmt = other.m_fmt;
        other.m_fmt = XmlFormatting::None;
        return *this;
    }


    XmlWriter::ScopedElement::~ScopedElement() {
        if (m_writer) {
            m_writer->endElement(m_fmt);
        }
    }

    XmlWriter::ScopedElement& XmlWriter::ScopedElement::writeText( std::string const& text, XmlFormatting fmt ) {
        m_writer->writeText( text, fmt );
        return *this;
    }

    XmlWriter::XmlWriter( std::ostream& os ) : m_os( os )
    {
        writeDeclaration();
    }

    XmlWriter::~XmlWriter() {
        while (!m_tags.empty()) {
            endElement();
        }
        newlineIfNecessary();
    }

    XmlWriter& XmlWriter::startElement( std::string const& name, XmlFormatting fmt ) {
        ensureTagClosed();
        newlineIfNecessary();
        if (shouldIndent(fmt)) {
            m_os << m_indent;
            m_indent += "  ";
        }
        m_os << '<' << name;
        m_tags.push_back( name );
        m_tagIsOpen = true;
        applyFormatting(fmt);
        return *this;
    }

    XmlWriter::ScopedElement XmlWriter::scopedElement( std::string const& name, XmlFormatting fmt ) {
        ScopedElement scoped( this, fmt );
        startElement( name, fmt );
        return scoped;
    }

    XmlWriter& XmlWriter::endElement(XmlFormatting fmt) {
        m_indent = m_indent.substr(0, m_indent.size() - 2);

        if( m_tagIsOpen ) {
            m_os << "/>";
            m_tagIsOpen = false;
        } else {
            newlineIfNecessary();
            if (shouldIndent(fmt)) {
                m_os << m_indent;
            }
            m_os << "</" << m_tags.back() << ">";
        }
        m_os << std::flush;
        applyFormatting(fmt);
        m_tags.pop_back();
        return *this;
    }

    XmlWriter& XmlWriter::writeAttribute( std::string const& name, std::string const& attribute ) {
        if( !name.empty() && !attribute.empty() )
            m_os << ' ' << name << "=\"" << XmlEncode( attribute, XmlEncode::ForAttributes ) << '"';
        return *this;
    }

    XmlWriter& XmlWriter::writeAttribute( std::string const& name, bool attribute ) {
        m_os << ' ' << name << "=\"" << ( attribute ? "true" : "false" ) << '"';
        return *this;
    }

    XmlWriter& XmlWriter::writeText( std::string const& text, XmlFormatting fmt) {
        if( !text.empty() ){
            bool tagWasOpen = m_tagIsOpen;
            ensureTagClosed();
            if (tagWasOpen && shouldIndent(fmt)) {
                m_os << m_indent;
            }
            m_os << XmlEncode( text );
            applyFormatting(fmt);
        }
        return *this;
    }

    XmlWriter& XmlWriter::writeComment( std::string const& text, XmlFormatting fmt) {
        ensureTagClosed();
        if (shouldIndent(fmt)) {
            m_os << m_indent;
        }
        m_os << "<!--" << text << "-->";
        applyFormatting(fmt);
        return *this;
    }

    void XmlWriter::writeStylesheetRef( std::string const& url ) {
        m_os << "<?xml-stylesheet type=\"text/xsl\" href=\"" << url << "\"?>\n";
    }

    XmlWriter& XmlWriter::writeBlankLine() {
        ensureTagClosed();
        m_os << '\n';
        return *this;
    }

    void XmlWriter::ensureTagClosed() {
        if( m_tagIsOpen ) {
            m_os << '>' << std::flush;
            newlineIfNecessary();
            m_tagIsOpen = false;
        }
    }

    void XmlWriter::applyFormatting(XmlFormatting fmt) {
        m_needsNewline = shouldNewline(fmt);
    }

    void XmlWriter::writeDeclaration() {
        m_os << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    }

    void XmlWriter::newlineIfNecessary() {
        if( m_needsNewline ) {
            m_os << std::endl;
            m_needsNewline = false;
        }
    }
}



#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <limits>


namespace Catch {
namespace {

    int32_t convert(float f) {
        static_assert(sizeof(float) == sizeof(int32_t), "Important ULP matcher assumption violated");
        int32_t i;
        std::memcpy(&i, &f, sizeof(f));
        return i;
    }

    int64_t convert(double d) {
        static_assert(sizeof(double) == sizeof(int64_t), "Important ULP matcher assumption violated");
        int64_t i;
        std::memcpy(&i, &d, sizeof(d));
        return i;
    }

    template <typename FP>
    bool almostEqualUlps(FP lhs, FP rhs, uint64_t maxUlpDiff) {
        // Comparison with NaN should always be false.
        // This way we can rule it out before getting into the ugly details
        if (Catch::isnan(lhs) || Catch::isnan(rhs)) {
            return false;
        }

        auto lc = convert(lhs);
        auto rc = convert(rhs);

        if ((lc < 0) != (rc < 0)) {
            // Potentially we can have +0 and -0
            return lhs == rhs;
        }

        auto ulpDiff = std::abs(lc - rc);
        return static_cast<uint64_t>(ulpDiff) <= maxUlpDiff;
    }

#if defined(CATCH_CONFIG_GLOBAL_NEXTAFTER)

    float nextafter(float x, float y) {
        return ::nextafterf(x, y);
    }

    double nextafter(double x, double y) {
        return ::nextafter(x, y);
    }

#endif // ^^^ CATCH_CONFIG_GLOBAL_NEXTAFTER ^^^

template <typename FP>
FP step(FP start, FP direction, uint64_t steps) {
    for (uint64_t i = 0; i < steps; ++i) {
#if defined(CATCH_CONFIG_GLOBAL_NEXTAFTER)
        start = Catch::nextafter(start, direction);
#else
        start = std::nextafter(start, direction);
#endif
    }
    return start;
}

// Performs equivalent check of std::fabs(lhs - rhs) <= margin
// But without the subtraction to allow for INFINITY in comparison
bool marginComparison(double lhs, double rhs, double margin) {
    return (lhs + margin >= rhs) && (rhs + margin >= lhs);
}

template <typename FloatingPoint>
void write(std::ostream& out, FloatingPoint num) {
    out << std::scientific
        << std::setprecision(std::numeric_limits<FloatingPoint>::max_digits10 - 1)
        << num;
}

} // end anonymous namespace

namespace Matchers {
namespace Detail {

    enum class FloatingPointKind : uint8_t {
        Float,
        Double
    };

} // end namespace Detail


    WithinAbsMatcher::WithinAbsMatcher(double target, double margin)
        :m_target{ target }, m_margin{ margin } {
        CATCH_ENFORCE(margin >= 0, "Invalid margin: " << margin << '.'
            << " Margin has to be non-negative.");
    }

    // Performs equivalent check of std::fabs(lhs - rhs) <= margin
    // But without the subtraction to allow for INFINITY in comparison
    bool WithinAbsMatcher::match(double const& matchee) const {
        return (matchee + m_margin >= m_target) && (m_target + m_margin >= matchee);
    }

    std::string WithinAbsMatcher::describe() const {
        return "is within " + ::Catch::Detail::stringify(m_margin) + " of " + ::Catch::Detail::stringify(m_target);
    }


    WithinUlpsMatcher::WithinUlpsMatcher(double target, uint64_t ulps, Detail::FloatingPointKind baseType)
        :m_target{ target }, m_ulps{ ulps }, m_type{ baseType } {
        CATCH_ENFORCE(m_type == Detail::FloatingPointKind::Double
                   || m_ulps < (std::numeric_limits<uint32_t>::max)(),
            "Provided ULP is impossibly large for a float comparison.");
    }

#if defined(__clang__)
#pragma clang diagnostic push
// Clang <3.5 reports on the default branch in the switch below
#pragma clang diagnostic ignored "-Wunreachable-code"
#endif

    bool WithinUlpsMatcher::match(double const& matchee) const {
        switch (m_type) {
        case Detail::FloatingPointKind::Float:
            return almostEqualUlps<float>(static_cast<float>(matchee), static_cast<float>(m_target), m_ulps);
        case Detail::FloatingPointKind::Double:
            return almostEqualUlps<double>(matchee, m_target, m_ulps);
        default:
            CATCH_INTERNAL_ERROR( "Unknown Detail::FloatingPointKind value" );
        }
    }

#if defined(__clang__)
#pragma clang diagnostic pop
#endif

    std::string WithinUlpsMatcher::describe() const {
        std::stringstream ret;

        ret << "is within " << m_ulps << " ULPs of ";

        if (m_type == Detail::FloatingPointKind::Float) {
            write(ret, static_cast<float>(m_target));
            ret << 'f';
        } else {
            write(ret, m_target);
        }

        ret << " ([";
        if (m_type == Detail::FloatingPointKind::Double) {
            write(ret, step(m_target, static_cast<double>(-INFINITY), m_ulps));
            ret << ", ";
            write(ret, step(m_target, static_cast<double>( INFINITY), m_ulps));
        } else {
            // We have to cast INFINITY to float because of MinGW, see #1782
            write(ret, step(static_cast<float>(m_target), static_cast<float>(-INFINITY), m_ulps));
            ret << ", ";
            write(ret, step(static_cast<float>(m_target), static_cast<float>( INFINITY), m_ulps));
        }
        ret << "])";

        return ret.str();
    }

    WithinRelMatcher::WithinRelMatcher(double target, double epsilon):
        m_target(target),
        m_epsilon(epsilon){
        CATCH_ENFORCE(m_epsilon >= 0., "Relative comparison with epsilon <  0 does not make sense.");
        CATCH_ENFORCE(m_epsilon  < 1., "Relative comparison with epsilon >= 1 does not make sense.");
    }

    bool WithinRelMatcher::match(double const& matchee) const {
        const auto relMargin = m_epsilon * (std::max)(std::fabs(matchee), std::fabs(m_target));
        return marginComparison(matchee, m_target,
                                std::isinf(relMargin)? 0 : relMargin);
    }

    std::string WithinRelMatcher::describe() const {
        Catch::ReusableStringStream sstr;
        sstr << "and " << m_target << " are within " << m_epsilon * 100. << "% of each other";
        return sstr.str();
    }


WithinUlpsMatcher WithinULP(double target, uint64_t maxUlpDiff) {
    return WithinUlpsMatcher(target, maxUlpDiff, Detail::FloatingPointKind::Double);
}

WithinUlpsMatcher WithinULP(float target, uint64_t maxUlpDiff) {
    return WithinUlpsMatcher(target, maxUlpDiff, Detail::FloatingPointKind::Float);
}

WithinAbsMatcher WithinAbs(double target, double margin) {
    return WithinAbsMatcher(target, margin);
}

WithinRelMatcher WithinRel(double target, double eps) {
    return WithinRelMatcher(target, eps);
}

WithinRelMatcher WithinRel(double target) {
    return WithinRelMatcher(target, std::numeric_limits<double>::epsilon() * 100);
}

WithinRelMatcher WithinRel(float target, float eps) {
    return WithinRelMatcher(target, eps);
}

WithinRelMatcher WithinRel(float target) {
    return WithinRelMatcher(target, std::numeric_limits<float>::epsilon() * 100);
}


} // namespace Matchers
} // namespace Catch



#include <regex>

namespace Catch {
namespace Matchers {

    CasedString::CasedString( std::string const& str, CaseSensitive caseSensitivity )
    :   m_caseSensitivity( caseSensitivity ),
        m_str( adjustString( str ) )
    {}
    std::string CasedString::adjustString( std::string const& str ) const {
        return m_caseSensitivity == CaseSensitive::No
               ? toLower( str )
               : str;
    }
    StringRef CasedString::caseSensitivitySuffix() const {
        return m_caseSensitivity == CaseSensitive::Yes
                   ? StringRef()
                   : " (case insensitive)"_sr;
    }


    StringMatcherBase::StringMatcherBase( std::string const& operation, CasedString const& comparator )
    : m_comparator( comparator ),
      m_operation( operation ) {
    }

    std::string StringMatcherBase::describe() const {
        std::string description;
        description.reserve(5 + m_operation.size() + m_comparator.m_str.size() +
                                    m_comparator.caseSensitivitySuffix().size());
        description += m_operation;
        description += ": \"";
        description += m_comparator.m_str;
        description += "\"";
        description += m_comparator.caseSensitivitySuffix();
        return description;
    }

    StringEqualsMatcher::StringEqualsMatcher( CasedString const& comparator ) : StringMatcherBase( "equals", comparator ) {}

    bool StringEqualsMatcher::match( std::string const& source ) const {
        return m_comparator.adjustString( source ) == m_comparator.m_str;
    }


    StringContainsMatcher::StringContainsMatcher( CasedString const& comparator ) : StringMatcherBase( "contains", comparator ) {}

    bool StringContainsMatcher::match( std::string const& source ) const {
        return contains( m_comparator.adjustString( source ), m_comparator.m_str );
    }


    StartsWithMatcher::StartsWithMatcher( CasedString const& comparator ) : StringMatcherBase( "starts with", comparator ) {}

    bool StartsWithMatcher::match( std::string const& source ) const {
        return startsWith( m_comparator.adjustString( source ), m_comparator.m_str );
    }


    EndsWithMatcher::EndsWithMatcher( CasedString const& comparator ) : StringMatcherBase( "ends with", comparator ) {}

    bool EndsWithMatcher::match( std::string const& source ) const {
        return endsWith( m_comparator.adjustString( source ), m_comparator.m_str );
    }



    RegexMatcher::RegexMatcher(std::string regex, CaseSensitive caseSensitivity): m_regex(std::move(regex)), m_caseSensitivity(caseSensitivity) {}

    bool RegexMatcher::match(std::string const& matchee) const {
        auto flags = std::regex::ECMAScript; // ECMAScript is the default syntax option anyway
        if (m_caseSensitivity == CaseSensitive::No) {
            flags |= std::regex::icase;
        }
        auto reg = std::regex(m_regex, flags);
        return std::regex_match(matchee, reg);
    }

    std::string RegexMatcher::describe() const {
        return "matches " + ::Catch::Detail::stringify(m_regex) + ((m_caseSensitivity == CaseSensitive::Yes)? " case sensitively" : " case insensitively");
    }


    StringEqualsMatcher Equals( std::string const& str, CaseSensitive caseSensitivity ) {
        return StringEqualsMatcher( CasedString( str, caseSensitivity) );
    }
    StringContainsMatcher Contains( std::string const& str, CaseSensitive caseSensitivity ) {
        return StringContainsMatcher( CasedString( str, caseSensitivity) );
    }
    EndsWithMatcher EndsWith( std::string const& str, CaseSensitive caseSensitivity ) {
        return EndsWithMatcher( CasedString( str, caseSensitivity) );
    }
    StartsWithMatcher StartsWith( std::string const& str, CaseSensitive caseSensitivity ) {
        return StartsWithMatcher( CasedString( str, caseSensitivity) );
    }

    RegexMatcher Matches(std::string const& regex, CaseSensitive caseSensitivity) {
        return RegexMatcher(regex, caseSensitivity);
    }

} // namespace Matchers
} // namespace Catch



namespace Catch {
namespace Matchers {
    MatcherGenericBase::~MatcherGenericBase() = default;

    namespace Detail {

        std::string describe_multi_matcher(StringRef combine, std::string const* descriptions_begin, std::string const* descriptions_end) {
            std::string description;
            std::size_t combined_size = 4;
            for ( auto desc = descriptions_begin; desc != descriptions_end; ++desc ) {
                combined_size += desc->size();
            }
            combined_size += (descriptions_end - descriptions_begin - 1) * combine.size();

            description.reserve(combined_size);

            description += "( ";
            bool first = true;
            for( auto desc = descriptions_begin; desc != descriptions_end; ++desc ) {
                if( first )
                    first = false;
                else
                    description += combine;
                description += *desc;
            }
            description += " )";
            return description;
        }

    } // namespace Detail
} // namespace Matchers
} // namespace Catch


/** \file
 * This is a special TU that combines what would otherwise be a very
 * small matcher-related TUs into one bigger TU.
 *
 * The reason for this is compilation performance improvements by
 * avoiding reparsing headers for many small TUs, instead having this
 * one TU include bit more, but having it all parsed only once.
 *
 * To avoid heavy-tail problem with compilation times, each "subpart"
 * of Catch2 has its own combined TU like this.
 */

//////////////////////////////////////////////
// vvv formerly catch_matchers_impl.cpp vvv //
//////////////////////////////////////////////

namespace Catch {

    // This is the general overload that takes a any string matcher
    // There is another overload, in catch_assertionhandler.h/.cpp, that only takes a string and infers
    // the Equals matcher (so the header does not mention matchers)
    void handleExceptionMatchExpr( AssertionHandler& handler, StringMatcher const& matcher, StringRef const& matcherString  ) {
        std::string exceptionMessage = Catch::translateActiveException();
        MatchExpr<std::string, StringMatcher const&> expr( std::move(exceptionMessage), matcher, matcherString );
        handler.handleExpr( expr );
    }

} // namespace Catch


//////////////////////////////////////////////////////////////
// vvv formerly catch_matchers_container_properties.cpp vvv //
//////////////////////////////////////////////////////////////

namespace Catch {
namespace Matchers {

    std::string IsEmptyMatcher::describe() const {
        return "is empty";
    }

    std::string HasSizeMatcher::describe() const {
        ReusableStringStream sstr;
        sstr << "has size == " << m_target_size;
        return sstr.str();
    }

    IsEmptyMatcher IsEmpty() {
        return {};
    }

    HasSizeMatcher SizeIs(std::size_t sz) {
        return HasSizeMatcher{ sz };
    }

} // end namespace Matchers
} // end namespace Catch



/////////////////////////////////////////
// vvv formerly catch_matchers.cpp vvv //
/////////////////////////////////////////


namespace Catch {
namespace Matchers {

    std::string MatcherUntypedBase::toString() const {
        if (m_cachedToString.empty()) {
            m_cachedToString = describe();
        }
        return m_cachedToString;
    }

    MatcherUntypedBase::~MatcherUntypedBase() = default;

} // namespace Matchers
} // namespace Catch



///////////////////////////////////////////////////
// vvv formerly catch_matchers_predicate.cpp vvv //
///////////////////////////////////////////////////

std::string Catch::Matchers::Detail::finalizeDescription(const std::string& desc) {
    if (desc.empty()) {
        return "matches undescribed predicate";
    } else {
        return "matches predicate: \"" + desc + '"';
    }
}





///////////////////////////////////////////////////
// vvv formerly catch_matchers_exception.cpp vvv //
///////////////////////////////////////////////////

namespace Catch {
namespace Matchers {

bool ExceptionMessageMatcher::match(std::exception const& ex) const {
    return ex.what() == m_message;
}

std::string ExceptionMessageMatcher::describe() const {
    return "exception message matches \"" + m_message + "\"";
}

ExceptionMessageMatcher Message(std::string const& message) {
    return ExceptionMessageMatcher(message);
}

} // namespace Matchers
} // namespace Catch



#include <ostream>

namespace Catch {

    AutomakeReporter::~AutomakeReporter() {}

    void AutomakeReporter::testCaseEnded(TestCaseStats const& _testCaseStats) {
        // Possible values to emit are PASS, XFAIL, SKIP, FAIL, XPASS and ERROR.
        stream << ":test-result: ";
        if (_testCaseStats.totals.assertions.allPassed()) {
            stream << "PASS";
        } else if (_testCaseStats.totals.assertions.allOk()) {
            stream << "XFAIL";
        } else {
            stream << "FAIL";
        }
        stream << ' ' << _testCaseStats.testInfo->name << '\n';
        StreamingReporterBase::testCaseEnded(_testCaseStats);
    }

    void AutomakeReporter::skipTest(TestCaseInfo const& testInfo) {
        stream << ":test-result: SKIP " << testInfo.name << '\n';
    }

} // end namespace Catch


/** \file
 * This is a special TU that combines what would otherwise be a very
 * small reporter-related TUs into one bigger TU.
 *
 * The reason for this is compilation performance improvements by
 * avoiding reparsing headers for many small TUs, instead having this
 * one TU include bit more, but having it all parsed only once.
 *
 * To avoid heavy-tail problem with compilation times, each "subpart"
 * of Catch2 has its own combined TU like this.
 */


#include <cfloat>
#include <cstdio>
#include <ostream>

namespace Catch {

    // Because formatting using c++ streams is stateful, drop down to C is
    // required Alternatively we could use stringstream, but its performance
    // is... not good.
    std::string getFormattedDuration( double duration ) {
        // Max exponent + 1 is required to represent the whole part
        // + 1 for decimal point
        // + 3 for the 3 decimal places
        // + 1 for null terminator
        const std::size_t maxDoubleSize = DBL_MAX_10_EXP + 1 + 1 + 3 + 1;
        char buffer[maxDoubleSize];

        // Save previous errno, to prevent sprintf from overwriting it
        ErrnoGuard guard;
#ifdef _MSC_VER
        sprintf_s( buffer, "%.3f", duration );
#else
        std::sprintf( buffer, "%.3f", duration );
#endif
        return std::string( buffer );
    }

    bool shouldShowDuration( IConfig const& config, double duration ) {
        if ( config.showDurations() == ShowDurations::Always ) {
            return true;
        }
        if ( config.showDurations() == ShowDurations::Never ) {
            return false;
        }
        const double min = config.minDuration();
        return min >= 0 && duration >= min;
    }

    std::string serializeFilters( std::vector<std::string> const& filters ) {
        // We add a ' ' separator between each filter
        size_t serialized_size = filters.size() - 1;
        for (auto const& filter : filters) {
            serialized_size += filter.size();
        }

        std::string serialized;
        serialized.reserve(serialized_size);
        bool first = true;

        for (auto const& filter : filters) {
            if (!first) {
                serialized.push_back(' ');
            }
            first = false;
            serialized.append(filter);
        }

        return serialized;
    }

    std::ostream& operator<<( std::ostream& out, lineOfChars value ) {
        for ( size_t idx = 0; idx < CATCH_CONFIG_CONSOLE_WIDTH - 1; ++idx ) {
            out.put( value.c );
        }
        return out;
    }

} // namespace Catch



namespace Catch {
    void EventListenerBase::assertionStarting( AssertionInfo const& ) {}

    bool EventListenerBase::assertionEnded( AssertionStats const& ) {
        return false;
    }
    void
    EventListenerBase::listReporters( std::vector<ReporterDescription> const&,
                                      IConfig const& ) {}
    void EventListenerBase::listTests( std::vector<TestCaseHandle> const&,
                                       IConfig const& ) {}
    void EventListenerBase::listTags( std::vector<TagInfo> const&,
                                      IConfig const& ) {}
    void EventListenerBase::noMatchingTestCases( std::string const& ) {}
    void EventListenerBase::testRunStarting( TestRunInfo const& ) {}
    void EventListenerBase::testGroupStarting( GroupInfo const& ) {}
    void EventListenerBase::testCaseStarting( TestCaseInfo const& ) {}
    void EventListenerBase::sectionStarting( SectionInfo const& ) {}
    void EventListenerBase::sectionEnded( SectionStats const& ) {}
    void EventListenerBase::testCaseEnded( TestCaseStats const& ) {}
    void EventListenerBase::testGroupEnded( TestGroupStats const& ) {}
    void EventListenerBase::testRunEnded( TestRunStats const& ) {}
    void EventListenerBase::skipTest( TestCaseInfo const& ) {}
} // namespace Catch




#include <ostream>

namespace {

    // Colour::LightGrey
    Catch::Colour::Code dimColour() { return Catch::Colour::FileName; }

    Catch::StringRef bothOrAll( std::size_t count ) {
        switch (count) {
        case 1:
            return Catch::StringRef{};
        case 2:
            return "both "_catch_sr;
        default:
            return "all "_catch_sr;
        }
    }

} // anon namespace


namespace Catch {
namespace {

#ifdef CATCH_PLATFORM_MAC
    static constexpr Catch::StringRef compactFailedString = "FAILED"_sr;
    static constexpr Catch::StringRef compactPassedString = "PASSED"_sr;
#else
    static constexpr Catch::StringRef compactFailedString = "failed"_sr;
    static constexpr Catch::StringRef compactPassedString = "passed"_sr;
#endif

// Colour, message variants:
// - white: No tests ran.
// -   red: Failed [both/all] N test cases, failed [both/all] M assertions.
// - white: Passed [both/all] N test cases (no assertions).
// -   red: Failed N tests cases, failed M assertions.
// - green: Passed [both/all] N tests cases with M assertions.
void printTotals(std::ostream& out, const Totals& totals) {
    if (totals.testCases.total() == 0) {
        out << "No tests ran.";
    } else if (totals.testCases.failed == totals.testCases.total()) {
        Colour colour(Colour::ResultError);
        const StringRef qualify_assertions_failed =
            totals.assertions.failed == totals.assertions.total() ?
            bothOrAll(totals.assertions.failed) : StringRef{};
        out <<
            "Failed " << bothOrAll(totals.testCases.failed)
            << pluralise(totals.testCases.failed, "test case") << ", "
            "failed " << qualify_assertions_failed <<
            pluralise(totals.assertions.failed, "assertion") << '.';
    } else if (totals.assertions.total() == 0) {
        out <<
            "Passed " << bothOrAll(totals.testCases.total())
            << pluralise(totals.testCases.total(), "test case")
            << " (no assertions).";
    } else if (totals.assertions.failed) {
        Colour colour(Colour::ResultError);
        out <<
            "Failed " << pluralise(totals.testCases.failed, "test case") << ", "
            "failed " << pluralise(totals.assertions.failed, "assertion") << '.';
    } else {
        Colour colour(Colour::ResultSuccess);
        out <<
            "Passed " << bothOrAll(totals.testCases.passed)
            << pluralise(totals.testCases.passed, "test case") <<
            " with " << pluralise(totals.assertions.passed, "assertion") << '.';
    }
}

// Implementation of CompactReporter formatting
class AssertionPrinter {
public:
    AssertionPrinter& operator= (AssertionPrinter const&) = delete;
    AssertionPrinter(AssertionPrinter const&) = delete;
    AssertionPrinter(std::ostream& _stream, AssertionStats const& _stats, bool _printInfoMessages)
        : stream(_stream)
        , result(_stats.assertionResult)
        , messages(_stats.infoMessages)
        , itMessage(_stats.infoMessages.begin())
        , printInfoMessages(_printInfoMessages) {}

    void print() {
        printSourceInfo();

        itMessage = messages.begin();

        switch (result.getResultType()) {
        case ResultWas::Ok:
            printResultType(Colour::ResultSuccess, compactPassedString);
            printOriginalExpression();
            printReconstructedExpression();
            if (!result.hasExpression())
                printRemainingMessages(Colour::None);
            else
                printRemainingMessages();
            break;
        case ResultWas::ExpressionFailed:
            if (result.isOk())
                printResultType(Colour::ResultSuccess, compactFailedString + " - but was ok"_sr);
            else
                printResultType(Colour::Error, compactFailedString);
            printOriginalExpression();
            printReconstructedExpression();
            printRemainingMessages();
            break;
        case ResultWas::ThrewException:
            printResultType(Colour::Error, compactFailedString);
            printIssue("unexpected exception with message:");
            printMessage();
            printExpressionWas();
            printRemainingMessages();
            break;
        case ResultWas::FatalErrorCondition:
            printResultType(Colour::Error, compactFailedString);
            printIssue("fatal error condition with message:");
            printMessage();
            printExpressionWas();
            printRemainingMessages();
            break;
        case ResultWas::DidntThrowException:
            printResultType(Colour::Error, compactFailedString);
            printIssue("expected exception, got none");
            printExpressionWas();
            printRemainingMessages();
            break;
        case ResultWas::Info:
            printResultType(Colour::None, "info"_sr);
            printMessage();
            printRemainingMessages();
            break;
        case ResultWas::Warning:
            printResultType(Colour::None, "warning"_sr);
            printMessage();
            printRemainingMessages();
            break;
        case ResultWas::ExplicitFailure:
            printResultType(Colour::Error, compactFailedString);
            printIssue("explicitly");
            printRemainingMessages(Colour::None);
            break;
            // These cases are here to prevent compiler warnings
        case ResultWas::Unknown:
        case ResultWas::FailureBit:
        case ResultWas::Exception:
            printResultType(Colour::Error, "** internal error **");
            break;
        }
    }

private:
    void printSourceInfo() const {
        Colour colourGuard(Colour::FileName);
        stream << result.getSourceInfo() << ':';
    }

    void printResultType(Colour::Code colour, StringRef passOrFail) const {
        if (!passOrFail.empty()) {
            {
                Colour colourGuard(colour);
                stream << ' ' << passOrFail;
            }
            stream << ':';
        }
    }

    void printIssue(char const* issue) const {
        stream << ' ' << issue;
    }

    void printExpressionWas() {
        if (result.hasExpression()) {
            stream << ';';
            {
                Colour colour(dimColour());
                stream << " expression was:";
            }
            printOriginalExpression();
        }
    }

    void printOriginalExpression() const {
        if (result.hasExpression()) {
            stream << ' ' << result.getExpression();
        }
    }

    void printReconstructedExpression() const {
        if (result.hasExpandedExpression()) {
            {
                Colour colour(dimColour());
                stream << " for: ";
            }
            stream << result.getExpandedExpression();
        }
    }

    void printMessage() {
        if (itMessage != messages.end()) {
            stream << " '" << itMessage->message << '\'';
            ++itMessage;
        }
    }

    void printRemainingMessages(Colour::Code colour = dimColour()) {
        if (itMessage == messages.end())
            return;

        const auto itEnd = messages.cend();
        const auto N = static_cast<std::size_t>(std::distance(itMessage, itEnd));

        {
            Colour colourGuard(colour);
            stream << " with " << pluralise(N, "message") << ':';
        }

        while (itMessage != itEnd) {
            // If this assertion is a warning ignore any INFO messages
            if (printInfoMessages || itMessage->type != ResultWas::Info) {
                printMessage();
                if (itMessage != itEnd) {
                    Colour colourGuard(dimColour());
                    stream << " and";
                }
                continue;
            }
            ++itMessage;
        }
    }

private:
    std::ostream& stream;
    AssertionResult const& result;
    std::vector<MessageInfo> messages;
    std::vector<MessageInfo>::const_iterator itMessage;
    bool printInfoMessages;
};

} // anon namespace

        std::string CompactReporter::getDescription() {
            return "Reports test results on a single line, suitable for IDEs";
        }

        void CompactReporter::noMatchingTestCases( std::string const& spec ) {
            stream << "No test cases matched '" << spec << '\'' << std::endl;
        }

        void CompactReporter::assertionStarting( AssertionInfo const& ) {}

        bool CompactReporter::assertionEnded( AssertionStats const& _assertionStats ) {
            AssertionResult const& result = _assertionStats.assertionResult;

            bool printInfoMessages = true;

            // Drop out if result was successful and we're not printing those
            if( !m_config->includeSuccessfulResults() && result.isOk() ) {
                if( result.getResultType() != ResultWas::Warning )
                    return false;
                printInfoMessages = false;
            }

            AssertionPrinter printer( stream, _assertionStats, printInfoMessages );
            printer.print();

            stream << std::endl;
            return true;
        }

        void CompactReporter::sectionEnded(SectionStats const& _sectionStats) {
            double dur = _sectionStats.durationInSeconds;
            if ( shouldShowDuration( *m_config, dur ) ) {
                stream << getFormattedDuration( dur ) << " s: " << _sectionStats.sectionInfo.name << std::endl;
            }
        }

        void CompactReporter::testRunEnded( TestRunStats const& _testRunStats ) {
            printTotals( stream, _testRunStats.totals );
            stream << '\n' << std::endl;
            StreamingReporterBase::testRunEnded( _testRunStats );
        }

        CompactReporter::~CompactReporter() {}

} // end namespace Catch




#include <cfloat>
#include <cstdio>

#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable:4061) // Not all labels are EXPLICITLY handled in switch
 // Note that 4062 (not all labels are handled and default is missing) is enabled
#endif

#if defined(__clang__)
#  pragma clang diagnostic push
// For simplicity, benchmarking-only helpers are always enabled
#  pragma clang diagnostic ignored "-Wunused-function"
#endif



namespace Catch {

namespace {

// Formatter impl for ConsoleReporter
class ConsoleAssertionPrinter {
public:
    ConsoleAssertionPrinter& operator= (ConsoleAssertionPrinter const&) = delete;
    ConsoleAssertionPrinter(ConsoleAssertionPrinter const&) = delete;
    ConsoleAssertionPrinter(std::ostream& _stream, AssertionStats const& _stats, bool _printInfoMessages)
        : stream(_stream),
        stats(_stats),
        result(_stats.assertionResult),
        colour(Colour::None),
        message(result.getMessage()),
        messages(_stats.infoMessages),
        printInfoMessages(_printInfoMessages) {
        switch (result.getResultType()) {
        case ResultWas::Ok:
            colour = Colour::Success;
            passOrFail = "PASSED";
            //if( result.hasMessage() )
            if (_stats.infoMessages.size() == 1)
                messageLabel = "with message";
            if (_stats.infoMessages.size() > 1)
                messageLabel = "with messages";
            break;
        case ResultWas::ExpressionFailed:
            if (result.isOk()) {
                colour = Colour::Success;
                passOrFail = "FAILED - but was ok";
            } else {
                colour = Colour::Error;
                passOrFail = "FAILED";
            }
            if (_stats.infoMessages.size() == 1)
                messageLabel = "with message";
            if (_stats.infoMessages.size() > 1)
                messageLabel = "with messages";
            break;
        case ResultWas::ThrewException:
            colour = Colour::Error;
            passOrFail = "FAILED";
            messageLabel = "due to unexpected exception with ";
            if (_stats.infoMessages.size() == 1)
                messageLabel += "message";
            if (_stats.infoMessages.size() > 1)
                messageLabel += "messages";
            break;
        case ResultWas::FatalErrorCondition:
            colour = Colour::Error;
            passOrFail = "FAILED";
            messageLabel = "due to a fatal error condition";
            break;
        case ResultWas::DidntThrowException:
            colour = Colour::Error;
            passOrFail = "FAILED";
            messageLabel = "because no exception was thrown where one was expected";
            break;
        case ResultWas::Info:
            messageLabel = "info";
            break;
        case ResultWas::Warning:
            messageLabel = "warning";
            break;
        case ResultWas::ExplicitFailure:
            passOrFail = "FAILED";
            colour = Colour::Error;
            if (_stats.infoMessages.size() == 1)
                messageLabel = "explicitly with message";
            if (_stats.infoMessages.size() > 1)
                messageLabel = "explicitly with messages";
            break;
            // These cases are here to prevent compiler warnings
        case ResultWas::Unknown:
        case ResultWas::FailureBit:
        case ResultWas::Exception:
            passOrFail = "** internal error **";
            colour = Colour::Error;
            break;
        }
    }

    void print() const {
        printSourceInfo();
        if (stats.totals.assertions.total() > 0) {
            printResultType();
            printOriginalExpression();
            printReconstructedExpression();
        } else {
            stream << '\n';
        }
        printMessage();
    }

private:
    void printResultType() const {
        if (!passOrFail.empty()) {
            Colour colourGuard(colour);
            stream << passOrFail << ":\n";
        }
    }
    void printOriginalExpression() const {
        if (result.hasExpression()) {
            Colour colourGuard(Colour::OriginalExpression);
            stream << "  ";
            stream << result.getExpressionInMacro();
            stream << '\n';
        }
    }
    void printReconstructedExpression() const {
        if (result.hasExpandedExpression()) {
            stream << "with expansion:\n";
            Colour colourGuard(Colour::ReconstructedExpression);
            stream << TextFlow::Column(result.getExpandedExpression()).indent(2) << '\n';
        }
    }
    void printMessage() const {
        if (!messageLabel.empty())
            stream << messageLabel << ':' << '\n';
        for (auto const& msg : messages) {
            // If this assertion is a warning ignore any INFO messages
            if (printInfoMessages || msg.type != ResultWas::Info)
                stream << TextFlow::Column(msg.message).indent(2) << '\n';
        }
    }
    void printSourceInfo() const {
        Colour colourGuard(Colour::FileName);
        stream << result.getSourceInfo() << ": ";
    }

    std::ostream& stream;
    AssertionStats const& stats;
    AssertionResult const& result;
    Colour::Code colour;
    std::string passOrFail;
    std::string messageLabel;
    std::string message;
    std::vector<MessageInfo> messages;
    bool printInfoMessages;
};

std::size_t makeRatio(std::size_t number, std::size_t total) {
    std::size_t ratio = total > 0 ? CATCH_CONFIG_CONSOLE_WIDTH * number / total : 0;
    return (ratio == 0 && number > 0) ? 1 : ratio;
}

std::size_t& findMax(std::size_t& i, std::size_t& j, std::size_t& k) {
    if (i > j && i > k)
        return i;
    else if (j > k)
        return j;
    else
        return k;
}

enum class Justification { Left, Right };

struct ColumnInfo {
    std::string name;
    int width;
    Justification justification;
};
struct ColumnBreak {};
struct RowBreak {};

class Duration {
    enum class Unit {
        Auto,
        Nanoseconds,
        Microseconds,
        Milliseconds,
        Seconds,
        Minutes
    };
    static const uint64_t s_nanosecondsInAMicrosecond = 1000;
    static const uint64_t s_nanosecondsInAMillisecond = 1000 * s_nanosecondsInAMicrosecond;
    static const uint64_t s_nanosecondsInASecond = 1000 * s_nanosecondsInAMillisecond;
    static const uint64_t s_nanosecondsInAMinute = 60 * s_nanosecondsInASecond;

    double m_inNanoseconds;
    Unit m_units;

public:
    explicit Duration(double inNanoseconds, Unit units = Unit::Auto)
        : m_inNanoseconds(inNanoseconds),
        m_units(units) {
        if (m_units == Unit::Auto) {
            if (m_inNanoseconds < s_nanosecondsInAMicrosecond)
                m_units = Unit::Nanoseconds;
            else if (m_inNanoseconds < s_nanosecondsInAMillisecond)
                m_units = Unit::Microseconds;
            else if (m_inNanoseconds < s_nanosecondsInASecond)
                m_units = Unit::Milliseconds;
            else if (m_inNanoseconds < s_nanosecondsInAMinute)
                m_units = Unit::Seconds;
            else
                m_units = Unit::Minutes;
        }

    }

    auto value() const -> double {
        switch (m_units) {
        case Unit::Microseconds:
            return m_inNanoseconds / static_cast<double>(s_nanosecondsInAMicrosecond);
        case Unit::Milliseconds:
            return m_inNanoseconds / static_cast<double>(s_nanosecondsInAMillisecond);
        case Unit::Seconds:
            return m_inNanoseconds / static_cast<double>(s_nanosecondsInASecond);
        case Unit::Minutes:
            return m_inNanoseconds / static_cast<double>(s_nanosecondsInAMinute);
        default:
            return m_inNanoseconds;
        }
    }
    StringRef unitsAsString() const {
        switch (m_units) {
        case Unit::Nanoseconds:
            return "ns"_sr;
        case Unit::Microseconds:
            return "us"_sr;
        case Unit::Milliseconds:
            return "ms"_sr;
        case Unit::Seconds:
            return "s"_sr;
        case Unit::Minutes:
            return "m"_sr;
        default:
            return "** internal error **"_sr;
        }

    }
    friend auto operator << (std::ostream& os, Duration const& duration) -> std::ostream& {
        return os << duration.value() << ' ' << duration.unitsAsString();
    }
};
} // end anon namespace

class TablePrinter {
    std::ostream& m_os;
    std::vector<ColumnInfo> m_columnInfos;
    ReusableStringStream m_oss;
    int m_currentColumn = -1;
    bool m_isOpen = false;

public:
    TablePrinter( std::ostream& os, std::vector<ColumnInfo> columnInfos )
    :   m_os( os ),
        m_columnInfos( std::move( columnInfos ) ) {}

    auto columnInfos() const -> std::vector<ColumnInfo> const& {
        return m_columnInfos;
    }

    void open() {
        if (!m_isOpen) {
            m_isOpen = true;
            *this << RowBreak();

			TextFlow::Columns headerCols;
			auto spacer = TextFlow::Spacer(2);
			for (auto const& info : m_columnInfos) {
				headerCols += TextFlow::Column(info.name).width(static_cast<std::size_t>(info.width - 2));
				headerCols += spacer;
			}
			m_os << headerCols << '\n';

            m_os << lineOfChars('-') << '\n';
        }
    }
    void close() {
        if (m_isOpen) {
            *this << RowBreak();
            m_os << std::endl;
            m_isOpen = false;
        }
    }

    template<typename T>
    friend TablePrinter& operator << (TablePrinter& tp, T const& value) {
        tp.m_oss << value;
        return tp;
    }

    friend TablePrinter& operator << (TablePrinter& tp, ColumnBreak) {
        auto colStr = tp.m_oss.str();
        const auto strSize = colStr.size();
        tp.m_oss.str("");
        tp.open();
        if (tp.m_currentColumn == static_cast<int>(tp.m_columnInfos.size() - 1)) {
            tp.m_currentColumn = -1;
            tp.m_os << '\n';
        }
        tp.m_currentColumn++;

        auto colInfo = tp.m_columnInfos[tp.m_currentColumn];
        auto padding = (strSize + 1 < static_cast<std::size_t>(colInfo.width))
            ? std::string(colInfo.width - (strSize + 1), ' ')
            : std::string();
        if (colInfo.justification == Justification::Left)
            tp.m_os << colStr << padding << ' ';
        else
            tp.m_os << padding << colStr << ' ';
        return tp;
    }

    friend TablePrinter& operator << (TablePrinter& tp, RowBreak) {
        if (tp.m_currentColumn > 0) {
            tp.m_os << '\n';
            tp.m_currentColumn = -1;
        }
        return tp;
    }
};

ConsoleReporter::ConsoleReporter(ReporterConfig const& config)
    : StreamingReporterBase(config),
    m_tablePrinter(new TablePrinter(config.stream(),
        [&config]() -> std::vector<ColumnInfo> {
        if (config.fullConfig()->benchmarkNoAnalysis())
        {
            return{
                { "benchmark name", CATCH_CONFIG_CONSOLE_WIDTH - 43, Justification::Left },
                { "     samples", 14, Justification::Right },
                { "  iterations", 14, Justification::Right },
                { "        mean", 14, Justification::Right }
            };
        }
        else
        {
            return{
                { "benchmark name", CATCH_CONFIG_CONSOLE_WIDTH - 43, Justification::Left },
                { "samples      mean       std dev", 14, Justification::Right },
                { "iterations   low mean   low std dev", 14, Justification::Right },
                { "estimated    high mean  high std dev", 14, Justification::Right }
            };
        }
    }())) {}
ConsoleReporter::~ConsoleReporter() = default;

std::string ConsoleReporter::getDescription() {
    return "Reports test results as plain lines of text";
}

void ConsoleReporter::noMatchingTestCases(std::string const& spec) {
    stream << "No test cases matched '" << spec << '\'' << std::endl;
}

void ConsoleReporter::reportInvalidArguments(std::string const&arg){
    stream << "Invalid Filter: " << arg << std::endl;
}

void ConsoleReporter::assertionStarting(AssertionInfo const&) {}

bool ConsoleReporter::assertionEnded(AssertionStats const& _assertionStats) {
    AssertionResult const& result = _assertionStats.assertionResult;

    bool includeResults = m_config->includeSuccessfulResults() || !result.isOk();

    // Drop out if result was successful but we're not printing them.
    if (!includeResults && result.getResultType() != ResultWas::Warning)
        return false;

    lazyPrint();

    ConsoleAssertionPrinter printer(stream, _assertionStats, includeResults);
    printer.print();
    stream << std::endl;
    return true;
}

void ConsoleReporter::sectionStarting(SectionInfo const& _sectionInfo) {
    m_tablePrinter->close();
    m_headerPrinted = false;
    StreamingReporterBase::sectionStarting(_sectionInfo);
}
void ConsoleReporter::sectionEnded(SectionStats const& _sectionStats) {
    m_tablePrinter->close();
    if (_sectionStats.missingAssertions) {
        lazyPrint();
        Colour colour(Colour::ResultError);
        if (m_sectionStack.size() > 1)
            stream << "\nNo assertions in section";
        else
            stream << "\nNo assertions in test case";
        stream << " '" << _sectionStats.sectionInfo.name << "'\n" << std::endl;
    }
    double dur = _sectionStats.durationInSeconds;
    if (shouldShowDuration(*m_config, dur)) {
        stream << getFormattedDuration(dur) << " s: " << _sectionStats.sectionInfo.name << std::endl;
    }
    if (m_headerPrinted) {
        m_headerPrinted = false;
    }
    StreamingReporterBase::sectionEnded(_sectionStats);
}

void ConsoleReporter::benchmarkPreparing(std::string const& name) {
	lazyPrintWithoutClosingBenchmarkTable();

	auto nameCol = TextFlow::Column(name).width(static_cast<std::size_t>(m_tablePrinter->columnInfos()[0].width - 2));

	bool firstLine = true;
	for (auto line : nameCol) {
		if (!firstLine)
			(*m_tablePrinter) << ColumnBreak() << ColumnBreak() << ColumnBreak();
		else
			firstLine = false;

		(*m_tablePrinter) << line << ColumnBreak();
	}
}

void ConsoleReporter::benchmarkStarting(BenchmarkInfo const& info) {
    (*m_tablePrinter) << info.samples << ColumnBreak()
        << info.iterations << ColumnBreak();
    if (!m_config->benchmarkNoAnalysis())
        (*m_tablePrinter) << Duration(info.estimatedDuration) << ColumnBreak();
}
void ConsoleReporter::benchmarkEnded(BenchmarkStats<> const& stats) {
    if (m_config->benchmarkNoAnalysis())
    {
        (*m_tablePrinter) << Duration(stats.mean.point.count()) << ColumnBreak();
    }
    else
    {
        (*m_tablePrinter) << ColumnBreak()
            << Duration(stats.mean.point.count()) << ColumnBreak()
            << Duration(stats.mean.lower_bound.count()) << ColumnBreak()
            << Duration(stats.mean.upper_bound.count()) << ColumnBreak() << ColumnBreak()
            << Duration(stats.standardDeviation.point.count()) << ColumnBreak()
            << Duration(stats.standardDeviation.lower_bound.count()) << ColumnBreak()
            << Duration(stats.standardDeviation.upper_bound.count()) << ColumnBreak() << ColumnBreak() << ColumnBreak() << ColumnBreak() << ColumnBreak();
    }
}

void ConsoleReporter::benchmarkFailed(std::string const& error) {
	Colour colour(Colour::Red);
    (*m_tablePrinter)
        << "Benchmark failed (" << error << ')'
        << ColumnBreak() << RowBreak();
}

void ConsoleReporter::testCaseEnded(TestCaseStats const& _testCaseStats) {
    m_tablePrinter->close();
    StreamingReporterBase::testCaseEnded(_testCaseStats);
    m_headerPrinted = false;
}
void ConsoleReporter::testGroupEnded(TestGroupStats const& _testGroupStats) {
    if (currentGroupInfo.used) {
        printSummaryDivider();
        stream << "Summary for group '" << _testGroupStats.groupInfo.name << "':\n";
        printTotals(_testGroupStats.totals);
        stream << '\n' << std::endl;
    }
    StreamingReporterBase::testGroupEnded(_testGroupStats);
}
void ConsoleReporter::testRunEnded(TestRunStats const& _testRunStats) {
    printTotalsDivider(_testRunStats.totals);
    printTotals(_testRunStats.totals);
    stream << std::endl;
    StreamingReporterBase::testRunEnded(_testRunStats);
}
void ConsoleReporter::testRunStarting(TestRunInfo const& _testInfo) {
    StreamingReporterBase::testRunStarting(_testInfo);
    printTestFilters();
}

void ConsoleReporter::lazyPrint() {

    m_tablePrinter->close();
    lazyPrintWithoutClosingBenchmarkTable();
}

void ConsoleReporter::lazyPrintWithoutClosingBenchmarkTable() {

    if (!currentTestRunInfo.used)
        lazyPrintRunInfo();
    if (!currentGroupInfo.used)
        lazyPrintGroupInfo();

    if (!m_headerPrinted) {
        printTestCaseAndSectionHeader();
        m_headerPrinted = true;
    }
}
void ConsoleReporter::lazyPrintRunInfo() {
    stream << '\n' << lineOfChars('~') << '\n';
    Colour colour(Colour::SecondaryText);
    stream << currentTestRunInfo->name
        << " is a Catch v" << libraryVersion() << " host application.\n"
        << "Run with -? for options\n\n";

    if (m_config->rngSeed() != 0)
        stream << "Randomness seeded to: " << m_config->rngSeed() << "\n\n";

    currentTestRunInfo.used = true;
}
void ConsoleReporter::lazyPrintGroupInfo() {
    if (!currentGroupInfo->name.empty() && currentGroupInfo->groupsCounts > 1) {
        printClosedHeader("Group: " + currentGroupInfo->name);
        currentGroupInfo.used = true;
    }
}
void ConsoleReporter::printTestCaseAndSectionHeader() {
    assert(!m_sectionStack.empty());
    printOpenHeader(currentTestCaseInfo->name);

    if (m_sectionStack.size() > 1) {
        Colour colourGuard(Colour::Headers);

        auto
            it = m_sectionStack.begin() + 1, // Skip first section (test case)
            itEnd = m_sectionStack.end();
        for (; it != itEnd; ++it)
            printHeaderString(it->name, 2);
    }

    SourceLineInfo lineInfo = m_sectionStack.back().lineInfo;


    stream << lineOfChars('-') << '\n';
    Colour colourGuard(Colour::FileName);
    stream << lineInfo << '\n';
    stream << lineOfChars('.') << '\n' << std::endl;
}

void ConsoleReporter::printClosedHeader(std::string const& _name) {
    printOpenHeader(_name);
    stream << lineOfChars('.') << '\n';
}
void ConsoleReporter::printOpenHeader(std::string const& _name) {
    stream << lineOfChars('-') << '\n';
    {
        Colour colourGuard(Colour::Headers);
        printHeaderString(_name);
    }
}

// if string has a : in first line will set indent to follow it on
// subsequent lines
void ConsoleReporter::printHeaderString(std::string const& _string, std::size_t indent) {
    std::size_t i = _string.find(": ");
    if (i != std::string::npos)
        i += 2;
    else
        i = 0;
    stream << TextFlow::Column(_string).indent(indent + i).initialIndent(indent) << '\n';
}

struct SummaryColumn {

    SummaryColumn( std::string _label, Colour::Code _colour )
    :   label( std::move( _label ) ),
        colour( _colour ) {}
    SummaryColumn addRow( std::size_t count ) {
        ReusableStringStream rss;
        rss << count;
        std::string row = rss.str();
        for (auto& oldRow : rows) {
            while (oldRow.size() < row.size())
                oldRow = ' ' + oldRow;
            while (oldRow.size() > row.size())
                row = ' ' + row;
        }
        rows.push_back(row);
        return *this;
    }

    std::string label;
    Colour::Code colour;
    std::vector<std::string> rows;

};

void ConsoleReporter::printTotals( Totals const& totals ) {
    if (totals.testCases.total() == 0) {
        stream << Colour(Colour::Warning) << "No tests ran\n";
    } else if (totals.assertions.total() > 0 && totals.testCases.allPassed()) {
        stream << Colour(Colour::ResultSuccess) << "All tests passed";
        stream << " ("
            << pluralise(totals.assertions.passed, "assertion") << " in "
            << pluralise(totals.testCases.passed, "test case") << ')'
            << '\n';
    } else {

        std::vector<SummaryColumn> columns;
        columns.push_back(SummaryColumn("", Colour::None)
                          .addRow(totals.testCases.total())
                          .addRow(totals.assertions.total()));
        columns.push_back(SummaryColumn("passed", Colour::Success)
                          .addRow(totals.testCases.passed)
                          .addRow(totals.assertions.passed));
        columns.push_back(SummaryColumn("failed", Colour::ResultError)
                          .addRow(totals.testCases.failed)
                          .addRow(totals.assertions.failed));
        columns.push_back(SummaryColumn("failed as expected", Colour::ResultExpectedFailure)
                          .addRow(totals.testCases.failedButOk)
                          .addRow(totals.assertions.failedButOk));

        printSummaryRow("test cases", columns, 0);
        printSummaryRow("assertions", columns, 1);
    }
}
void ConsoleReporter::printSummaryRow(std::string const& label, std::vector<SummaryColumn> const& cols, std::size_t row) {
    for (auto col : cols) {
        std::string value = col.rows[row];
        if (col.label.empty()) {
            stream << label << ": ";
            if (value != "0")
                stream << value;
            else
                stream << Colour(Colour::Warning) << "- none -";
        } else if (value != "0") {
            stream << Colour(Colour::LightGrey) << " | ";
            stream << Colour(col.colour)
                << value << ' ' << col.label;
        }
    }
    stream << '\n';
}

void ConsoleReporter::printTotalsDivider(Totals const& totals) {
    if (totals.testCases.total() > 0) {
        std::size_t failedRatio = makeRatio(totals.testCases.failed, totals.testCases.total());
        std::size_t failedButOkRatio = makeRatio(totals.testCases.failedButOk, totals.testCases.total());
        std::size_t passedRatio = makeRatio(totals.testCases.passed, totals.testCases.total());
        while (failedRatio + failedButOkRatio + passedRatio < CATCH_CONFIG_CONSOLE_WIDTH - 1)
            findMax(failedRatio, failedButOkRatio, passedRatio)++;
        while (failedRatio + failedButOkRatio + passedRatio > CATCH_CONFIG_CONSOLE_WIDTH - 1)
            findMax(failedRatio, failedButOkRatio, passedRatio)--;

        stream << Colour(Colour::Error) << std::string(failedRatio, '=');
        stream << Colour(Colour::ResultExpectedFailure) << std::string(failedButOkRatio, '=');
        if (totals.testCases.allPassed())
            stream << Colour(Colour::ResultSuccess) << std::string(passedRatio, '=');
        else
            stream << Colour(Colour::Success) << std::string(passedRatio, '=');
    } else {
        stream << Colour(Colour::Warning) << std::string(CATCH_CONFIG_CONSOLE_WIDTH - 1, '=');
    }
    stream << '\n';
}
void ConsoleReporter::printSummaryDivider() {
    stream << lineOfChars('-') << '\n';
}

void ConsoleReporter::printTestFilters() {
    if (m_config->testSpec().hasFilters()) {
        Colour guard(Colour::BrightYellow);
        stream << "Filters: " << serializeFilters(m_config->getTestsOrTags()) << '\n';
    }
}

} // end namespace Catch

#if defined(_MSC_VER)
#pragma warning(pop)
#endif

#if defined(__clang__)
#  pragma clang diagnostic pop
#endif



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




#include <cassert>
#include <ctime>
#include <algorithm>

namespace Catch {

    namespace {
        std::string getCurrentTimestamp() {
            // Beware, this is not reentrant because of backward compatibility issues
            // Also, UTC only, again because of backward compatibility (%z is C++11)
            time_t rawtime;
            std::time(&rawtime);
            auto const timeStampSize = sizeof("2017-01-16T17:06:45Z");

#ifdef _MSC_VER
            std::tm timeInfo = {};
            gmtime_s(&timeInfo, &rawtime);
#else
            std::tm* timeInfo;
            timeInfo = std::gmtime(&rawtime);
#endif

            char timeStamp[timeStampSize];
            const char * const fmt = "%Y-%m-%dT%H:%M:%SZ";

#ifdef _MSC_VER
            std::strftime(timeStamp, timeStampSize, fmt, &timeInfo);
#else
            std::strftime(timeStamp, timeStampSize, fmt, timeInfo);
#endif
            return std::string(timeStamp);
        }

        std::string fileNameTag(std::vector<Tag> const& tags) {
            auto it = std::find_if(begin(tags),
                                   end(tags),
                                   [] (Tag const& tag) {
                                       return tag.original.size() > 0
                                           && tag.original[0] == '#'; });
            if (it != tags.end()) {
                return static_cast<std::string>(
                    it->original.substr(1, it->original.size() - 1)
                );
            }
            return std::string();
        }
    } // anonymous namespace

    JunitReporter::JunitReporter( ReporterConfig const& _config )
        :   CumulativeReporterBase( _config ),
            xml( _config.stream() )
        {
            m_preferences.shouldRedirectStdOut = true;
            m_preferences.shouldReportAllAssertions = true;
        }

    JunitReporter::~JunitReporter() {}

    std::string JunitReporter::getDescription() {
        return "Reports test results in an XML format that looks like Ant's junitreport target";
    }

    void JunitReporter::noMatchingTestCases( std::string const& /*spec*/ ) {}

    void JunitReporter::testRunStarting( TestRunInfo const& runInfo )  {
        CumulativeReporterBase::testRunStarting( runInfo );
        xml.startElement( "testsuites" );
    }

    void JunitReporter::testGroupStarting( GroupInfo const& groupInfo ) {
        suiteTimer.start();
        stdOutForSuite.clear();
        stdErrForSuite.clear();
        unexpectedExceptions = 0;
        CumulativeReporterBase::testGroupStarting( groupInfo );
    }

    void JunitReporter::testCaseStarting( TestCaseInfo const& testCaseInfo ) {
        m_okToFail = testCaseInfo.okToFail();
    }

    bool JunitReporter::assertionEnded( AssertionStats const& assertionStats ) {
        if( assertionStats.assertionResult.getResultType() == ResultWas::ThrewException && !m_okToFail )
            unexpectedExceptions++;
        return CumulativeReporterBase::assertionEnded( assertionStats );
    }

    void JunitReporter::testCaseEnded( TestCaseStats const& testCaseStats ) {
        stdOutForSuite += testCaseStats.stdOut;
        stdErrForSuite += testCaseStats.stdErr;
        CumulativeReporterBase::testCaseEnded( testCaseStats );
    }

    void JunitReporter::testGroupEnded( TestGroupStats const& testGroupStats ) {
        double suiteTime = suiteTimer.getElapsedSeconds();
        CumulativeReporterBase::testGroupEnded( testGroupStats );
        writeGroup( *m_testGroups.back(), suiteTime );
    }

    void JunitReporter::testRunEndedCumulative() {
        xml.endElement();
    }

    void JunitReporter::writeGroup( TestGroupNode const& groupNode, double suiteTime ) {
        XmlWriter::ScopedElement e = xml.scopedElement( "testsuite" );

        TestGroupStats const& stats = groupNode.value;
        xml.writeAttribute( "name", stats.groupInfo.name );
        xml.writeAttribute( "errors", unexpectedExceptions );
        xml.writeAttribute( "failures", stats.totals.assertions.failed-unexpectedExceptions );
        xml.writeAttribute( "tests", stats.totals.assertions.total() );
        xml.writeAttribute( "hostname", "tbd" ); // !TBD
        if( m_config->showDurations() == ShowDurations::Never )
            xml.writeAttribute( "time", "" );
        else
            xml.writeAttribute( "time", suiteTime );
        xml.writeAttribute( "timestamp", getCurrentTimestamp() );

        // Write properties if there are any
        if (m_config->hasTestFilters() || m_config->rngSeed() != 0) {
            auto properties = xml.scopedElement("properties");
            if (m_config->hasTestFilters()) {
                xml.scopedElement("property")
                    .writeAttribute("name", "filters")
                    .writeAttribute("value", serializeFilters(m_config->getTestsOrTags()));
            }
            if (m_config->rngSeed() != 0) {
                xml.scopedElement("property")
                    .writeAttribute("name", "random-seed")
                    .writeAttribute("value", m_config->rngSeed());
            }
        }

        // Write test cases
        for( auto const& child : groupNode.children )
            writeTestCase( *child );

        xml.scopedElement( "system-out" ).writeText( trim( stdOutForSuite ), XmlFormatting::Newline );
        xml.scopedElement( "system-err" ).writeText( trim( stdErrForSuite ), XmlFormatting::Newline );
    }

    void JunitReporter::writeTestCase( TestCaseNode const& testCaseNode ) {
        TestCaseStats const& stats = testCaseNode.value;

        // All test cases have exactly one section - which represents the
        // test case itself. That section may have 0-n nested sections
        assert( testCaseNode.children.size() == 1 );
        SectionNode const& rootSection = *testCaseNode.children.front();

        std::string className = stats.testInfo->className;

        if( className.empty() ) {
            className = fileNameTag(stats.testInfo->tags);
            if ( className.empty() )
                className = "global";
        }

        if ( !m_config->name().empty() )
            className = m_config->name() + "." + className;

        writeSection( className, "", rootSection );
    }

    void JunitReporter::writeSection(  std::string const& className,
                        std::string const& rootName,
                        SectionNode const& sectionNode ) {
        std::string name = trim( sectionNode.stats.sectionInfo.name );
        if( !rootName.empty() )
            name = rootName + '/' + name;

        if( !sectionNode.assertions.empty() ||
            !sectionNode.stdOut.empty() ||
            !sectionNode.stdErr.empty() ) {
            XmlWriter::ScopedElement e = xml.scopedElement( "testcase" );
            if( className.empty() ) {
                xml.writeAttribute( "classname", name );
                xml.writeAttribute( "name", "root" );
            }
            else {
                xml.writeAttribute( "classname", className );
                xml.writeAttribute( "name", name );
            }
            xml.writeAttribute( "time", ::Catch::Detail::stringify( sectionNode.stats.durationInSeconds ) );
            // This is not ideal, but it should be enough to mimic gtest's
            // junit output.
            // Ideally the JUnit reporter would also handle `skipTest`
            // events and write those out appropriately.
            xml.writeAttribute( "status", "run" );

            writeAssertions( sectionNode );

            if( !sectionNode.stdOut.empty() )
                xml.scopedElement( "system-out" ).writeText( trim( sectionNode.stdOut ), XmlFormatting::Newline );
            if( !sectionNode.stdErr.empty() )
                xml.scopedElement( "system-err" ).writeText( trim( sectionNode.stdErr ), XmlFormatting::Newline );
        }
        for( auto const& childNode : sectionNode.childSections )
            if( className.empty() )
                writeSection( name, "", *childNode );
            else
                writeSection( className, name, *childNode );
    }

    void JunitReporter::writeAssertions( SectionNode const& sectionNode ) {
        for( auto const& assertion : sectionNode.assertions )
            writeAssertion( assertion );
    }

    void JunitReporter::writeAssertion( AssertionStats const& stats ) {
        AssertionResult const& result = stats.assertionResult;
        if( !result.isOk() ) {
            std::string elementName;
            switch( result.getResultType() ) {
                case ResultWas::ThrewException:
                case ResultWas::FatalErrorCondition:
                    elementName = "error";
                    break;
                case ResultWas::ExplicitFailure:
                case ResultWas::ExpressionFailed:
                case ResultWas::DidntThrowException:
                    elementName = "failure";
                    break;

                // We should never see these here:
                case ResultWas::Info:
                case ResultWas::Warning:
                case ResultWas::Ok:
                case ResultWas::Unknown:
                case ResultWas::FailureBit:
                case ResultWas::Exception:
                    elementName = "internalError";
                    break;
            }

            XmlWriter::ScopedElement e = xml.scopedElement( elementName );

            xml.writeAttribute( "message", result.getExpression() );
            xml.writeAttribute( "type", result.getTestMacroName() );

            ReusableStringStream rss;
            if (stats.totals.assertions.total() > 0) {
                rss << "FAILED" << ":\n";
                if (result.hasExpression()) {
                    rss << "  ";
                    rss << result.getExpressionInMacro();
                    rss << '\n';
                }
                if (result.hasExpandedExpression()) {
                    rss << "with expansion:\n";
                    rss << TextFlow::Column(result.getExpandedExpression()).indent(2) << '\n';
                }
            } else {
                rss << '\n';
            }

            if( !result.getMessage().empty() )
                rss << result.getMessage() << '\n';
            for( auto const& msg : stats.infoMessages )
                if( msg.type == ResultWas::Info )
                    rss << msg.message << '\n';

            rss << "at " << result.getSourceInfo();
            xml.writeText( rss.str(), XmlFormatting::Newline );
        }
    }

} // end namespace Catch



#include <cassert>

namespace Catch {

    ListeningReporter::ListeningReporter() {
        // We will assume that listeners will always want all assertions
        m_preferences.shouldReportAllAssertions = true;
    }

    void ListeningReporter::addListener( IStreamingReporterPtr&& listener ) {
        m_listeners.push_back( std::move( listener ) );
    }

    void ListeningReporter::addReporter(IStreamingReporterPtr&& reporter) {
        assert(!m_reporter && "Listening reporter can wrap only 1 real reporter");
        m_reporter = std::move( reporter );
        m_preferences.shouldRedirectStdOut = m_reporter->getPreferences().shouldRedirectStdOut;
    }

    void ListeningReporter::noMatchingTestCases( std::string const& spec ) {
        for ( auto const& listener : m_listeners ) {
            listener->noMatchingTestCases( spec );
        }
        m_reporter->noMatchingTestCases( spec );
    }

    void ListeningReporter::reportInvalidArguments(std::string const&arg){
        for ( auto const& listener : m_listeners ) {
            listener->reportInvalidArguments( arg );
        }
        m_reporter->reportInvalidArguments( arg );
    }

    void ListeningReporter::benchmarkPreparing( std::string const& name ) {
        for (auto const& listener : m_listeners) {
            listener->benchmarkPreparing(name);
        }
        m_reporter->benchmarkPreparing(name);
    }
    void ListeningReporter::benchmarkStarting( BenchmarkInfo const& benchmarkInfo ) {
        for ( auto const& listener : m_listeners ) {
            listener->benchmarkStarting( benchmarkInfo );
        }
        m_reporter->benchmarkStarting( benchmarkInfo );
    }
    void ListeningReporter::benchmarkEnded( BenchmarkStats<> const& benchmarkStats ) {
        for ( auto const& listener : m_listeners ) {
            listener->benchmarkEnded( benchmarkStats );
        }
        m_reporter->benchmarkEnded( benchmarkStats );
    }

    void ListeningReporter::benchmarkFailed( std::string const& error ) {
        for (auto const& listener : m_listeners) {
            listener->benchmarkFailed(error);
        }
        m_reporter->benchmarkFailed(error);
    }

    void ListeningReporter::testRunStarting( TestRunInfo const& testRunInfo ) {
        for ( auto const& listener : m_listeners ) {
            listener->testRunStarting( testRunInfo );
        }
        m_reporter->testRunStarting( testRunInfo );
    }

    void ListeningReporter::testGroupStarting( GroupInfo const& groupInfo ) {
        for ( auto const& listener : m_listeners ) {
            listener->testGroupStarting( groupInfo );
        }
        m_reporter->testGroupStarting( groupInfo );
    }


    void ListeningReporter::testCaseStarting( TestCaseInfo const& testInfo ) {
        for ( auto const& listener : m_listeners ) {
            listener->testCaseStarting( testInfo );
        }
        m_reporter->testCaseStarting( testInfo );
    }

    void ListeningReporter::sectionStarting( SectionInfo const& sectionInfo ) {
        for ( auto const& listener : m_listeners ) {
            listener->sectionStarting( sectionInfo );
        }
        m_reporter->sectionStarting( sectionInfo );
    }

    void ListeningReporter::assertionStarting( AssertionInfo const& assertionInfo ) {
        for ( auto const& listener : m_listeners ) {
            listener->assertionStarting( assertionInfo );
        }
        m_reporter->assertionStarting( assertionInfo );
    }

    // The return value indicates if the messages buffer should be cleared:
    bool ListeningReporter::assertionEnded( AssertionStats const& assertionStats ) {
        for( auto const& listener : m_listeners ) {
            static_cast<void>( listener->assertionEnded( assertionStats ) );
        }
        return m_reporter->assertionEnded( assertionStats );
    }

    void ListeningReporter::sectionEnded( SectionStats const& sectionStats ) {
        for ( auto const& listener : m_listeners ) {
            listener->sectionEnded( sectionStats );
        }
        m_reporter->sectionEnded( sectionStats );
    }

    void ListeningReporter::testCaseEnded( TestCaseStats const& testCaseStats ) {
        for ( auto const& listener : m_listeners ) {
            listener->testCaseEnded( testCaseStats );
        }
        m_reporter->testCaseEnded( testCaseStats );
    }

    void ListeningReporter::testGroupEnded( TestGroupStats const& testGroupStats ) {
        for ( auto const& listener : m_listeners ) {
            listener->testGroupEnded( testGroupStats );
        }
        m_reporter->testGroupEnded( testGroupStats );
    }

    void ListeningReporter::testRunEnded( TestRunStats const& testRunStats ) {
        for ( auto const& listener : m_listeners ) {
            listener->testRunEnded( testRunStats );
        }
        m_reporter->testRunEnded( testRunStats );
    }


    void ListeningReporter::skipTest( TestCaseInfo const& testInfo ) {
        for ( auto const& listener : m_listeners ) {
            listener->skipTest( testInfo );
        }
        m_reporter->skipTest( testInfo );
    }

    void ListeningReporter::listReporters(std::vector<ReporterDescription> const& descriptions, IConfig const& config) {
        for (auto const& listener : m_listeners) {
            listener->listReporters(descriptions, config);
        }
        m_reporter->listReporters(descriptions, config);
    }

    void ListeningReporter::listTests(std::vector<TestCaseHandle> const& tests, IConfig const& config) {
        for (auto const& listener : m_listeners) {
            listener->listTests(tests, config);
        }
        m_reporter->listTests(tests, config);
    }

    void ListeningReporter::listTags(std::vector<TagInfo> const& tags, IConfig const& config) {
        for (auto const& listener : m_listeners) {
            listener->listTags(tags, config);
        }
        m_reporter->listTags(tags, config);
    }

} // end namespace Catch




#include <map>

namespace Catch {

    SonarQubeReporter::~SonarQubeReporter() {}

    void SonarQubeReporter::testRunStarting(TestRunInfo const& testRunInfo) {
        CumulativeReporterBase::testRunStarting(testRunInfo);
        xml.startElement("testExecutions");
        xml.writeAttribute("version", '1');
    }

    void SonarQubeReporter::testGroupEnded(TestGroupStats const& testGroupStats) {
        CumulativeReporterBase::testGroupEnded(testGroupStats);
        writeGroup(*m_testGroups.back());
    }

    void SonarQubeReporter::writeGroup(TestGroupNode const& groupNode) {
        std::map<std::string, TestGroupNode::ChildNodes> testsPerFile;
        for (auto const& child : groupNode.children)
            testsPerFile[child->value.testInfo->lineInfo.file].push_back(child);

        for (auto const& kv : testsPerFile)
            writeTestFile(kv.first, kv.second);
    }

    void SonarQubeReporter::writeTestFile(std::string const& filename, TestGroupNode::ChildNodes const& testCaseNodes) {
        XmlWriter::ScopedElement e = xml.scopedElement("file");
        xml.writeAttribute("path", filename);

        for (auto const& child : testCaseNodes)
            writeTestCase(*child);
    }

    void SonarQubeReporter::writeTestCase(TestCaseNode const& testCaseNode) {
        // All test cases have exactly one section - which represents the
        // test case itself. That section may have 0-n nested sections
        assert(testCaseNode.children.size() == 1);
        SectionNode const& rootSection = *testCaseNode.children.front();
        writeSection("", rootSection, testCaseNode.value.testInfo->okToFail());
    }

    void SonarQubeReporter::writeSection(std::string const& rootName, SectionNode const& sectionNode, bool okToFail) {
        std::string name = trim(sectionNode.stats.sectionInfo.name);
        if (!rootName.empty())
            name = rootName + '/' + name;

        if (!sectionNode.assertions.empty() || !sectionNode.stdOut.empty() || !sectionNode.stdErr.empty()) {
            XmlWriter::ScopedElement e = xml.scopedElement("testCase");
            xml.writeAttribute("name", name);
            xml.writeAttribute("duration", static_cast<long>(sectionNode.stats.durationInSeconds * 1000));

            writeAssertions(sectionNode, okToFail);
        }

        for (auto const& childNode : sectionNode.childSections)
            writeSection(name, *childNode, okToFail);
    }

    void SonarQubeReporter::writeAssertions(SectionNode const& sectionNode, bool okToFail) {
        for (auto const& assertion : sectionNode.assertions)
            writeAssertion(assertion, okToFail);
    }

    void SonarQubeReporter::writeAssertion(AssertionStats const& stats, bool okToFail) {
        AssertionResult const& result = stats.assertionResult;
        if (!result.isOk()) {
            std::string elementName;
            if (okToFail) {
                elementName = "skipped";
            } else {
                switch (result.getResultType()) {
                case ResultWas::ThrewException:
                case ResultWas::FatalErrorCondition:
                    elementName = "error";
                    break;
                case ResultWas::ExplicitFailure:
                    elementName = "failure";
                    break;
                case ResultWas::ExpressionFailed:
                    elementName = "failure";
                    break;
                case ResultWas::DidntThrowException:
                    elementName = "failure";
                    break;

                    // We should never see these here:
                case ResultWas::Info:
                case ResultWas::Warning:
                case ResultWas::Ok:
                case ResultWas::Unknown:
                case ResultWas::FailureBit:
                case ResultWas::Exception:
                    elementName = "internalError";
                    break;
                }
            }

            XmlWriter::ScopedElement e = xml.scopedElement(elementName);

            ReusableStringStream messageRss;
            messageRss << result.getTestMacroName() << "(" << result.getExpression() << ")";
            xml.writeAttribute("message", messageRss.str());

            ReusableStringStream textRss;
            if (stats.totals.assertions.total() > 0) {
                textRss << "FAILED:\n";
                if (result.hasExpression()) {
                    textRss << "\t" << result.getExpressionInMacro() << "\n";
                }
                if (result.hasExpandedExpression()) {
                    textRss << "with expansion:\n\t" << result.getExpandedExpression() << "\n";
                }
            }

            if (!result.getMessage().empty())
                textRss << result.getMessage() << "\n";

            for (auto const& msg : stats.infoMessages)
                if (msg.type == ResultWas::Info)
                    textRss << msg.message << "\n";

            textRss << "at " << result.getSourceInfo();
            xml.writeText(textRss.str(), XmlFormatting::Newline);
        }
    }

} // end namespace Catch



namespace Catch {

    StreamingReporterBase::~StreamingReporterBase() = default;

    void
    StreamingReporterBase::testRunStarting( TestRunInfo const& _testRunInfo ) {
        currentTestRunInfo = _testRunInfo;
    }

    void
    StreamingReporterBase::testGroupStarting( GroupInfo const& _groupInfo ) {
        currentGroupInfo = _groupInfo;
    }

    void StreamingReporterBase::testGroupEnded( TestGroupStats const& ) {
        currentGroupInfo.reset();
    }

    void StreamingReporterBase::testRunEnded( TestRunStats const& ) {
        currentTestCaseInfo = nullptr;
        currentGroupInfo.reset();
        currentTestRunInfo.reset();
    }

} // end namespace Catch



#include <algorithm>
#include <ostream>

namespace Catch {

    namespace {
        // Yes, this has to be outside the class and namespaced by naming.
        // Making older compiler happy is hard.
        static constexpr StringRef tapFailedString = "not ok"_sr;
        static constexpr StringRef tapPassedString = "ok"_sr;

        class TapAssertionPrinter {
        public:
            TapAssertionPrinter& operator= (TapAssertionPrinter const&) = delete;
            TapAssertionPrinter(TapAssertionPrinter const&) = delete;
            TapAssertionPrinter(std::ostream& _stream, AssertionStats const& _stats, std::size_t _counter)
                : stream(_stream)
                , result(_stats.assertionResult)
                , messages(_stats.infoMessages)
                , itMessage(_stats.infoMessages.begin())
                , printInfoMessages(true)
                , counter(_counter) {}

            void print() {
                itMessage = messages.begin();

                switch (result.getResultType()) {
                case ResultWas::Ok:
                    printResultType(tapPassedString);
                    printOriginalExpression();
                    printReconstructedExpression();
                    if (!result.hasExpression())
                        printRemainingMessages(Colour::None);
                    else
                        printRemainingMessages();
                    break;
                case ResultWas::ExpressionFailed:
                    if (result.isOk()) {
                        printResultType(tapPassedString);
                    } else {
                        printResultType(tapFailedString);
                    }
                    printOriginalExpression();
                    printReconstructedExpression();
                    if (result.isOk()) {
                        printIssue(" # TODO");
                    }
                    printRemainingMessages();
                    break;
                case ResultWas::ThrewException:
                    printResultType(tapFailedString);
                    printIssue("unexpected exception with message:"_sr);
                    printMessage();
                    printExpressionWas();
                    printRemainingMessages();
                    break;
                case ResultWas::FatalErrorCondition:
                    printResultType(tapFailedString);
                    printIssue("fatal error condition with message:"_sr);
                    printMessage();
                    printExpressionWas();
                    printRemainingMessages();
                    break;
                case ResultWas::DidntThrowException:
                    printResultType(tapFailedString);
                    printIssue("expected exception, got none"_sr);
                    printExpressionWas();
                    printRemainingMessages();
                    break;
                case ResultWas::Info:
                    printResultType("info"_sr);
                    printMessage();
                    printRemainingMessages();
                    break;
                case ResultWas::Warning:
                    printResultType("warning"_sr);
                    printMessage();
                    printRemainingMessages();
                    break;
                case ResultWas::ExplicitFailure:
                    printResultType(tapFailedString);
                    printIssue("explicitly"_sr);
                    printRemainingMessages(Colour::None);
                    break;
                    // These cases are here to prevent compiler warnings
                case ResultWas::Unknown:
                case ResultWas::FailureBit:
                case ResultWas::Exception:
                    printResultType("** internal error **"_sr);
                    break;
                }
            }

        private:
            static Colour::Code dimColour() { return Colour::FileName; }

            void printSourceInfo() const {
                Colour colourGuard(dimColour());
                stream << result.getSourceInfo() << ':';
            }

            void printResultType(StringRef passOrFail) const {
                if (!passOrFail.empty()) {
                    stream << passOrFail << ' ' << counter << " -";
                }
            }

            void printIssue(StringRef issue) const {
                stream << ' ' << issue;
            }

            void printExpressionWas() {
                if (result.hasExpression()) {
                    stream << ';';
                    {
                        Colour colour(dimColour());
                        stream << " expression was:";
                    }
                    printOriginalExpression();
                }
            }

            void printOriginalExpression() const {
                if (result.hasExpression()) {
                    stream << ' ' << result.getExpression();
                }
            }

            void printReconstructedExpression() const {
                if (result.hasExpandedExpression()) {
                    {
                        Colour colour(dimColour());
                        stream << " for: ";
                    }
                    std::string expr = result.getExpandedExpression();
                    std::replace(expr.begin(), expr.end(), '\n', ' ');
                    stream << expr;
                }
            }

            void printMessage() {
                if (itMessage != messages.end()) {
                    stream << " '" << itMessage->message << '\'';
                    ++itMessage;
                }
            }

            void printRemainingMessages(Colour::Code colour = dimColour()) {
                if (itMessage == messages.end()) {
                    return;
                }

                // using messages.end() directly (or auto) yields compilation error:
                std::vector<MessageInfo>::const_iterator itEnd = messages.end();
                const std::size_t N = static_cast<std::size_t>(std::distance(itMessage, itEnd));

                {
                    Colour colourGuard(colour);
                    stream << " with " << pluralise(N, "message") << ':';
                }

                for (; itMessage != itEnd; ) {
                    // If this assertion is a warning ignore any INFO messages
                    if (printInfoMessages || itMessage->type != ResultWas::Info) {
                        stream << " '" << itMessage->message << '\'';
                        if (++itMessage != itEnd) {
                            Colour colourGuard(dimColour());
                            stream << " and";
                        }
                    }
                }
            }

        private:
            std::ostream& stream;
            AssertionResult const& result;
            std::vector<MessageInfo> messages;
            std::vector<MessageInfo>::const_iterator itMessage;
            bool printInfoMessages;
            std::size_t counter;
        };

    } // End anonymous namespace

    TAPReporter::~TAPReporter() {}

    void TAPReporter::noMatchingTestCases(std::string const& spec) {
        stream << "# No test cases matched '" << spec << "'\n";
    }

    bool TAPReporter::assertionEnded(AssertionStats const& _assertionStats) {
        ++counter;

        stream << "# " << currentTestCaseInfo->name << '\n';
        TapAssertionPrinter printer(stream, _assertionStats, counter);
        printer.print();

        stream << '\n' << std::flush;
        return true;
    }

    void TAPReporter::testRunEnded(TestRunStats const& _testRunStats) {
        stream << "1.." << _testRunStats.totals.assertions.total();
        if (_testRunStats.totals.testCases.total() == 0) {
            stream << " # Skipped: No tests ran.";
        }
        stream << "\n\n" << std::flush;
        StreamingReporterBase::testRunEnded(_testRunStats);
    }




} // end namespace Catch




#include <cassert>

namespace Catch {

    namespace {
        // if string has a : in first line will set indent to follow it on
        // subsequent lines
        void printHeaderString(std::ostream& os, std::string const& _string, std::size_t indent = 0) {
            std::size_t i = _string.find(": ");
            if (i != std::string::npos)
                i += 2;
            else
                i = 0;
            os << TextFlow::Column(_string)
                  .indent(indent + i)
                  .initialIndent(indent) << '\n';
        }

        std::string escape(std::string const& str) {
            std::string escaped = str;
            replaceInPlace(escaped, "|", "||");
            replaceInPlace(escaped, "'", "|'");
            replaceInPlace(escaped, "\n", "|n");
            replaceInPlace(escaped, "\r", "|r");
            replaceInPlace(escaped, "[", "|[");
            replaceInPlace(escaped, "]", "|]");
            return escaped;
        }
    } // end anonymous namespace


    TeamCityReporter::~TeamCityReporter() {}

    void TeamCityReporter::testGroupStarting(GroupInfo const& groupInfo) {
        StreamingReporterBase::testGroupStarting(groupInfo);
        stream << "##teamcity[testSuiteStarted name='"
            << escape(groupInfo.name) << "']\n";
    }

    void TeamCityReporter::testGroupEnded(TestGroupStats const& testGroupStats) {
        StreamingReporterBase::testGroupEnded(testGroupStats);
        stream << "##teamcity[testSuiteFinished name='"
            << escape(testGroupStats.groupInfo.name) << "']\n";
    }

    bool TeamCityReporter::assertionEnded(AssertionStats const& assertionStats) {
        AssertionResult const& result = assertionStats.assertionResult;
        if (!result.isOk()) {

            ReusableStringStream msg;
            if (!m_headerPrintedForThisSection)
                printSectionHeader(msg.get());
            m_headerPrintedForThisSection = true;

            msg << result.getSourceInfo() << '\n';

            switch (result.getResultType()) {
            case ResultWas::ExpressionFailed:
                msg << "expression failed";
                break;
            case ResultWas::ThrewException:
                msg << "unexpected exception";
                break;
            case ResultWas::FatalErrorCondition:
                msg << "fatal error condition";
                break;
            case ResultWas::DidntThrowException:
                msg << "no exception was thrown where one was expected";
                break;
            case ResultWas::ExplicitFailure:
                msg << "explicit failure";
                break;

                // We shouldn't get here because of the isOk() test
            case ResultWas::Ok:
            case ResultWas::Info:
            case ResultWas::Warning:
                CATCH_ERROR("Internal error in TeamCity reporter");
                // These cases are here to prevent compiler warnings
            case ResultWas::Unknown:
            case ResultWas::FailureBit:
            case ResultWas::Exception:
                CATCH_ERROR("Not implemented");
            }
            if (assertionStats.infoMessages.size() == 1)
                msg << " with message:";
            if (assertionStats.infoMessages.size() > 1)
                msg << " with messages:";
            for (auto const& messageInfo : assertionStats.infoMessages)
                msg << "\n  \"" << messageInfo.message << '"';


            if (result.hasExpression()) {
                msg <<
                    "\n  " << result.getExpressionInMacro() << "\n"
                    "with expansion:\n"
                    "  " << result.getExpandedExpression() << '\n';
            }

            if (currentTestCaseInfo->okToFail()) {
                msg << "- failure ignore as test marked as 'ok to fail'\n";
                stream << "##teamcity[testIgnored"
                    << " name='" << escape(currentTestCaseInfo->name) << '\''
                    << " message='" << escape(msg.str()) << '\''
                    << "]\n";
            } else {
                stream << "##teamcity[testFailed"
                    << " name='" << escape(currentTestCaseInfo->name) << '\''
                    << " message='" << escape(msg.str()) << '\''
                    << "]\n";
            }
        }
        stream.flush();
        return true;
    }

    void TeamCityReporter::testCaseStarting(TestCaseInfo const& testInfo) {
        m_testTimer.start();
        StreamingReporterBase::testCaseStarting(testInfo);
        stream << "##teamcity[testStarted name='"
            << escape(testInfo.name) << "']\n";
        stream.flush();
    }

    void TeamCityReporter::testCaseEnded(TestCaseStats const& testCaseStats) {
        StreamingReporterBase::testCaseEnded(testCaseStats);
        auto const& testCaseInfo = *testCaseStats.testInfo;
        if (!testCaseStats.stdOut.empty())
            stream << "##teamcity[testStdOut name='"
            << escape(testCaseInfo.name)
            << "' out='" << escape(testCaseStats.stdOut) << "']\n";
        if (!testCaseStats.stdErr.empty())
            stream << "##teamcity[testStdErr name='"
            << escape(testCaseInfo.name)
            << "' out='" << escape(testCaseStats.stdErr) << "']\n";
        stream << "##teamcity[testFinished name='"
            << escape(testCaseInfo.name) << "' duration='"
            << m_testTimer.getElapsedMilliseconds() << "']\n";
        stream.flush();
    }

    void TeamCityReporter::printSectionHeader(std::ostream& os) {
        assert(!m_sectionStack.empty());

        if (m_sectionStack.size() > 1) {
            os << lineOfChars('-') << '\n';

            std::vector<SectionInfo>::const_iterator
                it = m_sectionStack.begin() + 1, // Skip first section (test case)
                itEnd = m_sectionStack.end();
            for (; it != itEnd; ++it)
                printHeaderString(os, it->name);
            os << lineOfChars('-') << '\n';
        }

        SourceLineInfo lineInfo = m_sectionStack.front().lineInfo;

        os << lineInfo << '\n';
        os << lineOfChars('.') << "\n\n";
    }

} // end namespace Catch




#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable:4061) // Not all labels are EXPLICITLY handled in switch
                              // Note that 4062 (not all labels are handled
                              // and default is missing) is enabled
#endif

namespace Catch {
    XmlReporter::XmlReporter( ReporterConfig const& _config )
    :   StreamingReporterBase( _config ),
        m_xml(_config.stream())
    {
        m_preferences.shouldRedirectStdOut = true;
        m_preferences.shouldReportAllAssertions = true;
    }

    XmlReporter::~XmlReporter() = default;

    std::string XmlReporter::getDescription() {
        return "Reports test results as an XML document";
    }

    std::string XmlReporter::getStylesheetRef() const {
        return std::string();
    }

    void XmlReporter::writeSourceInfo( SourceLineInfo const& sourceInfo ) {
        m_xml
            .writeAttribute( "filename", sourceInfo.file )
            .writeAttribute( "line", sourceInfo.line );
    }

    void XmlReporter::noMatchingTestCases( std::string const& s ) {
        StreamingReporterBase::noMatchingTestCases( s );
    }

    void XmlReporter::testRunStarting( TestRunInfo const& testInfo ) {
        StreamingReporterBase::testRunStarting( testInfo );
        std::string stylesheetRef = getStylesheetRef();
        if( !stylesheetRef.empty() )
            m_xml.writeStylesheetRef( stylesheetRef );
        m_xml.startElement( "Catch" );
        if( !m_config->name().empty() )
            m_xml.writeAttribute( "name", m_config->name() );
        if (m_config->testSpec().hasFilters())
            m_xml.writeAttribute( "filters", serializeFilters( m_config->getTestsOrTags() ) );
        if( m_config->rngSeed() != 0 )
            m_xml.scopedElement( "Randomness" )
                .writeAttribute( "seed", m_config->rngSeed() );
    }

    void XmlReporter::testGroupStarting( GroupInfo const& groupInfo ) {
        StreamingReporterBase::testGroupStarting( groupInfo );
        m_xml.startElement( "Group" )
            .writeAttribute( "name", groupInfo.name );
    }

    void XmlReporter::testCaseStarting( TestCaseInfo const& testInfo ) {
        StreamingReporterBase::testCaseStarting(testInfo);
        m_xml.startElement( "TestCase" )
            .writeAttribute( "name", trim( testInfo.name ) )
            .writeAttribute( "tags", testInfo.tagsAsString() );

        writeSourceInfo( testInfo.lineInfo );

        if ( m_config->showDurations() == ShowDurations::Always )
            m_testCaseTimer.start();
        m_xml.ensureTagClosed();
    }

    void XmlReporter::sectionStarting( SectionInfo const& sectionInfo ) {
        StreamingReporterBase::sectionStarting( sectionInfo );
        if( m_sectionDepth++ > 0 ) {
            m_xml.startElement( "Section" )
                .writeAttribute( "name", trim( sectionInfo.name ) );
            writeSourceInfo( sectionInfo.lineInfo );
            m_xml.ensureTagClosed();
        }
    }

    void XmlReporter::assertionStarting( AssertionInfo const& ) { }

    bool XmlReporter::assertionEnded( AssertionStats const& assertionStats ) {

        AssertionResult const& result = assertionStats.assertionResult;

        bool includeResults = m_config->includeSuccessfulResults() || !result.isOk();

        if( includeResults || result.getResultType() == ResultWas::Warning ) {
            // Print any info messages in <Info> tags.
            for( auto const& msg : assertionStats.infoMessages ) {
                if( msg.type == ResultWas::Info && includeResults ) {
                    m_xml.scopedElement( "Info" )
                            .writeText( msg.message );
                } else if ( msg.type == ResultWas::Warning ) {
                    m_xml.scopedElement( "Warning" )
                            .writeText( msg.message );
                }
            }
        }

        // Drop out if result was successful but we're not printing them.
        if( !includeResults && result.getResultType() != ResultWas::Warning )
            return true;


        // Print the expression if there is one.
        if( result.hasExpression() ) {
            m_xml.startElement( "Expression" )
                .writeAttribute( "success", result.succeeded() )
                .writeAttribute( "type", result.getTestMacroName() );

            writeSourceInfo( result.getSourceInfo() );

            m_xml.scopedElement( "Original" )
                .writeText( result.getExpression() );
            m_xml.scopedElement( "Expanded" )
                .writeText( result.getExpandedExpression() );
        }

        // And... Print a result applicable to each result type.
        switch( result.getResultType() ) {
            case ResultWas::ThrewException:
                m_xml.startElement( "Exception" );
                writeSourceInfo( result.getSourceInfo() );
                m_xml.writeText( result.getMessage() );
                m_xml.endElement();
                break;
            case ResultWas::FatalErrorCondition:
                m_xml.startElement( "FatalErrorCondition" );
                writeSourceInfo( result.getSourceInfo() );
                m_xml.writeText( result.getMessage() );
                m_xml.endElement();
                break;
            case ResultWas::Info:
                m_xml.scopedElement( "Info" )
                    .writeText( result.getMessage() );
                break;
            case ResultWas::Warning:
                // Warning will already have been written
                break;
            case ResultWas::ExplicitFailure:
                m_xml.startElement( "Failure" );
                writeSourceInfo( result.getSourceInfo() );
                m_xml.writeText( result.getMessage() );
                m_xml.endElement();
                break;
            default:
                break;
        }

        if( result.hasExpression() )
            m_xml.endElement();

        return true;
    }

    void XmlReporter::sectionEnded( SectionStats const& sectionStats ) {
        StreamingReporterBase::sectionEnded( sectionStats );
        if( --m_sectionDepth > 0 ) {
            XmlWriter::ScopedElement e = m_xml.scopedElement( "OverallResults" );
            e.writeAttribute( "successes", sectionStats.assertions.passed );
            e.writeAttribute( "failures", sectionStats.assertions.failed );
            e.writeAttribute( "expectedFailures", sectionStats.assertions.failedButOk );

            if ( m_config->showDurations() == ShowDurations::Always )
                e.writeAttribute( "durationInSeconds", sectionStats.durationInSeconds );

            m_xml.endElement();
        }
    }

    void XmlReporter::testCaseEnded( TestCaseStats const& testCaseStats ) {
        StreamingReporterBase::testCaseEnded( testCaseStats );
        XmlWriter::ScopedElement e = m_xml.scopedElement( "OverallResult" );
        e.writeAttribute( "success", testCaseStats.totals.assertions.allOk() );

        if ( m_config->showDurations() == ShowDurations::Always )
            e.writeAttribute( "durationInSeconds", m_testCaseTimer.getElapsedSeconds() );

        if( !testCaseStats.stdOut.empty() )
            m_xml.scopedElement( "StdOut" ).writeText( trim( testCaseStats.stdOut ), XmlFormatting::Newline );
        if( !testCaseStats.stdErr.empty() )
            m_xml.scopedElement( "StdErr" ).writeText( trim( testCaseStats.stdErr ), XmlFormatting::Newline );

        m_xml.endElement();
    }

    void XmlReporter::testGroupEnded( TestGroupStats const& testGroupStats ) {
        StreamingReporterBase::testGroupEnded( testGroupStats );
        // TODO: Check testGroupStats.aborting and act accordingly.
        m_xml.scopedElement( "OverallResults" )
            .writeAttribute( "successes", testGroupStats.totals.assertions.passed )
            .writeAttribute( "failures", testGroupStats.totals.assertions.failed )
            .writeAttribute( "expectedFailures", testGroupStats.totals.assertions.failedButOk );
        m_xml.scopedElement( "OverallResultsCases")
            .writeAttribute( "successes", testGroupStats.totals.testCases.passed )
            .writeAttribute( "failures", testGroupStats.totals.testCases.failed )
            .writeAttribute( "expectedFailures", testGroupStats.totals.testCases.failedButOk );
        m_xml.endElement();
    }

    void XmlReporter::testRunEnded( TestRunStats const& testRunStats ) {
        StreamingReporterBase::testRunEnded( testRunStats );
        m_xml.scopedElement( "OverallResults" )
            .writeAttribute( "successes", testRunStats.totals.assertions.passed )
            .writeAttribute( "failures", testRunStats.totals.assertions.failed )
            .writeAttribute( "expectedFailures", testRunStats.totals.assertions.failedButOk );
        m_xml.scopedElement( "OverallResultsCases")
            .writeAttribute( "successes", testRunStats.totals.testCases.passed )
            .writeAttribute( "failures", testRunStats.totals.testCases.failed )
            .writeAttribute( "expectedFailures", testRunStats.totals.testCases.failedButOk );
        m_xml.endElement();
    }

    void XmlReporter::benchmarkPreparing(std::string const& name) {
        m_xml.startElement("BenchmarkResults")
            .writeAttribute("name", name);
    }

    void XmlReporter::benchmarkStarting(BenchmarkInfo const &info) {
        m_xml.writeAttribute("samples", info.samples)
            .writeAttribute("resamples", info.resamples)
            .writeAttribute("iterations", info.iterations)
            .writeAttribute("clockResolution", info.clockResolution)
            .writeAttribute("estimatedDuration", info.estimatedDuration)
            .writeComment("All values in nano seconds");
    }

    void XmlReporter::benchmarkEnded(BenchmarkStats<> const& benchmarkStats) {
        m_xml.startElement("mean")
            .writeAttribute("value", benchmarkStats.mean.point.count())
            .writeAttribute("lowerBound", benchmarkStats.mean.lower_bound.count())
            .writeAttribute("upperBound", benchmarkStats.mean.upper_bound.count())
            .writeAttribute("ci", benchmarkStats.mean.confidence_interval);
        m_xml.endElement();
        m_xml.startElement("standardDeviation")
            .writeAttribute("value", benchmarkStats.standardDeviation.point.count())
            .writeAttribute("lowerBound", benchmarkStats.standardDeviation.lower_bound.count())
            .writeAttribute("upperBound", benchmarkStats.standardDeviation.upper_bound.count())
            .writeAttribute("ci", benchmarkStats.standardDeviation.confidence_interval);
        m_xml.endElement();
        m_xml.startElement("outliers")
            .writeAttribute("variance", benchmarkStats.outlierVariance)
            .writeAttribute("lowMild", benchmarkStats.outliers.low_mild)
            .writeAttribute("lowSevere", benchmarkStats.outliers.low_severe)
            .writeAttribute("highMild", benchmarkStats.outliers.high_mild)
            .writeAttribute("highSevere", benchmarkStats.outliers.high_severe);
        m_xml.endElement();
        m_xml.endElement();
    }

    void XmlReporter::benchmarkFailed(std::string const &error) {
        m_xml.scopedElement("failed").
            writeAttribute("message", error);
        m_xml.endElement();
    }

    void XmlReporter::listReporters(std::vector<ReporterDescription> const& descriptions, IConfig const&) {
        auto outerTag = m_xml.scopedElement("AvailableReporters");
        for (auto const& reporter : descriptions) {
            auto inner = m_xml.scopedElement("Reporter");
            m_xml.startElement("Name", XmlFormatting::Indent)
                 .writeText(reporter.name, XmlFormatting::None)
                 .endElement(XmlFormatting::Newline);
            m_xml.startElement("Description", XmlFormatting::Indent)
                 .writeText(reporter.description, XmlFormatting::None)
                 .endElement(XmlFormatting::Newline);
        }
    }

    void XmlReporter::listTests(std::vector<TestCaseHandle> const& tests, IConfig const&) {
        auto outerTag = m_xml.scopedElement("MatchingTests");
        for (auto const& test : tests) {
            auto innerTag = m_xml.scopedElement("TestCase");
            auto const& testInfo = test.getTestCaseInfo();
            m_xml.startElement("Name", XmlFormatting::Indent)
                 .writeText(testInfo.name, XmlFormatting::None)
                 .endElement(XmlFormatting::Newline);
            m_xml.startElement("ClassName", XmlFormatting::Indent)
                 .writeText(testInfo.className, XmlFormatting::None)
                 .endElement(XmlFormatting::Newline);
            m_xml.startElement("Tags", XmlFormatting::Indent)
                 .writeText(testInfo.tagsAsString(), XmlFormatting::None)
                 .endElement(XmlFormatting::Newline);

            auto sourceTag = m_xml.scopedElement("SourceInfo");
            m_xml.startElement("File", XmlFormatting::Indent)
                 .writeText(testInfo.lineInfo.file, XmlFormatting::None)
                 .endElement(XmlFormatting::Newline);
            m_xml.startElement("Line", XmlFormatting::Indent)
                 .writeText(std::to_string(testInfo.lineInfo.line), XmlFormatting::None)
                 .endElement(XmlFormatting::Newline);
        }
    }

    void XmlReporter::listTags(std::vector<TagInfo> const& tags, IConfig const&) {
        auto outerTag = m_xml.scopedElement("TagsFromMatchingTests");
        for (auto const& tag : tags) {
            auto innerTag = m_xml.scopedElement("Tag");
            m_xml.startElement("Count", XmlFormatting::Indent)
                 .writeText(std::to_string(tag.count), XmlFormatting::None)
                 .endElement(XmlFormatting::Newline);
            auto aliasTag = m_xml.scopedElement("Aliases");
            for (auto const& alias : tag.spellings) {
                m_xml.startElement("Alias", XmlFormatting::Indent)
                     .writeText(static_cast<std::string>(alias), XmlFormatting::None)
                     .endElement(XmlFormatting::Newline);
            }
        }
    }

} // end namespace Catch

#if defined(_MSC_VER)
#pragma warning(pop)
#endif
