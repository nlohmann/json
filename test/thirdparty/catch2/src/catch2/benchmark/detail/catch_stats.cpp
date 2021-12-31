
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
// Adapted from donated nonius code.

#include <catch2/benchmark/detail/catch_stats.hpp>

#include <catch2/internal/catch_compiler_capabilities.hpp>

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
