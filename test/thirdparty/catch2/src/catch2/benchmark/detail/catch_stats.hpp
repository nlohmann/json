
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
// Adapted from donated nonius code.

#ifndef CATCH_STATS_HPP_INCLUDED
#define CATCH_STATS_HPP_INCLUDED

#include <catch2/benchmark/catch_estimate.hpp>
#include <catch2/benchmark/catch_outlier_classification.hpp>

#include <algorithm>
#include <vector>
#include <numeric>
#include <tuple>
#include <cmath>
#include <utility>

namespace Catch {
    namespace Benchmark {
        namespace Detail {
            using sample = std::vector<double>;

            double weighted_average_quantile(int k, int q, std::vector<double>::iterator first, std::vector<double>::iterator last);

            template <typename Iterator>
            OutlierClassification classify_outliers(Iterator first, Iterator last) {
                std::vector<double> copy(first, last);

                auto q1 = weighted_average_quantile(1, 4, copy.begin(), copy.end());
                auto q3 = weighted_average_quantile(3, 4, copy.begin(), copy.end());
                auto iqr = q3 - q1;
                auto los = q1 - (iqr * 3.);
                auto lom = q1 - (iqr * 1.5);
                auto him = q3 + (iqr * 1.5);
                auto his = q3 + (iqr * 3.);

                OutlierClassification o;
                for (; first != last; ++first) {
                    auto&& t = *first;
                    if (t < los) ++o.low_severe;
                    else if (t < lom) ++o.low_mild;
                    else if (t > his) ++o.high_severe;
                    else if (t > him) ++o.high_mild;
                    ++o.samples_seen;
                }
                return o;
            }

            template <typename Iterator>
            double mean(Iterator first, Iterator last) {
                auto count = last - first;
                double sum = std::accumulate(first, last, 0.);
                return sum / count;
            }

            template <typename Estimator, typename Iterator>
            sample jackknife(Estimator&& estimator, Iterator first, Iterator last) {
                auto n = last - first;
                auto second = first;
                ++second;
                sample results;
                results.reserve(n);

                for (auto it = first; it != last; ++it) {
                    std::iter_swap(it, first);
                    results.push_back(estimator(second, last));
                }

                return results;
            }

            inline double normal_cdf(double x) {
                return std::erfc(-x / std::sqrt(2.0)) / 2.0;
            }

            double erfc_inv(double x);

            double normal_quantile(double p);

            template <typename Iterator, typename Estimator>
            Estimate<double> bootstrap(double confidence_level, Iterator first, Iterator last, sample const& resample, Estimator&& estimator) {
                auto n_samples = last - first;

                double point = estimator(first, last);
                // Degenerate case with a single sample
                if (n_samples == 1) return { point, point, point, confidence_level };

                sample jack = jackknife(estimator, first, last);
                double jack_mean = mean(jack.begin(), jack.end());
                double sum_squares, sum_cubes;
                std::tie(sum_squares, sum_cubes) = std::accumulate(jack.begin(), jack.end(), std::make_pair(0., 0.), [jack_mean](std::pair<double, double> sqcb, double x) -> std::pair<double, double> {
                    auto d = jack_mean - x;
                    auto d2 = d * d;
                    auto d3 = d2 * d;
                    return { sqcb.first + d2, sqcb.second + d3 };
                });

                double accel = sum_cubes / (6 * std::pow(sum_squares, 1.5));
                int n = static_cast<int>(resample.size());
                double prob_n = std::count_if(resample.begin(), resample.end(), [point](double x) { return x < point; }) / (double)n;
                // degenerate case with uniform samples
                if (prob_n == 0) return { point, point, point, confidence_level };

                double bias = normal_quantile(prob_n);
                double z1 = normal_quantile((1. - confidence_level) / 2.);

                auto cumn = [n](double x) -> int {
                    return std::lround(normal_cdf(x) * n); };
                auto a = [bias, accel](double b) { return bias + b / (1. - accel * b); };
                double b1 = bias + z1;
                double b2 = bias - z1;
                double a1 = a(b1);
                double a2 = a(b2);
                auto lo = std::max(cumn(a1), 0);
                auto hi = std::min(cumn(a2), n - 1);

                return { point, resample[lo], resample[hi], confidence_level };
            }

            double outlier_variance(Estimate<double> mean, Estimate<double> stddev, int n);

            struct bootstrap_analysis {
                Estimate<double> mean;
                Estimate<double> standard_deviation;
                double outlier_variance;
            };

            bootstrap_analysis analyse_samples(double confidence_level, int n_resamples, std::vector<double>::iterator first, std::vector<double>::iterator last);
        } // namespace Detail
    } // namespace Benchmark
} // namespace Catch

#endif // CATCH_STATS_HPP_INCLUDED
