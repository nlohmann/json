// Copyright 2015 Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "benchmark/benchmark.h"
#include "complexity.h"

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <string>
#include <tuple>
#include <vector>
#include <iomanip> // for setprecision
#include <limits>

#include "string_util.h"
#include "timers.h"

namespace benchmark {

namespace {

std::string FormatKV(std::string const& key, std::string const& value) {
  return StringPrintF("\"%s\": \"%s\"", key.c_str(), value.c_str());
}

std::string FormatKV(std::string const& key, const char* value) {
  return StringPrintF("\"%s\": \"%s\"", key.c_str(), value);
}

std::string FormatKV(std::string const& key, bool value) {
  return StringPrintF("\"%s\": %s", key.c_str(), value ? "true" : "false");
}

std::string FormatKV(std::string const& key, int64_t value) {
  std::stringstream ss;
  ss << '"' << key << "\": " << value;
  return ss.str();
}

std::string FormatKV(std::string const& key, double value) {
  std::stringstream ss;
  ss << '"' << key << "\": ";

  const auto max_digits10 = std::numeric_limits<decltype (value)>::max_digits10;
  const auto max_fractional_digits10 = max_digits10 - 1;

  ss << std::scientific << std::setprecision(max_fractional_digits10) << value;
  return ss.str();
}

int64_t RoundDouble(double v) { return static_cast<int64_t>(v + 0.5); }

}  // end namespace

bool JSONReporter::ReportContext(const Context& context) {
  std::ostream& out = GetOutputStream();

  out << "{\n";
  std::string inner_indent(2, ' ');

  // Open context block and print context information.
  out << inner_indent << "\"context\": {\n";
  std::string indent(4, ' ');

  std::string walltime_value = LocalDateTimeString();
  out << indent << FormatKV("date", walltime_value) << ",\n";

  CPUInfo const& info = context.cpu_info;
  out << indent << FormatKV("num_cpus", static_cast<int64_t>(info.num_cpus))
      << ",\n";
  out << indent
      << FormatKV("mhz_per_cpu",
                  RoundDouble(info.cycles_per_second / 1000000.0))
      << ",\n";
  out << indent << FormatKV("cpu_scaling_enabled", info.scaling_enabled)
      << ",\n";

  out << indent << "\"caches\": [\n";
  indent = std::string(6, ' ');
  std::string cache_indent(8, ' ');
  for (size_t i = 0; i < info.caches.size(); ++i) {
    auto& CI = info.caches[i];
    out << indent << "{\n";
    out << cache_indent << FormatKV("type", CI.type) << ",\n";
    out << cache_indent << FormatKV("level", static_cast<int64_t>(CI.level))
        << ",\n";
    out << cache_indent
        << FormatKV("size", static_cast<int64_t>(CI.size) * 1000u) << ",\n";
    out << cache_indent
        << FormatKV("num_sharing", static_cast<int64_t>(CI.num_sharing))
        << "\n";
    out << indent << "}";
    if (i != info.caches.size() - 1) out << ",";
    out << "\n";
  }
  indent = std::string(4, ' ');
  out << indent << "],\n";

#if defined(NDEBUG)
  const char build_type[] = "release";
#else
  const char build_type[] = "debug";
#endif
  out << indent << FormatKV("library_build_type", build_type) << "\n";
  // Close context block and open the list of benchmarks.
  out << inner_indent << "},\n";
  out << inner_indent << "\"benchmarks\": [\n";
  return true;
}

void JSONReporter::ReportRuns(std::vector<Run> const& reports) {
  if (reports.empty()) {
    return;
  }
  std::string indent(4, ' ');
  std::ostream& out = GetOutputStream();
  if (!first_report_) {
    out << ",\n";
  }
  first_report_ = false;

  for (auto it = reports.begin(); it != reports.end(); ++it) {
    out << indent << "{\n";
    PrintRunData(*it);
    out << indent << '}';
    auto it_cp = it;
    if (++it_cp != reports.end()) {
      out << ",\n";
    }
  }
}

void JSONReporter::Finalize() {
  // Close the list of benchmarks and the top level object.
  GetOutputStream() << "\n  ]\n}\n";
}

void JSONReporter::PrintRunData(Run const& run) {
  std::string indent(6, ' ');
  std::ostream& out = GetOutputStream();
  out << indent << FormatKV("name", run.benchmark_name) << ",\n";
  if (run.error_occurred) {
    out << indent << FormatKV("error_occurred", run.error_occurred) << ",\n";
    out << indent << FormatKV("error_message", run.error_message) << ",\n";
  }
  if (!run.report_big_o && !run.report_rms) {
    out << indent << FormatKV("iterations", run.iterations) << ",\n";
    out << indent
        << FormatKV("real_time", run.GetAdjustedRealTime())
        << ",\n";
    out << indent
        << FormatKV("cpu_time", run.GetAdjustedCPUTime());
    out << ",\n"
        << indent << FormatKV("time_unit", GetTimeUnitString(run.time_unit));
  } else if (run.report_big_o) {
    out << indent
        << FormatKV("cpu_coefficient", run.GetAdjustedCPUTime())
        << ",\n";
    out << indent
        << FormatKV("real_coefficient", run.GetAdjustedRealTime())
        << ",\n";
    out << indent << FormatKV("big_o", GetBigOString(run.complexity)) << ",\n";
    out << indent << FormatKV("time_unit", GetTimeUnitString(run.time_unit));
  } else if (run.report_rms) {
    out << indent
        << FormatKV("rms", run.GetAdjustedCPUTime());
  }
  if (run.bytes_per_second > 0.0) {
    out << ",\n"
        << indent
        << FormatKV("bytes_per_second", run.bytes_per_second);
  }
  if (run.items_per_second > 0.0) {
    out << ",\n"
        << indent
        << FormatKV("items_per_second", run.items_per_second);
  }
  for(auto &c : run.counters) {
    out << ",\n"
        << indent
        << FormatKV(c.first, c.second);
  }
  if (!run.report_label.empty()) {
    out << ",\n" << indent << FormatKV("label", run.report_label);
  }
  out << '\n';
}

} // end namespace benchmark
