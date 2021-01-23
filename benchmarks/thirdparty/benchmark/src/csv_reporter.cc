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

#include "check.h"
#include "string_util.h"
#include "timers.h"

// File format reference: http://edoceo.com/utilitas/csv-file-format.

namespace benchmark {

namespace {
std::vector<std::string> elements = {
    "name",           "iterations",       "real_time",        "cpu_time",
    "time_unit",      "bytes_per_second", "items_per_second", "label",
    "error_occurred", "error_message"};
}  // namespace

std::string CsvEscape(const std::string & s) {
  std::string tmp;
  tmp.reserve(s.size() + 2);
  for (char c : s) {
    switch (c) {
    case '"' : tmp += "\"\""; break;
    default  : tmp += c; break;
    }
  }
  return '"' + tmp + '"';
}

bool CSVReporter::ReportContext(const Context& context) {
  PrintBasicContext(&GetErrorStream(), context);
  return true;
}

void CSVReporter::ReportRuns(const std::vector<Run>& reports) {
  std::ostream& Out = GetOutputStream();

  if (!printed_header_) {
    // save the names of all the user counters
    for (const auto& run : reports) {
      for (const auto& cnt : run.counters) {
        if (cnt.first == "bytes_per_second" || cnt.first == "items_per_second")
          continue;
        user_counter_names_.insert(cnt.first);
      }
    }

    // print the header
    for (auto B = elements.begin(); B != elements.end();) {
      Out << *B++;
      if (B != elements.end()) Out << ",";
    }
    for (auto B = user_counter_names_.begin();
         B != user_counter_names_.end();) {
      Out << ",\"" << *B++ << "\"";
    }
    Out << "\n";

    printed_header_ = true;
  } else {
    // check that all the current counters are saved in the name set
    for (const auto& run : reports) {
      for (const auto& cnt : run.counters) {
        if (cnt.first == "bytes_per_second" || cnt.first == "items_per_second")
          continue;
        CHECK(user_counter_names_.find(cnt.first) != user_counter_names_.end())
            << "All counters must be present in each run. "
            << "Counter named \"" << cnt.first
            << "\" was not in a run after being added to the header";
      }
    }
  }

  // print results for each run
  for (const auto& run : reports) {
    PrintRunData(run);
  }
}

void CSVReporter::PrintRunData(const Run& run) {
  std::ostream& Out = GetOutputStream();
  Out << CsvEscape(run.benchmark_name()) << ",";
  if (run.error_occurred) {
    Out << std::string(elements.size() - 3, ',');
    Out << "true,";
    Out << CsvEscape(run.error_message) << "\n";
    return;
  }

  // Do not print iteration on bigO and RMS report
  if (!run.report_big_o && !run.report_rms) {
    Out << run.iterations;
  }
  Out << ",";

  Out << run.GetAdjustedRealTime() << ",";
  Out << run.GetAdjustedCPUTime() << ",";

  // Do not print timeLabel on bigO and RMS report
  if (run.report_big_o) {
    Out << GetBigOString(run.complexity);
  } else if (!run.report_rms) {
    Out << GetTimeUnitString(run.time_unit);
  }
  Out << ",";

  if (run.counters.find("bytes_per_second") != run.counters.end()) {
    Out << run.counters.at("bytes_per_second");
  }
  Out << ",";
  if (run.counters.find("items_per_second") != run.counters.end()) {
    Out << run.counters.at("items_per_second");
  }
  Out << ",";
  if (!run.report_label.empty()) {
    Out << CsvEscape(run.report_label);
  }
  Out << ",,";  // for error_occurred and error_message

  // Print user counters
  for (const auto& ucn : user_counter_names_) {
    auto it = run.counters.find(ucn);
    if (it == run.counters.end()) {
      Out << ",";
    } else {
      Out << "," << it->second;
    }
  }
  Out << '\n';
}

}  // end namespace benchmark
