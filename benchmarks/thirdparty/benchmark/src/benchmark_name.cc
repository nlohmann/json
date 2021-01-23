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

#include <benchmark/benchmark.h>

namespace benchmark {

namespace {

// Compute the total size of a pack of std::strings
size_t size_impl() { return 0; }

template <typename Head, typename... Tail>
size_t size_impl(const Head& head, const Tail&... tail) {
  return head.size() + size_impl(tail...);
}

// Join a pack of std::strings using a delimiter
// TODO: use absl::StrJoin
void join_impl(std::string&, char) {}

template <typename Head, typename... Tail>
void join_impl(std::string& s, const char delimiter, const Head& head,
               const Tail&... tail) {
  if (!s.empty() && !head.empty()) {
    s += delimiter;
  }

  s += head;

  join_impl(s, delimiter, tail...);
}

template <typename... Ts>
std::string join(char delimiter, const Ts&... ts) {
  std::string s;
  s.reserve(sizeof...(Ts) + size_impl(ts...));
  join_impl(s, delimiter, ts...);
  return s;
}
}  // namespace

std::string BenchmarkName::str() const {
  return join('/', function_name, args, min_time, iterations, repetitions,
              time_type, threads);
}
}  // namespace benchmark
