// Copyright 2016 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <iostream>
#include <sstream>
#include <json.hpp>

using json = nlohmann::json;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  try {
    std::stringstream s;
    s << json::parse(data, data + size);
    try {
      auto j = json::parse(s.str());
      std::stringstream s2;
      s2 << j;
      assert(s.str() == s2.str());
      assert(j == json::parse(s.str()));
    } catch (const std::invalid_argument&) { 
      assert(0);
    }
  } catch (const std::invalid_argument&) { }
  return 0;
}
