// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.

// Simple test for a fuzzer.
// The fuzzer must find a string based on dictionary words:
//   "Elvis"
//   "Presley"
#include <cstdint>
#include <cstdlib>
#include <cstddef>
#include <cstring>
#include <iostream>

static volatile int Zero = 0;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  const char *Expected = "ElvisPresley";
  if (Size < strlen(Expected)) return 0;
  size_t Match = 0;
  for (size_t i = 0; Expected[i]; i++)
    if (Expected[i] + Zero == Data[i])
      Match++;
  if (Match == strlen(Expected)) {
    std::cout << "BINGO; Found the target, exiting\n";
    exit(1);
  }
  return 0;
}

