// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.

// Simple test for a fuzzer. The fuzzer must find the string "Hi!".
#include <cstdint>
#include <cstdlib>
#include <cstddef>
#include <iostream>

static volatile int Sink;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size > 0 && Data[0] == 'H') {
    Sink = 1;
    if (Size > 1 && Data[1] == 'i') {
      Sink = 2;
      if (Size > 2 && Data[2] == '!') {
        Sink = 2;
        while (Sink)
          ;
      }
    }
  }
  return 0;
}

