// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.

// Simple test for a cutom mutator.
#include <assert.h>
#include <cstdint>
#include <cstdlib>
#include <cstddef>
#include <iostream>

#include "FuzzerInterface.h"

static volatile int Sink;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  assert(Data);
  if (Size > 0 && Data[0] == 'H') {
    Sink = 1;
    if (Size > 1 && Data[1] == 'i') {
      Sink = 2;
      if (Size > 2 && Data[2] == '!') {
        std::cout << "BINGO; Found the target, exiting\n";
        exit(1);
      }
    }
  }
  return 0;
}

extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size,
                                          size_t MaxSize, unsigned int Seed) {
  static bool Printed;
  if (!Printed) {
    std::cerr << "In LLVMFuzzerCustomMutator\n";
    Printed = true;
  }
  return LLVMFuzzerMutate(Data, Size, MaxSize);
}
