// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.

// Test for a fuzzer: must find the case where a particular basic block is
// executed many times.
#include <iostream>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  int Num = 0;
  for (size_t i = 0; i < Size; i++)
    if (Data[i] == 'A' + i)
      Num++;
  if (Num >= 4) {
    std::cerr <<  "BINGO!\n";
    exit(1);
  }
  return 0;
}
