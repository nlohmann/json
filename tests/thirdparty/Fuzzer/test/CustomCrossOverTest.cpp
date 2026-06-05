// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.

// Simple test for a cutom mutator.
#include <assert.h>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <random>
#include <string.h>

#include "FuzzerInterface.h"

static const char *Separator = "-_^_-";
static const char *Target = "012-_^_-abc";

static volatile int sink;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  assert(Data);
  std::string Str(reinterpret_cast<const char *>(Data), Size);

  // Ensure that two different elements exist in the corpus.
  if (Size && Data[0] == '0') sink++;
  if (Size && Data[0] == 'a') sink--;

  if (Str.find(Target) != std::string::npos) {
    std::cout << "BINGO; Found the target, exiting\n";
    exit(1);
  }
  return 0;
}

extern "C" size_t LLVMFuzzerCustomCrossOver(const uint8_t *Data1, size_t Size1,
                                            const uint8_t *Data2, size_t Size2,
                                            uint8_t *Out, size_t MaxOutSize,
                                            unsigned int Seed) {
  static bool Printed;
  static size_t SeparatorLen = strlen(Separator);

  if (!Printed) {
    std::cerr << "In LLVMFuzzerCustomCrossover\n";
    Printed = true;
  }

  std::mt19937 R(Seed);

  size_t Offset1 = 0;
  size_t Len1 = R() % (Size1 - Offset1);
  size_t Offset2 = 0;
  size_t Len2 = R() % (Size2 - Offset2);
  size_t Size = Len1 + Len2 + SeparatorLen;

  if (Size > MaxOutSize)
    return 0;

  memcpy(Out, Data1 + Offset1, Len1);
  memcpy(Out + Len1, Separator, SeparatorLen);
  memcpy(Out + Len1 + SeparatorLen, Data2 + Offset2, Len2);

  return Len1 + Len2 + SeparatorLen;
}
