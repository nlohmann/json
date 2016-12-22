// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.

// Test with a more mallocs than frees, but no leak.
#include <cstdint>
#include <cstddef>

const int kAllocatedPointersSize = 10000;
int NumAllocatedPointers = 0;
int *AllocatedPointers[kAllocatedPointersSize];

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (NumAllocatedPointers < kAllocatedPointersSize)
    AllocatedPointers[NumAllocatedPointers++] = new int;
  return 0;
}

