// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.

// The fuzzer should find a leak in a non-main thread.
#include <cstdint>
#include <cstddef>
#include <thread>

static volatile int *Sink;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size == 0) return 0;
  if (Data[0] != 'F') return 0;
  std::thread T([&] { Sink = new int; });
  T.join();
  return 0;
}

