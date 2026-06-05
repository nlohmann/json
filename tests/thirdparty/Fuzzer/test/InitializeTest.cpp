// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.

// Make sure LLVMFuzzerInitialize is called.
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *argv0;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  assert(*argc > 0);
  argv0 = **argv;
  fprintf(stderr, "LLVMFuzzerInitialize: %s\n", argv0);
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size == strlen(argv0) &&
      !strncmp(reinterpret_cast<const char *>(Data), argv0, Size)) {
    fprintf(stderr, "BINGO %s\n", argv0);
    exit(1);
  }
  return 0;
}
