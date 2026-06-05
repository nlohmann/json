//===- FuzzerUtilPosix.cpp - Misc utils for Posix. ------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// Misc utils implementation using Posix API.
//===----------------------------------------------------------------------===//
#include "FuzzerDefs.h"
#if LIBFUZZER_POSIX
#include "FuzzerIO.h"
#include "FuzzerInternal.h"
#include <cassert>
#include <chrono>
#include <cstring>
#include <errno.h>
#include <iomanip>
#include <signal.h>
#include <sstream>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>

namespace fuzzer {

static void AlarmHandler(int, siginfo_t *, void *) {
  Fuzzer::StaticAlarmCallback();
}

static void CrashHandler(int, siginfo_t *, void *) {
  Fuzzer::StaticCrashSignalCallback();
}

static void InterruptHandler(int, siginfo_t *, void *) {
  Fuzzer::StaticInterruptCallback();
}

static void SetSigaction(int signum,
                         void (*callback)(int, siginfo_t *, void *)) {
  struct sigaction sigact;
  memset(&sigact, 0, sizeof(sigact));
  sigact.sa_sigaction = callback;
  if (sigaction(signum, &sigact, 0)) {
    Printf("libFuzzer: sigaction failed with %d\n", errno);
    exit(1);
  }
}

void SetTimer(int Seconds) {
  struct itimerval T {
    {Seconds, 0}, { Seconds, 0 }
  };
  if (setitimer(ITIMER_REAL, &T, nullptr)) {
    Printf("libFuzzer: setitimer failed with %d\n", errno);
    exit(1);
  }
  SetSigaction(SIGALRM, AlarmHandler);
}

void SetSignalHandler(const FuzzingOptions& Options) {
  if (Options.UnitTimeoutSec > 0)
    SetTimer(Options.UnitTimeoutSec / 2 + 1);
  if (Options.HandleInt)
    SetSigaction(SIGINT, InterruptHandler);
  if (Options.HandleTerm)
    SetSigaction(SIGTERM, InterruptHandler);
  if (Options.HandleSegv)
    SetSigaction(SIGSEGV, CrashHandler);
  if (Options.HandleBus)
    SetSigaction(SIGBUS, CrashHandler);
  if (Options.HandleAbrt)
    SetSigaction(SIGABRT, CrashHandler);
  if (Options.HandleIll)
    SetSigaction(SIGILL, CrashHandler);
  if (Options.HandleFpe)
    SetSigaction(SIGFPE, CrashHandler);
}

void SleepSeconds(int Seconds) {
  sleep(Seconds); // Use C API to avoid coverage from instrumented libc++.
}

unsigned long GetPid() { return (unsigned long)getpid(); }

size_t GetPeakRSSMb() {
  struct rusage usage;
  if (getrusage(RUSAGE_SELF, &usage))
    return 0;
  if (LIBFUZZER_LINUX) {
    // ru_maxrss is in KiB
    return usage.ru_maxrss >> 10;
  } else if (LIBFUZZER_APPLE) {
    // ru_maxrss is in bytes
    return usage.ru_maxrss >> 20;
  }
  assert(0 && "GetPeakRSSMb() is not implemented for your platform");
  return 0;
}

FILE *OpenProcessPipe(const char *Command, const char *Mode) {
  return popen(Command, Mode);
}

const void *SearchMemory(const void *Data, size_t DataLen, const void *Patt,
                         size_t PattLen) {
  return memmem(Data, DataLen, Patt, PattLen);
}

}  // namespace fuzzer

#endif // LIBFUZZER_POSIX
