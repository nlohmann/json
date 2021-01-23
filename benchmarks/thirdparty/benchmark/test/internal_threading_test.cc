
#undef NDEBUG

#include <chrono>
#include <thread>
#include "../src/timers.h"
#include "benchmark/benchmark.h"
#include "output_test.h"

static const std::chrono::duration<double, std::milli> time_frame(50);
static const double time_frame_in_sec(
    std::chrono::duration_cast<std::chrono::duration<double, std::ratio<1, 1>>>(
        time_frame)
        .count());

void MyBusySpinwait() {
  const auto start = benchmark::ChronoClockNow();

  while (true) {
    const auto now = benchmark::ChronoClockNow();
    const auto elapsed = now - start;

    if (std::chrono::duration<double, std::chrono::seconds::period>(elapsed) >=
        time_frame)
      return;
  }
}

// ========================================================================= //
// --------------------------- TEST CASES BEGIN ---------------------------- //
// ========================================================================= //

// ========================================================================= //
// BM_MainThread

void BM_MainThread(benchmark::State& state) {
  for (auto _ : state) {
    MyBusySpinwait();
    state.SetIterationTime(time_frame_in_sec);
  }
  state.counters["invtime"] =
      benchmark::Counter{1, benchmark::Counter::kIsRate};
}

BENCHMARK(BM_MainThread)->Iterations(1)->Threads(1);
BENCHMARK(BM_MainThread)->Iterations(1)->Threads(1)->UseRealTime();
BENCHMARK(BM_MainThread)->Iterations(1)->Threads(1)->UseManualTime();
BENCHMARK(BM_MainThread)->Iterations(1)->Threads(1)->MeasureProcessCPUTime();
BENCHMARK(BM_MainThread)
    ->Iterations(1)
    ->Threads(1)
    ->MeasureProcessCPUTime()
    ->UseRealTime();
BENCHMARK(BM_MainThread)
    ->Iterations(1)
    ->Threads(1)
    ->MeasureProcessCPUTime()
    ->UseManualTime();

BENCHMARK(BM_MainThread)->Iterations(1)->Threads(2);
BENCHMARK(BM_MainThread)->Iterations(1)->Threads(2)->UseRealTime();
BENCHMARK(BM_MainThread)->Iterations(1)->Threads(2)->UseManualTime();
BENCHMARK(BM_MainThread)->Iterations(1)->Threads(2)->MeasureProcessCPUTime();
BENCHMARK(BM_MainThread)
    ->Iterations(1)
    ->Threads(2)
    ->MeasureProcessCPUTime()
    ->UseRealTime();
BENCHMARK(BM_MainThread)
    ->Iterations(1)
    ->Threads(2)
    ->MeasureProcessCPUTime()
    ->UseManualTime();

// ========================================================================= //
// BM_WorkerThread

void BM_WorkerThread(benchmark::State& state) {
  for (auto _ : state) {
    std::thread Worker(&MyBusySpinwait);
    Worker.join();
    state.SetIterationTime(time_frame_in_sec);
  }
  state.counters["invtime"] =
      benchmark::Counter{1, benchmark::Counter::kIsRate};
}

BENCHMARK(BM_WorkerThread)->Iterations(1)->Threads(1);
BENCHMARK(BM_WorkerThread)->Iterations(1)->Threads(1)->UseRealTime();
BENCHMARK(BM_WorkerThread)->Iterations(1)->Threads(1)->UseManualTime();
BENCHMARK(BM_WorkerThread)->Iterations(1)->Threads(1)->MeasureProcessCPUTime();
BENCHMARK(BM_WorkerThread)
    ->Iterations(1)
    ->Threads(1)
    ->MeasureProcessCPUTime()
    ->UseRealTime();
BENCHMARK(BM_WorkerThread)
    ->Iterations(1)
    ->Threads(1)
    ->MeasureProcessCPUTime()
    ->UseManualTime();

BENCHMARK(BM_WorkerThread)->Iterations(1)->Threads(2);
BENCHMARK(BM_WorkerThread)->Iterations(1)->Threads(2)->UseRealTime();
BENCHMARK(BM_WorkerThread)->Iterations(1)->Threads(2)->UseManualTime();
BENCHMARK(BM_WorkerThread)->Iterations(1)->Threads(2)->MeasureProcessCPUTime();
BENCHMARK(BM_WorkerThread)
    ->Iterations(1)
    ->Threads(2)
    ->MeasureProcessCPUTime()
    ->UseRealTime();
BENCHMARK(BM_WorkerThread)
    ->Iterations(1)
    ->Threads(2)
    ->MeasureProcessCPUTime()
    ->UseManualTime();

// ========================================================================= //
// BM_MainThreadAndWorkerThread

void BM_MainThreadAndWorkerThread(benchmark::State& state) {
  for (auto _ : state) {
    std::thread Worker(&MyBusySpinwait);
    MyBusySpinwait();
    Worker.join();
    state.SetIterationTime(time_frame_in_sec);
  }
  state.counters["invtime"] =
      benchmark::Counter{1, benchmark::Counter::kIsRate};
}

BENCHMARK(BM_MainThreadAndWorkerThread)->Iterations(1)->Threads(1);
BENCHMARK(BM_MainThreadAndWorkerThread)
    ->Iterations(1)
    ->Threads(1)
    ->UseRealTime();
BENCHMARK(BM_MainThreadAndWorkerThread)
    ->Iterations(1)
    ->Threads(1)
    ->UseManualTime();
BENCHMARK(BM_MainThreadAndWorkerThread)
    ->Iterations(1)
    ->Threads(1)
    ->MeasureProcessCPUTime();
BENCHMARK(BM_MainThreadAndWorkerThread)
    ->Iterations(1)
    ->Threads(1)
    ->MeasureProcessCPUTime()
    ->UseRealTime();
BENCHMARK(BM_MainThreadAndWorkerThread)
    ->Iterations(1)
    ->Threads(1)
    ->MeasureProcessCPUTime()
    ->UseManualTime();

BENCHMARK(BM_MainThreadAndWorkerThread)->Iterations(1)->Threads(2);
BENCHMARK(BM_MainThreadAndWorkerThread)
    ->Iterations(1)
    ->Threads(2)
    ->UseRealTime();
BENCHMARK(BM_MainThreadAndWorkerThread)
    ->Iterations(1)
    ->Threads(2)
    ->UseManualTime();
BENCHMARK(BM_MainThreadAndWorkerThread)
    ->Iterations(1)
    ->Threads(2)
    ->MeasureProcessCPUTime();
BENCHMARK(BM_MainThreadAndWorkerThread)
    ->Iterations(1)
    ->Threads(2)
    ->MeasureProcessCPUTime()
    ->UseRealTime();
BENCHMARK(BM_MainThreadAndWorkerThread)
    ->Iterations(1)
    ->Threads(2)
    ->MeasureProcessCPUTime()
    ->UseManualTime();

// ========================================================================= //
// ---------------------------- TEST CASES END ----------------------------- //
// ========================================================================= //

int main(int argc, char* argv[]) { RunOutputTests(argc, argv); }
