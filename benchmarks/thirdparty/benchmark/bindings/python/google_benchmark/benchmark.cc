// Benchmark for Python.

#include <map>
#include <string>
#include <vector>

#include "pybind11/operators.h"
#include "pybind11/pybind11.h"
#include "pybind11/stl.h"
#include "pybind11/stl_bind.h"

#include "benchmark/benchmark.h"

PYBIND11_MAKE_OPAQUE(benchmark::UserCounters);

namespace {
namespace py = ::pybind11;

std::vector<std::string> Initialize(const std::vector<std::string>& argv) {
  // The `argv` pointers here become invalid when this function returns, but
  // benchmark holds the pointer to `argv[0]`. We create a static copy of it
  // so it persists, and replace the pointer below.
  static std::string executable_name(argv[0]);
  std::vector<char*> ptrs;
  ptrs.reserve(argv.size());
  for (auto& arg : argv) {
    ptrs.push_back(const_cast<char*>(arg.c_str()));
  }
  ptrs[0] = const_cast<char*>(executable_name.c_str());
  int argc = static_cast<int>(argv.size());
  benchmark::Initialize(&argc, ptrs.data());
  std::vector<std::string> remaining_argv;
  remaining_argv.reserve(argc);
  for (int i = 0; i < argc; ++i) {
    remaining_argv.emplace_back(ptrs[i]);
  }
  return remaining_argv;
}

benchmark::internal::Benchmark* RegisterBenchmark(const char* name,
                                                  py::function f) {
  return benchmark::RegisterBenchmark(
      name, [f](benchmark::State& state) { f(&state); });
}

PYBIND11_MODULE(_benchmark, m) {
  using benchmark::TimeUnit;
  py::enum_<TimeUnit>(m, "TimeUnit")
      .value("kNanosecond", TimeUnit::kNanosecond)
      .value("kMicrosecond", TimeUnit::kMicrosecond)
      .value("kMillisecond", TimeUnit::kMillisecond)
      .export_values();

  using benchmark::BigO;
  py::enum_<BigO>(m, "BigO")
      .value("oNone", BigO::oNone)
      .value("o1", BigO::o1)
      .value("oN", BigO::oN)
      .value("oNSquared", BigO::oNSquared)
      .value("oNCubed", BigO::oNCubed)
      .value("oLogN", BigO::oLogN)
      .value("oNLogN", BigO::oLogN)
      .value("oAuto", BigO::oAuto)
      .value("oLambda", BigO::oLambda)
      .export_values();

  using benchmark::internal::Benchmark;
  py::class_<Benchmark>(m, "Benchmark")
      // For methods returning a pointer tor the current object, reference
      // return policy is used to ask pybind not to take ownership oof the
      // returned object and avoid calling delete on it.
      // https://pybind11.readthedocs.io/en/stable/advanced/functions.html#return-value-policies
      //
      // For methods taking a const std::vector<...>&, a copy is created
      // because a it is bound to a Python list.
      // https://pybind11.readthedocs.io/en/stable/advanced/cast/stl.html
      .def("unit", &Benchmark::Unit, py::return_value_policy::reference)
      .def("arg", &Benchmark::Arg, py::return_value_policy::reference)
      .def("args", &Benchmark::Args, py::return_value_policy::reference)
      .def("range", &Benchmark::Range, py::return_value_policy::reference,
           py::arg("start"), py::arg("limit"))
      .def("dense_range", &Benchmark::DenseRange,
           py::return_value_policy::reference, py::arg("start"),
           py::arg("limit"), py::arg("step") = 1)
      .def("ranges", &Benchmark::Ranges, py::return_value_policy::reference)
      .def("args_product", &Benchmark::ArgsProduct,
           py::return_value_policy::reference)
      .def("arg_name", &Benchmark::ArgName, py::return_value_policy::reference)
      .def("arg_names", &Benchmark::ArgNames,
           py::return_value_policy::reference)
      .def("range_pair", &Benchmark::RangePair,
           py::return_value_policy::reference, py::arg("lo1"), py::arg("hi1"),
           py::arg("lo2"), py::arg("hi2"))
      .def("range_multiplier", &Benchmark::RangeMultiplier,
           py::return_value_policy::reference)
      .def("min_time", &Benchmark::MinTime, py::return_value_policy::reference)
      .def("iterations", &Benchmark::Iterations,
           py::return_value_policy::reference)
      .def("repetitions", &Benchmark::Repetitions,
           py::return_value_policy::reference)
      .def("report_aggregates_only", &Benchmark::ReportAggregatesOnly,
           py::return_value_policy::reference, py::arg("value") = true)
      .def("display_aggregates_only", &Benchmark::DisplayAggregatesOnly,
           py::return_value_policy::reference, py::arg("value") = true)
      .def("measure_process_cpu_time", &Benchmark::MeasureProcessCPUTime,
           py::return_value_policy::reference)
      .def("use_real_time", &Benchmark::UseRealTime,
           py::return_value_policy::reference)
      .def("use_manual_time", &Benchmark::UseManualTime,
           py::return_value_policy::reference)
      .def(
          "complexity",
          (Benchmark * (Benchmark::*)(benchmark::BigO)) & Benchmark::Complexity,
          py::return_value_policy::reference,
          py::arg("complexity") = benchmark::oAuto);

  using benchmark::Counter;
  py::class_<Counter> py_counter(m, "Counter");

  py::enum_<Counter::Flags>(py_counter, "Flags")
      .value("kDefaults", Counter::Flags::kDefaults)
      .value("kIsRate", Counter::Flags::kIsRate)
      .value("kAvgThreads", Counter::Flags::kAvgThreads)
      .value("kAvgThreadsRate", Counter::Flags::kAvgThreadsRate)
      .value("kIsIterationInvariant", Counter::Flags::kIsIterationInvariant)
      .value("kIsIterationInvariantRate",
             Counter::Flags::kIsIterationInvariantRate)
      .value("kAvgIterations", Counter::Flags::kAvgIterations)
      .value("kAvgIterationsRate", Counter::Flags::kAvgIterationsRate)
      .value("kInvert", Counter::Flags::kInvert)
      .export_values()
      .def(py::self | py::self);

  py::enum_<Counter::OneK>(py_counter, "OneK")
      .value("kIs1000", Counter::OneK::kIs1000)
      .value("kIs1024", Counter::OneK::kIs1024)
      .export_values();

  py_counter
      .def(py::init<double, Counter::Flags, Counter::OneK>(),
           py::arg("value") = 0., py::arg("flags") = Counter::kDefaults,
           py::arg("k") = Counter::kIs1000)
      .def(py::init([](double value) { return Counter(value); }))
      .def_readwrite("value", &Counter::value)
      .def_readwrite("flags", &Counter::flags)
      .def_readwrite("oneK", &Counter::oneK);
  py::implicitly_convertible<py::float_, Counter>();
  py::implicitly_convertible<py::int_, Counter>();

  py::bind_map<benchmark::UserCounters>(m, "UserCounters");

  using benchmark::State;
  py::class_<State>(m, "State")
      .def("__bool__", &State::KeepRunning)
      .def_property_readonly("keep_running", &State::KeepRunning)
      .def("pause_timing", &State::PauseTiming)
      .def("resume_timing", &State::ResumeTiming)
      .def("skip_with_error", &State::SkipWithError)
      .def_property_readonly("error_occured", &State::error_occurred)
      .def("set_iteration_time", &State::SetIterationTime)
      .def_property("bytes_processed", &State::bytes_processed,
                    &State::SetBytesProcessed)
      .def_property("complexity_n", &State::complexity_length_n,
                    &State::SetComplexityN)
      .def_property("items_processed", &State::items_processed,
                    &State::SetItemsProcessed)
      .def("set_label", (void (State::*)(const char*)) & State::SetLabel)
      .def("range", &State::range, py::arg("pos") = 0)
      .def_property_readonly("iterations", &State::iterations)
      .def_readwrite("counters", &State::counters)
      .def_readonly("thread_index", &State::thread_index)
      .def_readonly("threads", &State::threads);

  m.def("Initialize", Initialize);
  m.def("RegisterBenchmark", RegisterBenchmark,
        py::return_value_policy::reference);
  m.def("RunSpecifiedBenchmarks",
        []() { benchmark::RunSpecifiedBenchmarks(); });
};
}  // namespace
