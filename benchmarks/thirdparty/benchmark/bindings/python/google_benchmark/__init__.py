# Copyright 2020 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Python benchmarking utilities.

Example usage:
  import google_benchmark as benchmark

  @benchmark.register
  def my_benchmark(state):
      ...  # Code executed outside `while` loop is not timed.

      while state:
        ...  # Code executed within `while` loop is timed.

  if __name__ == '__main__':
    benchmark.main()
"""

from absl import app
from google_benchmark import _benchmark
from google_benchmark._benchmark import (
    Counter,
    kNanosecond,
    kMicrosecond,
    kMillisecond,
    oNone,
    o1,
    oN,
    oNSquared,
    oNCubed,
    oLogN,
    oNLogN,
    oAuto,
    oLambda,
)


__all__ = [
    "register",
    "main",
    "Counter",
    "kNanosecond",
    "kMicrosecond",
    "kMillisecond",
    "oNone",
    "o1",
    "oN",
    "oNSquared",
    "oNCubed",
    "oLogN",
    "oNLogN",
    "oAuto",
    "oLambda",
]

__version__ = "0.2.0"


class __OptionMaker:
    """A stateless class to collect benchmark options.

    Collect all decorator calls like @option.range(start=0, limit=1<<5).
    """

    class Options:
        """Pure data class to store options calls, along with the benchmarked function."""

        def __init__(self, func):
            self.func = func
            self.builder_calls = []

    @classmethod
    def make(cls, func_or_options):
        """Make Options from Options or the benchmarked function."""
        if isinstance(func_or_options, cls.Options):
            return func_or_options
        return cls.Options(func_or_options)

    def __getattr__(self, builder_name):
        """Append option call in the Options."""

        # The function that get returned on @option.range(start=0, limit=1<<5).
        def __builder_method(*args, **kwargs):

            # The decorator that get called, either with the benchmared function
            # or the previous Options
            def __decorator(func_or_options):
                options = self.make(func_or_options)
                options.builder_calls.append((builder_name, args, kwargs))
                # The decorator returns Options so it is not technically a decorator
                # and needs a final call to @regiser
                return options

            return __decorator

        return __builder_method


# Alias for nicer API.
# We have to instanciate an object, even if stateless, to be able to use __getattr__
# on option.range
option = __OptionMaker()


def register(undefined=None, *, name=None):
    """Register function for benchmarking."""
    if undefined is None:
        # Decorator is called without parenthesis so we return a decorator
        return lambda f: register(f, name=name)

    # We have either the function to benchmark (simple case) or an instance of Options
    # (@option._ case).
    options = __OptionMaker.make(undefined)

    if name is None:
        name = options.func.__name__

    # We register the benchmark and reproduce all the @option._ calls onto the
    # benchmark builder pattern
    benchmark = _benchmark.RegisterBenchmark(name, options.func)
    for name, args, kwargs in options.builder_calls[::-1]:
        getattr(benchmark, name)(*args, **kwargs)

    # return the benchmarked function because the decorator does not modify it
    return options.func


def _flags_parser(argv):
    argv = _benchmark.Initialize(argv)
    return app.parse_flags_with_usage(argv)


def _run_benchmarks(argv):
    if len(argv) > 1:
        raise app.UsageError("Too many command-line arguments.")
    return _benchmark.RunSpecifiedBenchmarks()


def main(argv=None):
    return app.run(_run_benchmarks, argv=argv, flags_parser=_flags_parser)


# Methods for use with custom main function.
initialize = _benchmark.Initialize
run_benchmarks = _benchmark.RunSpecifiedBenchmarks
