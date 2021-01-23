#ifndef BENCHMARK_COMMANDLINEFLAGS_H_
#define BENCHMARK_COMMANDLINEFLAGS_H_

#include <cstdint>
#include <string>

// Macro for referencing flags.
#define FLAG(name) FLAGS_##name

// Macros for declaring flags.
#define DECLARE_bool(name) extern bool FLAG(name)
#define DECLARE_int32(name) extern int32_t FLAG(name)
#define DECLARE_double(name) extern double FLAG(name)
#define DECLARE_string(name) extern std::string FLAG(name)

// Macros for defining flags.
#define DEFINE_bool(name, default_val)            \
  bool FLAG(name) =                               \
    benchmark::BoolFromEnv(#name, default_val)
#define DEFINE_int32(name, default_val)           \
  int32_t FLAG(name) =                            \
    benchmark::Int32FromEnv(#name, default_val)
#define DEFINE_double(name, default_val)          \
  double FLAG(name) =                             \
    benchmark::DoubleFromEnv(#name, default_val)
#define DEFINE_string(name, default_val)          \
  std::string FLAG(name) =                        \
    benchmark::StringFromEnv(#name, default_val)

namespace benchmark {

// Parses a bool from the environment variable
// corresponding to the given flag.
//
// If the variable exists, returns IsTruthyFlagValue() value;  if not,
// returns the given default value.
bool BoolFromEnv(const char* flag, bool default_val);

// Parses an Int32 from the environment variable
// corresponding to the given flag.
//
// If the variable exists, returns ParseInt32() value;  if not, returns
// the given default value.
int32_t Int32FromEnv(const char* flag, int32_t default_val);

// Parses an Double from the environment variable
// corresponding to the given flag.
//
// If the variable exists, returns ParseDouble();  if not, returns
// the given default value.
double DoubleFromEnv(const char* flag, double default_val);

// Parses a string from the environment variable
// corresponding to the given flag.
//
// If variable exists, returns its value;  if not, returns
// the given default value.
const char* StringFromEnv(const char* flag, const char* default_val);

// Parses a string for a bool flag, in the form of either
// "--flag=value" or "--flag".
//
// In the former case, the value is taken as true if it passes IsTruthyValue().
//
// In the latter case, the value is taken as true.
//
// On success, stores the value of the flag in *value, and returns
// true.  On failure, returns false without changing *value.
bool ParseBoolFlag(const char* str, const char* flag, bool* value);

// Parses a string for an Int32 flag, in the form of
// "--flag=value".
//
// On success, stores the value of the flag in *value, and returns
// true.  On failure, returns false without changing *value.
bool ParseInt32Flag(const char* str, const char* flag, int32_t* value);

// Parses a string for a Double flag, in the form of
// "--flag=value".
//
// On success, stores the value of the flag in *value, and returns
// true.  On failure, returns false without changing *value.
bool ParseDoubleFlag(const char* str, const char* flag, double* value);

// Parses a string for a string flag, in the form of
// "--flag=value".
//
// On success, stores the value of the flag in *value, and returns
// true.  On failure, returns false without changing *value.
bool ParseStringFlag(const char* str, const char* flag, std::string* value);

// Returns true if the string matches the flag.
bool IsFlag(const char* str, const char* flag);

// Returns true unless value starts with one of: '0', 'f', 'F', 'n' or 'N', or
// some non-alphanumeric character. Also returns false if the value matches
// one of 'no', 'false', 'off' (case-insensitive). As a special case, also
// returns true if value is the empty string.
bool IsTruthyFlagValue(const std::string& value);

}  // end namespace benchmark

#endif  // BENCHMARK_COMMANDLINEFLAGS_H_
