#include "string_util.h"

#include <array>
#include <cmath>
#include <cstdarg>
#include <cstdio>
#include <memory>
#include <sstream>

#include "arraysize.h"

namespace benchmark {
namespace {

// kilo, Mega, Giga, Tera, Peta, Exa, Zetta, Yotta.
const char kBigSIUnits[] = "kMGTPEZY";
// Kibi, Mebi, Gibi, Tebi, Pebi, Exbi, Zebi, Yobi.
const char kBigIECUnits[] = "KMGTPEZY";
// milli, micro, nano, pico, femto, atto, zepto, yocto.
const char kSmallSIUnits[] = "munpfazy";

// We require that all three arrays have the same size.
static_assert(arraysize(kBigSIUnits) == arraysize(kBigIECUnits),
              "SI and IEC unit arrays must be the same size");
static_assert(arraysize(kSmallSIUnits) == arraysize(kBigSIUnits),
              "Small SI and Big SI unit arrays must be the same size");

static const int64_t kUnitsSize = arraysize(kBigSIUnits);

void ToExponentAndMantissa(double val, double thresh, int precision,
                           double one_k, std::string* mantissa,
                           int64_t* exponent) {
  std::stringstream mantissa_stream;

  if (val < 0) {
    mantissa_stream << "-";
    val = -val;
  }

  // Adjust threshold so that it never excludes things which can't be rendered
  // in 'precision' digits.
  const double adjusted_threshold =
      std::max(thresh, 1.0 / std::pow(10.0, precision));
  const double big_threshold = adjusted_threshold * one_k;
  const double small_threshold = adjusted_threshold;
  // Values in ]simple_threshold,small_threshold[ will be printed as-is
  const double simple_threshold = 0.01;

  if (val > big_threshold) {
    // Positive powers
    double scaled = val;
    for (size_t i = 0; i < arraysize(kBigSIUnits); ++i) {
      scaled /= one_k;
      if (scaled <= big_threshold) {
        mantissa_stream << scaled;
        *exponent = i + 1;
        *mantissa = mantissa_stream.str();
        return;
      }
    }
    mantissa_stream << val;
    *exponent = 0;
  } else if (val < small_threshold) {
    // Negative powers
    if (val < simple_threshold) {
      double scaled = val;
      for (size_t i = 0; i < arraysize(kSmallSIUnits); ++i) {
        scaled *= one_k;
        if (scaled >= small_threshold) {
          mantissa_stream << scaled;
          *exponent = -static_cast<int64_t>(i + 1);
          *mantissa = mantissa_stream.str();
          return;
        }
      }
    }
    mantissa_stream << val;
    *exponent = 0;
  } else {
    mantissa_stream << val;
    *exponent = 0;
  }
  *mantissa = mantissa_stream.str();
}

std::string ExponentToPrefix(int64_t exponent, bool iec) {
  if (exponent == 0) return "";

  const int64_t index = (exponent > 0 ? exponent - 1 : -exponent - 1);
  if (index >= kUnitsSize) return "";

  const char* array =
      (exponent > 0 ? (iec ? kBigIECUnits : kBigSIUnits) : kSmallSIUnits);
  if (iec)
    return array[index] + std::string("i");
  else
    return std::string(1, array[index]);
}

std::string ToBinaryStringFullySpecified(double value, double threshold,
                                         int precision, double one_k = 1024.0) {
  std::string mantissa;
  int64_t exponent;
  ToExponentAndMantissa(value, threshold, precision, one_k, &mantissa,
                        &exponent);
  return mantissa + ExponentToPrefix(exponent, false);
}

}  // end namespace

void AppendHumanReadable(int n, std::string* str) {
  std::stringstream ss;
  // Round down to the nearest SI prefix.
  ss << ToBinaryStringFullySpecified(n, 1.0, 0);
  *str += ss.str();
}

std::string HumanReadableNumber(double n, double one_k) {
  // 1.1 means that figures up to 1.1k should be shown with the next unit down;
  // this softens edge effects.
  // 1 means that we should show one decimal place of precision.
  return ToBinaryStringFullySpecified(n, 1.1, 1, one_k);
}

std::string StrFormatImp(const char* msg, va_list args) {
  // we might need a second shot at this, so pre-emptivly make a copy
  va_list args_cp;
  va_copy(args_cp, args);

  // TODO(ericwf): use std::array for first attempt to avoid one memory
  // allocation guess what the size might be
  std::array<char, 256> local_buff;
  std::size_t size = local_buff.size();
  // 2015-10-08: vsnprintf is used instead of snd::vsnprintf due to a limitation
  // in the android-ndk
  auto ret = vsnprintf(local_buff.data(), size, msg, args_cp);

  va_end(args_cp);

  // handle empty expansion
  if (ret == 0) return std::string{};
  if (static_cast<std::size_t>(ret) < size)
    return std::string(local_buff.data());

  // we did not provide a long enough buffer on our first attempt.
  // add 1 to size to account for null-byte in size cast to prevent overflow
  size = static_cast<std::size_t>(ret) + 1;
  auto buff_ptr = std::unique_ptr<char[]>(new char[size]);
  // 2015-10-08: vsnprintf is used instead of snd::vsnprintf due to a limitation
  // in the android-ndk
  ret = vsnprintf(buff_ptr.get(), size, msg, args);
  return std::string(buff_ptr.get());
}

std::string StrFormat(const char* format, ...) {
  va_list args;
  va_start(args, format);
  std::string tmp = StrFormatImp(format, args);
  va_end(args);
  return tmp;
}

void ReplaceAll(std::string* str, const std::string& from,
                const std::string& to) {
  std::size_t start = 0;
  while ((start = str->find(from, start)) != std::string::npos) {
    str->replace(start, from.length(), to);
    start += to.length();
  }
}

}  // end namespace benchmark
