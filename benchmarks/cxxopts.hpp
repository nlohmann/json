/*

Copyright (c) 2014 Jarryd Beck

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

*/

#ifndef CXX_OPTS_HPP
#define CXX_OPTS_HPP

#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wnon-virtual-dtor"
#endif

#include <exception>
#include <iostream>
#include <map>
#include <memory>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

//when we ask cxxopts to use Unicode, help strings are processed using ICU,
//which results in the correct lengths being computed for strings when they
//are formatted for the help output
//it is necessary to make sure that <unicode/unistr.h> can be found by the
//compiler, and that icu-uc is linked in to the binary.

#ifdef CXXOPTS_USE_UNICODE
#include <unicode/unistr.h>

namespace cxxopts
{
  typedef icu::UnicodeString String;

  inline
  String
  toLocalString(std::string s)
  {
    return icu::UnicodeString::fromUTF8(s);
  }

  class UnicodeStringIterator : public
    std::iterator<std::forward_iterator_tag, int32_t>
  {
    public:

    UnicodeStringIterator(const icu::UnicodeString* s, int32_t pos)
    : s(s)
    , i(pos)
    {
    }

    value_type
    operator*() const
    {
      return s->char32At(i);
    }

    bool
    operator==(const UnicodeStringIterator& rhs) const
    {
      return s == rhs.s && i == rhs.i;
    }

    bool
    operator!=(const UnicodeStringIterator& rhs) const
    {
      return !(*this == rhs);
    }

    UnicodeStringIterator&
    operator++()
    {
      ++i;
      return *this;
    }

    UnicodeStringIterator
    operator+(int32_t v)
    {
      return UnicodeStringIterator(s, i + v);
    }

    private:
    const icu::UnicodeString* s;
    int32_t i;
  };

  inline
  String&
  stringAppend(String&s, String a)
  {
    return s.append(std::move(a));
  }

  inline
  String&
  stringAppend(String& s, int n, UChar32 c)
  {
    for (int i = 0; i != n; ++i)
    {
      s.append(c);
    }

    return s;
  }

  template <typename Iterator>
  String&
  stringAppend(String& s, Iterator begin, Iterator end)
  {
    while (begin != end)
    {
      s.append(*begin);
      ++begin;
    }

    return s;
  }

  inline
  size_t
  stringLength(const String& s)
  {
    return s.length();
  }

  inline
  std::string
  toUTF8String(const String& s)
  {
    std::string result;
    s.toUTF8String(result);

    return result;
  }
}

namespace std
{
  cxxopts::UnicodeStringIterator
  begin(const icu::UnicodeString& s)
  {
    return cxxopts::UnicodeStringIterator(&s, 0);
  }

  cxxopts::UnicodeStringIterator
  end(const icu::UnicodeString& s)
  {
    return cxxopts::UnicodeStringIterator(&s, s.length());
  }
}

//ifdef CXXOPTS_USE_UNICODE
#else

namespace cxxopts
{
  typedef std::string String;

  template <typename T>
  T
  toLocalString(T&& t)
  {
    return t;
  }

  inline
  size_t
  stringLength(const String& s)
  {
    return s.length();
  }

  inline
  String&
  stringAppend(String&s, String a)
  {
    return s.append(std::move(a));
  }

  inline
  String&
  stringAppend(String& s, size_t n, char c)
  {
    return s.append(n, c);
  }

  template <typename Iterator>
  String&
  stringAppend(String& s, Iterator begin, Iterator end)
  {
    return s.append(begin, end);
  }

  template <typename T>
  std::string
  toUTF8String(T&& t)
  {
    return std::forward<T>(t);
  }

}

//ifdef CXXOPTS_USE_UNICODE
#endif

namespace cxxopts
{
  class Value : public std::enable_shared_from_this<Value>
  {
    public:

    virtual void
    parse(const std::string& text) const = 0;

    virtual void
    parse() const = 0;

    virtual bool
    has_arg() const = 0;

    virtual bool
    has_default() const = 0;

    virtual bool
    has_implicit() const = 0;

    virtual std::string
    get_default_value() const = 0;

    virtual std::string
    get_implicit_value() const = 0;

    virtual std::shared_ptr<Value>
    default_value(const std::string& value) = 0;

    virtual std::shared_ptr<Value>
    implicit_value(const std::string& value) = 0;
  };

  class OptionException : public std::exception
  {
    public:
    OptionException(const std::string& message)
    : m_message(message)
    {
    }

    virtual const char*
    what() const noexcept
    {
      return m_message.c_str();
    }

    private:
    std::string m_message;
  };

  class OptionSpecException : public OptionException
  {
    public:

    OptionSpecException(const std::string& message)
    : OptionException(message)
    {
    }
  };

  class OptionParseException : public OptionException
  {
    public:
    OptionParseException(const std::string& message)
    : OptionException(message)
    {
    }
  };

  class option_exists_error : public OptionSpecException
  {
    public:
    option_exists_error(const std::string& option)
    : OptionSpecException(u8"Option ‘" + option + u8"’ already exists")
    {
    }
  };

  class invalid_option_format_error : public OptionSpecException
  {
    public:
    invalid_option_format_error(const std::string& format)
    : OptionSpecException(u8"Invalid option format ‘" + format + u8"’")
    {
    }
  };

  class option_not_exists_exception : public OptionParseException
  {
    public:
    option_not_exists_exception(const std::string& option)
    : OptionParseException(u8"Option ‘" + option + u8"’ does not exist")
    {
    }
  };

  class missing_argument_exception : public OptionParseException
  {
    public:
    missing_argument_exception(const std::string& option)
    : OptionParseException(u8"Option ‘" + option + u8"’ is missing an argument")
    {
    }
  };

  class option_requires_argument_exception : public OptionParseException
  {
    public:
    option_requires_argument_exception(const std::string& option)
    : OptionParseException(u8"Option ‘" + option + u8"’ requires an argument")
    {
    }
  };

  class option_not_has_argument_exception : public OptionParseException
  {
    public:
    option_not_has_argument_exception
    (
      const std::string& option,
      const std::string& arg
    )
    : OptionParseException(
        u8"Option ‘" + option + u8"’ does not take an argument, but argument‘"
        + arg + "’ given")
    {
    }
  };

  class option_not_present_exception : public OptionParseException
  {
    public:
    option_not_present_exception(const std::string& option)
    : OptionParseException(u8"Option ‘" + option + u8"’ not present")
    {
    }
  };

  class argument_incorrect_type : public OptionParseException
  {
    public:
    argument_incorrect_type
    (
      const std::string& arg
    )
    : OptionParseException(
      u8"Argument ‘" + arg + u8"’ failed to parse"
    )
    {
    }
  };

  namespace values
  {
    template <typename T>
    void
    parse_value(const std::string& text, T& value)
    {
      std::istringstream is(text);
      if (!(is >> value))
      {
        std::cerr << "cannot parse empty value" << std::endl;
        throw argument_incorrect_type(text);
      }

      if (is.rdbuf()->in_avail() != 0)
      {
        throw argument_incorrect_type(text);
      }
    }

    template <typename T>
    void
    parse_value(const std::string& text, std::vector<T>& value)
    {
      T v;
      parse_value(text, v);
      value.push_back(v);
    }

    inline
    void
    parse_value(const std::string& /*text*/, bool& value)
    {
      //TODO recognise on, off, yes, no, enable, disable
      //so that we can write --long=yes explicitly
      value = true;
    }

    inline
    void
    parse_value(const std::string& text, std::string& value)
    {
      value = text;
    }

    template <typename T>
    struct value_has_arg
    {
      static constexpr bool value = true;
    };

    template <>
    struct value_has_arg<bool>
    {
      static constexpr bool value = false;
    };

    template <typename T>
    class standard_value : public Value
    {
      public:
      standard_value()
      : m_result(std::make_shared<T>())
      , m_store(m_result.get())
      {
      }

      standard_value(T* t)
      : m_store(t)
      {
      }

      void
      parse(const std::string& text) const
      {
        if (m_implicit && text.empty())
        {
          parse_value(m_implicit_value, *m_store);
        }
        else
        {
          parse_value(text, *m_store);
        }
      }

      void
      parse() const
      {
        parse_value(m_default_value, *m_store);
      }

      bool
      has_arg() const
      {
        return value_has_arg<T>::value;
      }

      bool
      has_default() const
      {
        return m_default;
      }

      bool
      has_implicit() const
      {
        return m_implicit;
      }

      virtual std::shared_ptr<Value>
      default_value(const std::string& value){
        m_default = true;
        m_default_value = value;
        return shared_from_this();
      }

      virtual std::shared_ptr<Value>
      implicit_value(const std::string& value){
        m_implicit = true;
        m_implicit_value = value;
        return shared_from_this();
      }

      std::string
      get_default_value() const
      {
        return m_default_value;
      }

      std::string
      get_implicit_value() const
      {
        return m_implicit_value;
      }

      const T&
      get() const
      {
        if (m_store == nullptr)
        {
          return *m_result;
        }
        else
        {
          return *m_store;
        }
      }

      protected:
      std::shared_ptr<T> m_result;
      T* m_store;
      bool m_default = false;
      std::string m_default_value;
      bool m_implicit = false;
      std::string m_implicit_value;
    };
  }

  template <typename T>
  std::shared_ptr<Value>
  value()
  {
    return std::make_shared<values::standard_value<T>>();
  }

  template <typename T>
  std::shared_ptr<Value>
  value(T& t)
  {
    return std::make_shared<values::standard_value<T>>(&t);
  }

  class OptionAdder;

  class OptionDetails
  {
    public:
    OptionDetails
    (
      const String& description,
      std::shared_ptr<const Value> value
    )
    : m_desc(description)
    , m_value(value)
    , m_count(0)
    {
    }

    const String&
    description() const
    {
      return m_desc;
    }

    bool
    has_arg() const
    {
      return m_value->has_arg();
    }

    void
    parse(const std::string& text)
    {
      m_value->parse(text);
      ++m_count;
    }

    void
    parse_default()
    {
      m_value->parse();
      ++m_count;
    }

    int
    count() const
    {
      return m_count;
    }

    const Value& value() const {
        return *m_value;
    }

    template <typename T>
    const T&
    as() const
    {
#ifdef CXXOPTS_NO_RTTI
      return static_cast<const values::standard_value<T>&>(*m_value).get();
#else
      return dynamic_cast<const values::standard_value<T>&>(*m_value).get();
#endif
    }

    private:
    String m_desc;
    std::shared_ptr<const Value> m_value;
    int m_count;
  };

  struct HelpOptionDetails
  {
    std::string s;
    std::string l;
    String desc;
    bool has_arg;
    bool has_default;
    std::string default_value;
    bool has_implicit;
    std::string implicit_value;
    std::string arg_help;
  };

  struct HelpGroupDetails
  {
    std::string name;
    std::string description;
    std::vector<HelpOptionDetails> options;
  };

  class Options
  {
    public:

    Options(std::string program, std::string help_string = "")
    : m_program(std::move(program))
    , m_help_string(toLocalString(std::move(help_string)))
    {
    }

    inline
    void
    parse(int& argc, char**& argv);

    inline
    OptionAdder
    add_options(std::string group = "");

    inline
    void
    add_option
    (
      const std::string& group,
      const std::string& s,
      const std::string& l,
      std::string desc,
      std::shared_ptr<const Value> value,
      std::string arg_help
    );

    int
    count(const std::string& o) const
    {
      auto iter = m_options.find(o);
      if (iter == m_options.end())
      {
        return 0;
      }

      return iter->second->count();
    }

    const OptionDetails&
    operator[](const std::string& option) const
    {
      auto iter = m_options.find(option);

      if (iter == m_options.end())
      {
        throw option_not_present_exception(option);
      }

      return *iter->second;
    }

    //parse positional arguments into the given option
    inline
    void
    parse_positional(std::string option);

    inline
    std::string
    help(const std::vector<std::string>& groups = {""}) const;

    inline
    const std::vector<std::string>
    groups() const;

    inline
    const HelpGroupDetails&
    group_help(const std::string& group) const;

    private:

    inline
    void
    add_one_option
    (
      const std::string& option,
      std::shared_ptr<OptionDetails> details
    );

    inline
    bool
    consume_positional(std::string a);

    inline
    void
    add_to_option(const std::string& option, const std::string& arg);

    inline
    void
    parse_option
    (
      std::shared_ptr<OptionDetails> value,
      const std::string& name,
      const std::string& arg = ""
    );

    inline
    void
    checked_parse_arg
    (
      int argc,
      char* argv[],
      int& current,
      std::shared_ptr<OptionDetails> value,
      const std::string& name
    );

    inline
    String
    help_one_group(const std::string& group) const;

    std::string m_program;
    String m_help_string;

    std::map<std::string, std::shared_ptr<OptionDetails>> m_options;
    std::string m_positional;

    //mapping from groups to help options
    std::map<std::string, HelpGroupDetails> m_help;
  };

  class OptionAdder
  {
    public:

    OptionAdder(Options& options, std::string group)
    : m_options(options), m_group(std::move(group))
    {
    }

    inline
    OptionAdder&
    operator()
    (
      const std::string& opts,
      const std::string& desc,
      std::shared_ptr<const Value> value
        = ::cxxopts::value<bool>(),
      std::string arg_help = ""
    );

    private:
    Options& m_options;
    std::string m_group;
  };

}

namespace cxxopts
{

  namespace
  {

    constexpr int OPTION_LONGEST = 30;
    constexpr int OPTION_DESC_GAP = 2;

    std::basic_regex<char> option_matcher
      ("--([[:alnum:]][-_[:alnum:]]+)(=(.*))?|-([a-zA-Z]+)");

    std::basic_regex<char> option_specifier
      ("(([a-zA-Z]),)?([a-zA-Z0-9][-_a-zA-Z0-9]+)");

    String
    format_option
    (
      const HelpOptionDetails& o
    )
    {
      auto& s = o.s;
      auto& l = o.l;

      String result = "  ";

      if (s.size() > 0)
      {
        result += "-" + toLocalString(s) + ",";
      }
      else
      {
        result += "   ";
      }

      if (l.size() > 0)
      {
        result += " --" + toLocalString(l);
      }

      if (o.has_arg)
      {
        auto arg = o.arg_help.size() > 0 ? toLocalString(o.arg_help) : "arg";

        if (o.has_implicit)
        {
          result += " [=" + arg + "(=" + toLocalString(o.implicit_value) + ")]";
        }
        else
        {
          result += " " + arg;
        }
      }

      return result;
    }

    String
    format_description
    (
      const HelpOptionDetails& o,
      size_t start,
      size_t width
    )
    {
      auto desc = o.desc;

      if (o.has_default)
      {
        desc += toLocalString(" (default:" + o.default_value + ")");
      }

      String result;

      auto current = std::begin(desc);
      auto startLine = current;
      auto lastSpace = current;

      auto size = size_t{};

      while (current != std::end(desc))
      {
        if (*current == ' ')
        {
          lastSpace = current;
        }

        if (size > width)
        {
          if (lastSpace == startLine)
          {
            stringAppend(result, startLine, current + 1);
            stringAppend(result, "\n");
            stringAppend(result, start, ' ');
            startLine = current + 1;
            lastSpace = startLine;
          }
          else
          {
            stringAppend(result, startLine, lastSpace);
            stringAppend(result, "\n");
            stringAppend(result, start, ' ');
            startLine = lastSpace + 1;
          }
          size = 0;
        }
        else
        {
          ++size;
        }

        ++current;
      }

      //append whatever is left
      stringAppend(result, startLine, current);

      return result;
    }
  }

OptionAdder
Options::add_options(std::string group)
{
  return OptionAdder(*this, std::move(group));
}

OptionAdder&
OptionAdder::operator()
(
  const std::string& opts,
  const std::string& desc,
  std::shared_ptr<const Value> value,
  std::string arg_help
)
{
  std::match_results<const char*> result;
  std::regex_match(opts.c_str(), result, option_specifier);

  if (result.empty())
  {
    throw invalid_option_format_error(opts);
  }

  const auto& s = result[2];
  const auto& l = result[3];

  m_options.add_option(m_group, s.str(), l.str(), desc, value,
    std::move(arg_help));

  return *this;
}

void
Options::parse_option
(
  std::shared_ptr<OptionDetails> value,
  const std::string& /*name*/,
  const std::string& arg
)
{
  value->parse(arg);
}

void
Options::checked_parse_arg
(
  int argc,
  char* argv[],
  int& current,
  std::shared_ptr<OptionDetails> value,
  const std::string& name
)
{
  if (current + 1 >= argc)
  {
    if (value->value().has_implicit())
    {
      parse_option(value, name, "");
    }
    else
    {
      throw missing_argument_exception(name);
    }
  }
  else
  {
    if (argv[current + 1][0] == '-' && value->value().has_implicit())
    {
      parse_option(value, name, "");
    }
    else
    {
      parse_option(value, name, argv[current + 1]);
      ++current;
    }
  }
}

void
Options::add_to_option(const std::string& option, const std::string& arg)
{
  auto iter = m_options.find(option);

  if (iter == m_options.end())
  {
    throw option_not_exists_exception(option);
  }

  parse_option(iter->second, option, arg);
}

bool
Options::consume_positional(std::string a)
{
  if (m_positional.size() > 0)
  {
    add_to_option(m_positional, a);
    return true;
  }
  else
  {
    return false;
  }
}

void
Options::parse_positional(std::string option)
{
  m_positional = std::move(option);
}

void
Options::parse(int& argc, char**& argv)
{
  int current = 1;

  int nextKeep = 1;

  while (current != argc)
  {
    std::match_results<const char*> result;
    std::regex_match(argv[current], result, option_matcher);

    if (result.empty())
    {
      //not a flag

      //if true is returned here then it was consumed, otherwise it is
      //ignored
      if (consume_positional(argv[current]))
      {
      }
      else
      {
        argv[nextKeep] = argv[current];
        ++nextKeep;
      }
      //if we return from here then it was parsed successfully, so continue
    }
    else
    {
      //short or long option?
      if (result[4].length() != 0)
      {
        const std::string& s = result[4];

        for (std::size_t i = 0; i != s.size(); ++i)
        {
          std::string name(1, s[i]);
          auto iter = m_options.find(name);

          if (iter == m_options.end())
          {
            throw option_not_exists_exception(name);
          }

          auto value = iter->second;

          //if no argument then just add it
          if (!value->has_arg())
          {
            parse_option(value, name);
          }
          else
          {
            //it must be the last argument
            if (i + 1 == s.size())
            {
              checked_parse_arg(argc, argv, current, value, name);
            }
            else if (value->value().has_implicit())
            {
              parse_option(value, name, "");
            }
            else
            {
              //error
              throw option_requires_argument_exception(name);
            }
          }
        }
      }
      else if (result[1].length() != 0)
      {
        const std::string& name = result[1];

        auto iter = m_options.find(name);

        if (iter == m_options.end())
        {
          throw option_not_exists_exception(name);
        }

        auto opt = iter->second;

        //equals provided for long option?
        if (result[3].length() != 0)
        {
          //parse the option given

          //but if it doesn't take an argument, this is an error
          if (!opt->has_arg())
          {
            throw option_not_has_argument_exception(name, result[3]);
          }

          parse_option(opt, name, result[3]);
        }
        else
        {
          if (opt->has_arg())
          {
            //parse the next argument
            checked_parse_arg(argc, argv, current, opt, name);
          }
          else
          {
            //parse with empty argument
            parse_option(opt, name);
          }
        }
      }

    }

    ++current;
  }

  for (auto& opt : m_options)
  {
    auto& detail = opt.second;
    auto& value = detail->value();

    if(!detail->count() && value.has_default()){
      detail->parse_default();
    }
  }

  argc = nextKeep;
}

void
Options::add_option
(
  const std::string& group,
  const std::string& s,
  const std::string& l,
  std::string desc,
  std::shared_ptr<const Value> value,
  std::string arg_help
)
{
  auto stringDesc = toLocalString(std::move(desc));
  auto option = std::make_shared<OptionDetails>(stringDesc, value);

  if (s.size() > 0)
  {
    add_one_option(s, option);
  }

  if (l.size() > 0)
  {
    add_one_option(l, option);
  }

  //add the help details
  auto& options = m_help[group];

  options.options.emplace_back(HelpOptionDetails{s, l, stringDesc,
      value->has_arg(),
      value->has_default(), value->get_default_value(),
      value->has_implicit(), value->get_implicit_value(),
      std::move(arg_help)});
}

void
Options::add_one_option
(
  const std::string& option,
  std::shared_ptr<OptionDetails> details
)
{
  auto in = m_options.emplace(option, details);

  if (!in.second)
  {
    throw option_exists_error(option);
  }
}

String
Options::help_one_group(const std::string& g) const
{
  typedef std::vector<std::pair<String, String>> OptionHelp;

  auto group = m_help.find(g);
  if (group == m_help.end())
  {
    return "";
  }

  OptionHelp format;

  size_t longest = 0;

  String result;

  if (!g.empty())
  {
    result += toLocalString(" " + g + " options:\n\n");
  }

  for (const auto& o : group->second.options)
  {
    auto s = format_option(o);
    longest = std::max(longest, stringLength(s));
    format.push_back(std::make_pair(s, String()));
  }

  longest = std::min(longest, static_cast<size_t>(OPTION_LONGEST));

  //widest allowed description
  auto allowed = size_t{76} - longest - OPTION_DESC_GAP;

  auto fiter = format.begin();
  for (const auto& o : group->second.options)
  {
    auto d = format_description(o, longest + OPTION_DESC_GAP, allowed);

    result += fiter->first;
    if (stringLength(fiter->first) > longest)
    {
      result += "\n";
      result += toLocalString(std::string(longest + OPTION_DESC_GAP, ' '));
    }
    else
    {
      result += toLocalString(std::string(longest + OPTION_DESC_GAP -
        stringLength(fiter->first),
        ' '));
    }
    result += d;
    result += "\n";

    ++fiter;
  }

  return result;
}

std::string
Options::help(const std::vector<std::string>& groups) const
{
  String result = "Usage:\n  " + toLocalString(m_program) + " [OPTION...]"
    + m_help_string + "\n\n";

  for (std::size_t i = 0; i < groups.size(); ++i)
  {
    result += help_one_group(groups[i]);
    if (i < groups.size() - 1)
    {
      result += "\n";
    }
  }

  return toUTF8String(result);
}

const std::vector<std::string>
Options::groups() const
{
  std::vector<std::string> g;

  std::transform(
    m_help.begin(),
    m_help.end(),
    std::back_inserter(g),
    [] (const std::map<std::string, HelpGroupDetails>::value_type& pair)
    {
      return pair.first;
    }
  );

  return g;
}

const HelpGroupDetails&
Options::group_help(const std::string& group) const
{
  return m_help.at(group);
}

}

#if defined(__GNU__)
#pragma GCC diagnostic pop
#endif

#endif //CXX_OPTS_HPP