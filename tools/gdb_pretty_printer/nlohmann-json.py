import gdb
import re

ns_pattern = re.compile(r'nlohmann(::json_abi(?P<tags>\w*)(_v(?P<v_major>\d+)_(?P<v_minor>\d+)_(?P<v_patch>\d+))?)?::(?P<name>.+)')
class JsonValuePrinter:
    "Print a json-value"

    def __init__(self, val):
        self.val = val

    def to_string(self):
        if self.val.type.strip_typedefs().code == gdb.TYPE_CODE_FLT:
            return ("%.6f" % float(self.val)).rstrip("0")
        return self.val

def json_lookup_function(val):
    if m := ns_pattern.fullmatch(str(val.type.strip_typedefs().name)):
      name = m.group('name')
      if name and name.startswith('basic_json<') and name.endswith('>'):
          m = ns_pattern.fullmatch(str(val['m_type']))
          t = m.group('name')
          if t and t.startswith('detail::value_t::'):
              try:
                  union_val = val['m_value'][t.removeprefix('detail::value_t::')]
                  if union_val.type.code == gdb.TYPE_CODE_PTR:
                      return gdb.default_visualizer(union_val.dereference())
                  else:
                      return JsonValuePrinter(union_val)
              except Exception:
                  return JsonValuePrinter(val['m_type'])

gdb.pretty_printers.append(json_lookup_function)
