import gdb

class JsonValuePrinter:
    "Print a json-value"

    def __init__(self, val):
        self.val = val

    def to_string(self):
        if self.val.type.strip_typedefs().code == gdb.TYPE_CODE_FLT:
            return ("%.6f" % float(self.val)).rstrip("0")
        return self.val

def json_lookup_function(val):
    name = val.type.strip_typedefs().name
    if name and name.startswith("nlohmann::basic_json<") and name.endswith(">"):
        t = str(val['m_type'])
        if t.startswith("nlohmann::detail::value_t::"):
            try:
                union_val = val['m_value'][t[27:]]
                if union_val.type.code == gdb.TYPE_CODE_PTR:
                    return gdb.default_visualizer(union_val.dereference())
                else:
                    return JsonValuePrinter(union_val)
            except:
                return JsonValuePrinter(val['m_type'])

gdb.pretty_printers.append(json_lookup_function)
