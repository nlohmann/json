%token value_number value_string
%token begin_object end_object
%token begin_array end_array
%token literal_true literal_false literal_null
%token name_separator value_separator

%%

value:
  object | array | value_string | value_number | literal_true | literal_false | literal_null
;

object:
  begin_object end_object
| begin_object object_value_list end_object
;

object_value_list:
  value_string name_separator value
| value_string name_separator value value_separator object_value_list
;

array:
  begin_array end_array
| begin_array array_value_list end_array
;

array_value_list:
  value { /* value in array_value_list */ }
| value value_separator array_value_list
;
