from sigma.conversion.deferred import DeferredQueryExpression, DeferredTextQueryExpression
from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule
from sigma.conversion.base import TextQueryBackend
from sigma.conditions import ConditionItem, ConditionAND, ConditionOR, ConditionNOT, ConditionType
from sigma.types import SigmaCompareExpression, SigmaRegularExpression, SigmaRegularExpressionFlag
import re
from typing import ClassVar, Dict, Tuple, Pattern, List, Any, Optional, Union


class AzureDeferredWhereExpression(DeferredTextQueryExpression):
    template = 'where {op}{value}'
    operators = {
        True: "not",
        False: "",
    }
    default_field = None


class AzureLogsourceDeferredExpression(DeferredTextQueryExpression):
    template = '{value}'
    operators = {
        True: "not",
        False: "",
    }
    default_field = None


class AzureBackend(TextQueryBackend):
    """azure backend."""
    # See the pySigma documentation for further infromation:
    # https://sigmahq-pysigma.readthedocs.io/en/latest/Backends.html

    # Operator precedence: tuple of Condition{AND,OR,NOT} in order of precedence.
    # The backend generates grouping if required
    name: ClassVar[str] = "Azure Backend"
    formats: Dict[str, str] = {
        "default": "Plain Azure queries",
    }
    requires_pipeline: bool = False

    precedence: ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (ConditionNOT, ConditionAND, ConditionOR)
    group_expression: ClassVar[str] = "({expr})"   # Expression for precedence override grouping as format string with {expr} placeholder
    parenthesize: bool = True

    # Generated query tokens
    token_separator: str = " "     # separator inserted between all boolean operators
    or_token: ClassVar[str] = "or"
    and_token: ClassVar[str] = "and"
    not_token: ClassVar[str] = "not"
    eq_token: ClassVar[str] = token_separator + "=~" + token_separator  # Token inserted between field and value (without separator)

    # String output
    ## Fields
    ### Quoting
    field_quote: ClassVar[str] = "'"                               # Character used to quote field characters if field_quote_pattern matches (or not, depending on field_quote_pattern_negation). No field name quoting is done if not set.
    field_quote_pattern: ClassVar[Pattern] = re.compile("^\\w+$")   # Quote field names if this pattern (doesn't) matches, depending on field_quote_pattern_negation. Field name is always quoted if pattern is not set.
    field_quote_pattern_negation: ClassVar[bool] = True            # Negate field_quote_pattern result. Field name is quoted if pattern doesn't matches if set to True (default).

    ### Escaping
    field_escape: ClassVar[str] = "\\"               # Character to escape particular parts defined in field_escape_pattern.
    field_escape_quote: ClassVar[bool] = False        # Escape quote string defined in field_quote
    field_escape_pattern: ClassVar[Pattern] = re.compile(r'\\')   # All matches of this pattern are prepended with the string contained in field_escape.

    ## Values
    str_quote      : ClassVar[str] = '"'     # string quoting character (added as escaping character)
    escape_char    : ClassVar[str] = "\\"    # Escaping character for special characrers inside string
    wildcard_multi : ClassVar[str] = "*"     # Character used as multi-character wildcard
    wildcard_single: ClassVar[str] = "*"     # Character used as single-character wildcard
    add_escaped    : ClassVar[str] = ""    # Characters quoted in addition to wildcards and string quote
    filter_chars   : ClassVar[str] = ""      # Characters filtered
    bool_values    : ClassVar[Dict[bool, str]] = {   # Values to which boolean values are mapped.
        True: "true",
        False: "false",
    }

    # String matching operators. if none is appropriate eq_token is used.
    startswith_expression: ClassVar[str] = "{field} startswith {value}"
    endswith_expression  : ClassVar[str] = "{field} endswith {value}"
    contains_expression  : ClassVar[str] = "{field} contains {value}"
    wildcard_match_expression: ClassVar[str] = "{field} match {value}"      # Special expression if wildcards can't be matched with the eq_token operator

    # Regular expressions
    # Regular expression query as format string with placeholders {field}, {regex}, {flag_x} where x
    # is one of the flags shortcuts supported by Sigma (currently i, m and s) and refers to the
    # token stored in the class variable re_flags.
    re_expression: ClassVar[str] = '{field} matches regex "{regex}"'
    re_escape_char: ClassVar[str] = "\\"               # Character used for escaping in regular expressions
    re_escape: ClassVar[Tuple[str]] = ()               # List of strings that are escaped
    re_escape_escape_char: bool = True                 # If True, the escape character is also escaped
    re_flag_prefix: bool = True                        # If True, the flags are prepended as (?x) group at the beginning of the regular expression, e.g. (?i). If this is not supported by the target, it should be set to False.
    # Mapping from SigmaRegularExpressionFlag values to static string templates that are used in
    # flag_x placeholders in re_expression template.
    # By default, i, m and s are defined. If a flag is not supported by the target query language,
    # remove it from re_flags or don't define it to ensure proper error handling in case of appearance.
    re_flags: Dict[SigmaRegularExpressionFlag, str] = {
        SigmaRegularExpressionFlag.IGNORECASE: "i",
        SigmaRegularExpressionFlag.MULTILINE: "m",
        SigmaRegularExpressionFlag.DOTALL   : "s",
    }

    # Case sensitive string matching expression. String is quoted/escaped like a normal string.
    # Placeholders {field} and {value} are replaced with field name and quoted/escaped string.
    case_sensitive_match_expression: ClassVar[str] = "{field} casematch {value}"
    # Case sensitive string matching operators similar to standard string matching. If not provided,
    # case_sensitive_match_expression is used.
    case_sensitive_startswith_expression: ClassVar[str] = "{field} casematch_startswith {value}"
    case_sensitive_endswith_expression  : ClassVar[str] = "{field} casematch_endswith {value}"
    case_sensitive_contains_expression  : ClassVar[str] = "{field} casematch_contains {value}"

    # cidr expressions
    cidr_wildcard: ClassVar[str] = "*"    # Character used as single wildcard
    cidr_expression: ClassVar[str] = 'ipv4_is_in_range({field}, "{value}")'    # CIDR expression query as format string with placeholders {field} = {value}
    cidr_in_list_expression: ClassVar[str] = "{field} in ({value})"    # CIDR expression query as format string with placeholders {field} = in({list})

    # Numeric comparison operators
    compare_op_expression: ClassVar[str] = "{field}" + token_separator + "{operator}" + token_separator + "{value}"  # Compare operation query as format string with placeholders {field}, {operator} and {value}
    # Mapping between CompareOperators elements and strings used as replacement for {operator} in compare_op_expression
    compare_operators: ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT : "<",
        SigmaCompareExpression.CompareOperators.LTE: "<=",
        SigmaCompareExpression.CompareOperators.GT : ">",
        SigmaCompareExpression.CompareOperators.GTE: ">=",
    }

    # Expression for comparing two event fields
    field_equals_field_expression: ClassVar[Optional[str]] = None  # Field comparison expression with the placeholders {field1} and {field2} corresponding to left field and right value side of Sigma detection item
    field_equals_field_escaping_quoting: Tuple[bool, bool] = (True, True)   # If regular field-escaping/quoting is applied to field1 and field2. A custom escaping/quoting can be implemented in the convert_condition_field_eq_field_escape_and_quote method.

    # Null/None expressions
    field_null_expression: ClassVar[str] = "{field} is null"          # Expression for field has null value as format string with {field} placeholder for field name

    # Field existence condition expressions.
    field_exists_expression: ClassVar[str] = "exists({field})"             # Expression for field existence as format string with {field} placeholder for field name
    field_not_exists_expression: ClassVar[str] = "notexists({field})"      # Expression for field non-existence as format string with {field} placeholder for field name. If not set, field_exists_expression is negated with boolean NOT.

    # Field value in list, e.g. "field in (value list)" or "field containsall (value list)"
    convert_or_as_in: ClassVar[bool] = True                     # Convert OR as in-expression
    convert_and_as_in: ClassVar[bool] = False                    # Convert AND as in-expression
    in_expressions_allow_wildcards: ClassVar[bool] = True       # Values in list can contain wildcards. If set to False (default) only plain values are converted into in-expressions.
    field_in_list_expression: ClassVar[str] = "{field} {op} ({list})"  # Expression for field in list of values as format string with placeholders {field}, {op} and {list}
    or_in_operator: ClassVar[str] = "in"               # Operator used to convert OR into in-expressions. Must be set if convert_or_as_in is set
    and_in_operator: ClassVar[str] = "contains-all"    # Operator used to convert AND into in-expressions. Must be set if convert_and_as_in is set
    list_separator: ClassVar[str] = ", "               # List element separator

    # Value not bound to a field
    unbound_value_str_expression: ClassVar[str] = '["*"] contains {value}'  # Expression for string value not bound to a field as format string with placeholder {value}
    unbound_value_num_expression: ClassVar[str] = '["*"] contains "{value}"'  # Expression for number value not bound to a field as format string with placeholder {value}
    unbound_value_re_expression: ClassVar[str] = '_=~{value}'   # Expression for regular expression not bound to a field as format string with placeholder {value} and {flag_x} as described for re_expression

    # Query finalization: appending and concatenating deferred query part
    deferred_start: ClassVar[str] = "\n| "               # String used as separator between main query and deferred parts
    deferred_separator: ClassVar[str] = "\n| "           # String used to join multiple deferred query parts
    deferred_only_query: ClassVar[str] = "union *"            # String used as query if final query only contains deferred expression

    # TODO: implement custom methods for query elements not covered by the default backend base.
    # Documentation: https://sigmahq-pysigma.readthedocs.io/en/latest/Backends.html

    def convert_condition(self, cond: ConditionType, state: ConversionState) -> Any:
        """
        Start with a deferred where expression
        """
        if getattr(cond, 'field', '') == '__azure_logsource':
            return AzureLogsourceDeferredExpression(state, field=None, value=str(cond.value))

        if len(cond.parent_chain_condition_classes()) == 0:
            return AzureDeferredWhereExpression(state, field=None, value=super().convert_condition(cond, state))

        return super().convert_condition(cond, state)

    def escape_and_quote_field(self, field_name: str) -> str:
        """
        Wrap raw field names with brackets if they have spaces.
        """
        field = super().escape_and_quote_field(field_name)

        if field.startswith(self.field_quote) and field.endswith(self.field_quote):
            field = "[" + field + "]"

        return field

    def finalize_query(self, rule: SigmaRule, query: Union[str, DeferredQueryExpression], index: int, state: ConversionState, output_format: str) -> Union[str, DeferredQueryExpression]:
        """
        Converting our "AzureLogsourceDeferredExpression" into an Azure Table Prefix
        """

        logsource_expressions = [deferred for deferred in state.deferred if isinstance(deferred, AzureLogsourceDeferredExpression)]
        if len(logsource_expressions):
            query = logsource_expressions[0].value  # TODO Might be more than one table
            state.deferred = list(filter(lambda d: not isinstance(d, AzureLogsourceDeferredExpression), state.deferred))

        return super().finalize_query(rule, query, index, state, output_format)
