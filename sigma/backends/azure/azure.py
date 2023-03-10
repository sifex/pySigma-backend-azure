import random
import re
from typing import ClassVar, Dict, Tuple, Pattern, Any, Union

from sigma.conditions import ConditionItem, ConditionAND, ConditionOR, ConditionNOT, ConditionType, \
    ConditionValueExpression
from sigma.conversion.base import TextQueryBackend
from sigma.conversion.deferred import DeferredTextQueryExpression, DeferredQueryExpression
from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule
from sigma.types import SigmaCompareExpression, SigmaString, SigmaNumber, SigmaBool


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
    """Azure backend."""
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
    group_expression: ClassVar[str] = "({expr})"  # Expression for precedence override grouping as format string with
    # {expr} placeholder
    parenthesize: bool = True

    # Generated query tokens
    # separator inserted between all boolean operators
    token_separator: str = " "
    or_token: ClassVar[str] = "or"
    and_token: ClassVar[str] = "and"
    not_token: ClassVar[str] = "not"

    # Token inserted between field and value (without separator)
    eq_token: ClassVar[str] = token_separator + "=~" + token_separator

    # String output
    ## Fields
    ### Quoting
    field_quote: ClassVar[str] = "'"  # Character used to quote field characters if field_quote_pattern matches (or not, depending on field_quote_pattern_negation). No field name quoting is done if not set.
    field_quote_pattern: ClassVar[Pattern] = re.compile("^\\w+$")  # Quote field names if this pattern (doesn't) matches, depending on field_quote_pattern_negation. Field name is always quoted if pattern is not set.
    field_quote_pattern_negation: ClassVar[bool] = True  # Negate field_quote_pattern result. Field name is quoted if pattern doesn't match if set to True (default).

    ### Escaping
    field_escape: ClassVar[str] = "\\"  # Character to escape particular parts defined in field_escape_pattern.
    field_escape_quote: ClassVar[bool] = False  # Escape quote string defined in field_quote
    field_escape_pattern: ClassVar[Pattern] = re.compile(r'\\')  # All matches of this pattern are prepended with the string contained in field_escape.

    ## Values
    str_quote: ClassVar[str] = '"'  # string quoting character (added as escaping character)
    escape_char: ClassVar[str] = "\\"  # Escaping character for special characrers inside string
    wildcard_multi: ClassVar[str] = "*"  # Character used as multi-character wildcard
    wildcard_single: ClassVar[str] = "*"  # Character used as single-character wildcard
    add_escaped: ClassVar[str] = ""  # Characters quoted in addition to wildcards and string quote
    filter_chars: ClassVar[str] = ""  # Characters filtered
    bool_values: ClassVar[Dict[bool, str]] = {  # Values to which boolean values are mapped.
        True: "true",
        False: "false",
    }

    # String matching operators. if none is appropriate eq_token is used.
    startswith_expression: ClassVar[str] = "startswith"
    endswith_expression: ClassVar[str] = "endswith"
    contains_expression: ClassVar[str] = "contains"
    wildcard_match_expression: ClassVar[str] = "match"  # Special expression if wildcards can't be matched with the eq_token operator

    # Regular expressions
    re_expression: ClassVar[
        str] = '{field} matches regex "(?i){regex}"'  # Regular expression query as format string with placeholders {field} and {regex}
    re_escape_char: ClassVar[str] = "\\"  # Character used for escaping in regular expressions
    re_escape: ClassVar[Tuple[str]] = ()  # List of strings that are escaped

    # cidr expressions
    cidr_wildcard: ClassVar[str] = "*"  # Character used as single wildcard
    cidr_expression: ClassVar[str] = 'ipv4_is_in_range({field}, "{value}")'  # CIDR expression query as format string with placeholders {field} = {value}
    cidr_in_list_expression: ClassVar[str] = "{field} in ({value})"  # CIDR expression query as format string with placeholders {field} = in({list})

    # Numeric comparison operators
    compare_op_expression: ClassVar[str] = "{field}" + token_separator + "{operator}" + token_separator + "{value}"
    # Compare operation query as format string with placeholders {field}, {operator} and {value}

    # Mapping between CompareOperators elements and strings used as replacement for {operator} in compare_op_expression
    compare_operators: ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT: "<",
        SigmaCompareExpression.CompareOperators.LTE: "<=",
        SigmaCompareExpression.CompareOperators.GT: ">",
        SigmaCompareExpression.CompareOperators.GTE: ">=",
    }

    # Null/None expressions
    field_null_expression: ClassVar[str] = "isempty({field})"  # Expression for field has null value as format string with {field} placeholder for field name

    # Field value in list, e.g. "field in (value list)" or "field containsall (value list)"
    convert_or_as_in: ClassVar[bool] = True  # Convert OR as in-expression
    convert_and_as_in: ClassVar[bool] = False  # Convert AND as in-expression
    in_expressions_allow_wildcards: ClassVar[bool] = True  # Values in list can contain wildcards. If set to False ( default) only plain values are converted into in-expressions.
    field_in_list_expression: ClassVar[str] = "{field} {op} ({list})"  # Expression for field in list of values as format string with placeholders {field}, {op} and {list}
    or_in_operator: ClassVar[str] = "in"  # Operator used to convert OR into in-expressions. Must be set if convert_or_as_in is set
    and_in_operator: ClassVar[str] = "contains-all"  # Operator used to convert AND into in-expressions. Must be set if convert_and_as_in is set
    list_separator: ClassVar[str] = ", "  # List element separator

    # Value not bound to a field
    unbound_value_str_expression: ClassVar[str] = '["*"] contains {value}'  # Expression for string value not bound to a field as format string with placeholder {value}
    unbound_value_num_expression: ClassVar[str] = '["*"] contains "{value}"'  # Expression for number value not bound to a field as format string with placeholder {value}
    unbound_value_re_expression: ClassVar[str] = '_=~{value}'  # Expression for regular expression not bound to a field as format string with placeholder {value}

    # Query finalization: appending and concatenating deferred query part
    deferred_start: ClassVar[str] = "\n| "  # String used as separator between main query and deferred parts
    deferred_separator: ClassVar[str] = "\n| "  # String used to join multiple deferred query parts
    deferred_only_query: ClassVar[str] = "union *"  # String used as query if final query only contains

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
