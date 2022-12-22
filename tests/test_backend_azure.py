import pytest
from sigma.collection import SigmaCollection
from sigma.backends.azure import AzureBackend


@pytest.fixture
def azure_backend():
    return AzureBackend()


def test_azure_and_expression(azure_backend: AzureBackend):
    assert azure_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """)
    ) == ['union * | where (fieldA == "valueA" and fieldB == "valueB")']


def test_azure_or_expression(azure_backend: AzureBackend):
    assert azure_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA
                sel2:
                    fieldB: valueB
                condition: 1 of sel*
        """)
    ) == ['union * | where (fieldA == "valueA" or fieldB == "valueB")']


def test_azure_and_or_expression(azure_backend: AzureBackend):
    assert azure_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA1
                        - valueA2
                    fieldB:
                        - valueB1
                        - valueB2
                condition: sel
        """)
    ) == [
               'union * | where ((fieldA == "valueA1" or fieldA == "valueA2") and (fieldB == "valueB1" or fieldB == "valueB2"))']


def test_azure_or_and_expression(azure_backend: AzureBackend):
    assert azure_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA1
                    fieldB: valueB1
                sel2:
                    fieldA: valueA2
                    fieldB: valueB2
                condition: 1 of sel*
        """)
    ) == ['union * | where ((fieldA == "valueA1" and fieldB == "valueB1") or (fieldA == "valueA2" and fieldB == "valueB2"))']


def test_azure_in_expression(azure_backend: AzureBackend):
    assert azure_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA
                        - valueB
                        - valueC*
                condition: sel
        """)
    ) == ['| where (fieldA == "valueA" or fieldA == "valueB" or fieldA startswith \'valueC\')']


def test_azure_regex_query(azure_backend: AzureBackend):
    assert azure_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: foo.*bar
                    fieldB: foo
                condition: sel
        """)
    ) == ['union * | where (fieldA matches regex "(?i)foo..*bar" and fieldB == "foo")']


def test_azure_cidr_query(azure_backend: AzureBackend):
    assert azure_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field|cidr: 192.168.0.0/16
                condition: sel
        """)
    ) == ['<insert expected result here>']


def test_azure_field_name_with_whitespace(azure_backend: AzureBackend):
    assert azure_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field name: value
                condition: sel
        """)
    ) == ['union * | where field name == "value"']


# TODO: implement tests for all backend features that don't belong to the base class defaults, e.g. features that were
# implemented with custom code, deferred expressions etc.


def test_azure_format1_output(azure_backend: AzureBackend):
    """Test for output format format1."""
    # TODO: implement a test for the output format
    pass


def test_azure_format2_output(azure_backend: AzureBackend):
    """Test for output format format2."""
    # TODO: implement a test for the output format
    pass
