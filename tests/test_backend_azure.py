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
    ) == ['union *\n| where (fieldA =~ "valueA" and fieldB =~ "valueB")']


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
    ) == ['union *\n| where (fieldA =~ "valueA" or fieldB =~ "valueB")']


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
               'union *\n| where ((fieldA in ("valueA1", "valueA2")) and (fieldB in ("valueB1", "valueB2")))'
    ]


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
    ) == [
               'union *\n| where ((fieldA =~ "valueA1" and fieldB =~ "valueB1") or (fieldA =~ "valueA2" and fieldB =~ "valueB2"))']


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
    ) == ['union *\n| where (fieldA in ("valueA", "valueB", "valueC*"))']


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
    ) == ['union *\n| where (fieldA matches regex "(?i)foo.*bar" and fieldB =~ "foo")']


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
                    fieldname|cidr: 192.168.0.0/16
                condition: sel
        """)
    ) == ["union *\n| where (ipv4_is_in_range(fieldname, \"192.168.0.0/16\"))"]


def test_azure_cidr_query_or(azure_backend : AzureBackend):
    query = azure_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|cidr:
                        - 192.168.0.0/16
                        - 10.0.0.0/8
                    fieldB: foo
                    fieldC: bar
                condition: sel
        """)
    ) == [
        'union *\n| where ((ipv4_is_in_range(fieldA, "192.168.0.0/16") or ipv4_is_in_range(fieldA, "10.0.0.0/8")) and fieldB =~ "foo" and fieldC =~ "bar")'
    ]


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
    ) == ['union *\n| where ([\'field name\'] =~ "value")']
