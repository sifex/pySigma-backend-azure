import pytest
from sigma.collection import SigmaCollection

from sigma.backends.azure import AzureBackend
from sigma.pipelines.azure import azure_windows_pipeline
from sigma.pipelines.azure.azure import azure_windows_service_map


@pytest.mark.parametrize(
    ("service", "source"),
    azure_windows_service_map.items()
)
def test_splunk_windows_pipeline_simple(service, source):
    assert AzureBackend(processing_pipeline=azure_windows_pipeline()).convert(
        SigmaCollection.from_yaml(f"""
            title: Test
            status: test
            logsource:
                product: windows
                service: {service}
            detection:
                sel:
                    EventID: 123
                    field: value
                condition: sel
        """)
    ) == [f"source=\"WinEventLog:{source}\" EventCode=123 field=\"value\""]

