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
    ) == [f'{source}\n| where (EventID =~ 123 and field =~ "value")']


def test_azure_process_creation():
    assert AzureBackend(processing_pipeline=azure_windows_pipeline()).convert(
        SigmaCollection.from_yaml(f"""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    CommandLine: test
                    CurrentDirectory: test
                    Image: test
                    IntegrityLevel: test
                    ParentCommandLine: test
                    ParentImage: test
                    ParentProcessGuid: test
                    ParentProcessId: test
                    ProcessGuid: test
                    ProcessId: test
                    User: test
                condition: sel
        """)
    ) == ['SecurityEvent\n| where EventID =~ "4688" and ((CommandLine =~ "test" and CurrentDirectory =~ "test" and Image =~ "test" and IntegrityLevel =~ "test" and ParentCommandLine =~ "test" and ParentImage =~ "test" and ParentProcessGuid =~ "test" and ParentProcessId =~ "test" and ProcessGuid =~ "test" and ProcessId =~ "test" and User =~ "test"))']
