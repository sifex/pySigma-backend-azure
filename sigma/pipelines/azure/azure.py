from sigma.pipelines.common import logsource_windows
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation, \
    ReplaceStringTransformation, AddConditionTransformation

azure_windows_service_map = {
    'security': 'SecurityEvent',
    'sysmon': 'SysmonEvent',
    'powershell': 'Event',
    'office365': 'OfficeActivity',
    'azuread': 'AuditLogs',
    'azureactivity': 'AzureActivity',
}


def azure_windows_pipeline() -> ProcessingPipeline:  # Processing pipelines should be defined as functions that return a ProcessingPipeline object.
    return ProcessingPipeline(
        name="Azure Windows Pipeline",
        # Set of identifiers of backends (from the backends mapping) that are allowed to use this processing pipeline. This can be used by frontends like Sigma CLI to warn the user about inappropriate usage.
        priority=20,  # The priority defines the order pipelines are applied. See documentation for common values.
        items=[
                  ProcessingItem(  # log sources mapped from windows_service_source_mapping
                      identifier=f"azure_windows_{service}",
                      transformation=AddConditionTransformation(source),
                      rule_conditions=[logsource_windows(service)],
                  )
                  for service, source in azure_windows_service_map.items()
              ] + [
                  ProcessingItem(  # Field mappings
                      identifier="azure_field_mapping",
                      transformation=FieldMappingTransformation({
                          # "EventID": "event_id",
                      })
                  )
              ],
    )


def azure_backend_pipeline() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="Azure generic pipeline",
        priority=20,
        items=[
            # ProcessingItem(
            #     identifier=f"azure_prefix_logsource",
            #     transformation=AddConditionTransformation('Table'),
            # )
        ]
    )


def logsource_value_to_azure_logsource(logsource_field: str):
    if "-" in logsource_field:
        table = "-".join([item.capitalize() for item in logsource_field.split("-")])
    elif "_" in logsource_field:
        table = "_".join([item.capitalize() for item in logsource_field.split("_")])
    else:
        if logsource_field.islower() or logsource_field.isupper():
            table = logsource_field.capitalize()
        else:
            table = logsource_field

    return table
