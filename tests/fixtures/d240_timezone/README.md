These two inputs are copied byte-for-byte from the real CASE-C5B04D31 RECmd
run `RUN-20261011T110426201672Z-tools-5618aeb2`:

- `20261011110620_TimeZoneInfo__SYSTEM.csv` is RECmd's `TimeZoneInfo` output
  from the acquired `H:\C\Windows\System32\config\SYSTEM` hive. Its SHA-256
  is `2CD4A9D5E2783B828620147501EDBD626B83A254D092641177A7D78A9FFF8FB2`.
- `20261011T110631_recmd_meta.json` records the RECmd invocation against that
  `SYSTEM` hive. It is included so the test proves the CSV-to-hive association
  from the captured command, rather than inventing a host mapping.

The task XML used by `test_task_xml_importer.py` is the real Office task under
`Evidence-files/01-windows/tasks/system32-tasks/`. The test applies the real
CASE-C5B04D31 SYSTEM timezone values to that XML and checks the date-specific
Eastern daylight offset. The exact `SRL Update Service` raw XML is not present
in the local evidence tree; its verbatim imported artifact row is checked by
the D240 runbook probe against CASE-C5B04D31 when available.
