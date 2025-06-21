# Microsoft Defender ASR Rule Status Sensor

This PowerShell script reports the configuration status of Microsoft Defender for Endpoint **Attack Surface Reduction (ASR)** rules across windows endpoints. It outputs each rule’s GUID, Microsoft Defender ASR rule name, and current status — identifying whether it is **Not Configured**, **Enabled**, or in **Audit Mode**.

Ideal for use as a **ASR compliance sensor** in an endpoint management tool such Tanium.

---

## Overview

Microsoft Defender ASR rules are powerful mitigations that reduce the attack surface by blocking common malware and exploit behaviors. However, many environments lack **centralized visibility** into which ASR rules are deployed, enabled, or audited on endpoints.

This script solves that by:

- Returning the current **status** of all key ASR rules
- Mapping cryptic **GUIDs** to human-readable rule names
- Outputting results in a pipe-delimited format for easy ingestion

---

## Key Features

- Reports status of all known ASR rules
- Status values include:
  - `Not Configured`
  - `Enabled`
  - `Audit Mode`
  - `Block`
  - `Unknown`
- Provides readable output with:
  - Rule Name
  - Rule GUID
  - Current Status
- Can be integrated into:
  - Tanium sensors
  - Microsoft Intune custom compliance
  - SCCM/ConfigMgr baselines
  - GRC dashboards

---

## Example Output
Block abuse of exploited vulnerable signed drivers|56a863a9-875e-4185-98a7-b882c64b5ce5|Enabled
Block all Office applications from creating child processes|d4f940ab-401b-4efc-aadc-ad5f3c50688a|Audit Mode
Block credential stealing from Windows LSASS|9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2|Not Configured

---

## Output Format
Rule Name|GUID|Status

## Optionally specify a custom delimiter (default is |):
Get-MDE-SpecificASRRulesStatus -Delimiter ";"
## License
This project is licensed under the MIT License.

## Author
Kerpink Williams
Cybersecurity Engineer 
LinkedIn: https://www.linkedin.com/in/kerpink-williams/
Medium: https://medium.com/@kerpinkwilliams


