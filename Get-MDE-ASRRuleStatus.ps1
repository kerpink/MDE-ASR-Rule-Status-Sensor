<#
.SYNOPSIS
Custom compliance script to report the configuration status of Microsoft Defender ASR rules.

.DESCRIPTION
This script evaluates a predefined list of Microsoft Defender Attack Surface Reduction (ASR) rules by their GUIDs, determines their current status (Not Configured, Enabled, Audit Mode, Block, or Unknown), and returns each rule's name, ID, and configuration state.

This output provides visibility into enterprise ASR posture and supports compliance auditing, Tanium sensor reporting, and Microsoft Intune integration.

.OUTPUTS
Pipe-delimited string: Rule Name|GUID|Status

.COMPONENT
Microsoft Defender for Endpoint, Microsoft Intune, Tanium

.AUTHOR
Kerpink Williams

.VERSION
1.0.0
#>
Function Get-MDE-SpecificASRRulesStatus {
    [cmdletBinding()]
    param (
        [string]$Delimiter = "|"
    )

    # Define ASR rules with GUIDs
    $ASRRules = @(
 @{ Name = "Block abuse of exploited vulnerable signed drivers"; GUID = "56a863a9-875e-4185-98a7-b882c64b5ce5" }
 @{ Name = "Block Adobe Reader from creating child processes"; GUID = "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" }
 @{ Name = "Block all Office applications from creating child processes"; GUID = "d4f940ab-401b-4efc-aadc-ad5f3c50688a" }
 @{ Name = "Block credential stealing from Windows LSASS"; GUID = "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" }
 @{ Name = "Block executable content from email client and webmail"; GUID = "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" }
 @{ Name = "Block executable files from running unless they meet criteria"; GUID = "01443614-cd74-433a-b99e-2ecdc07bfc25" }
 @{ Name = "Block execution of potentially obfuscated scripts"; GUID = "5beb7efe-fd9a-4556-801d-275e5ffc04cc" }
 @{ Name = "Block JavaScript or VBScript from launching executables"; GUID = "d3e037e1-3eb8-44c8-a917-57927947596d" }
 @{ Name = "Block Office applications from creating executable content"; GUID = "3b576869-a4ec-4529-8536-b80a7769e899" }
 @{ Name = "Block Office applications from injecting code into other processes"; GUID = "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" }
 @{ Name = "Block Office communication applications from creating child processes"; GUID = "26190899-1602-49e8-8b27-eb1d0a1ce869" }
 @{ Name = "Block persistence through WMI event subscription"; GUID = "e6db77e5-3df2-4cf1-b95a-636979351e5b" }
 @{ Name = "Block process creations originating from PSExec and WMI commands"; GUID = "d1e49aac-8f56-4280-b9ba-993a6d77406c" }
 @{ Name = "Block rebooting machine in Safe Mode (preview)"; GUID = "33ddedf1-c6e0-47cb-833e-de6133960387" }
 @{ Name = "Block untrusted and unsigned processes from USB"; GUID = "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" }
 @{ Name = "Block use of copied or impersonated system tools (preview)"; GUID = "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb" }
 @{ Name = "Block Webshell creation for Servers"; GUID = "a8f5898e-1dc8-49a9-9878-85004b8a61e6" }
 @{ Name = "Block Win32 API calls from Office macros"; GUID = "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" }
 @{ Name = "Use advanced protection against ransomware"; GUID = "c1db55ab-c21a-4637-bb3f-a12568109d35" }
    )

    try {
        # Retrieve ASR rules and their actions
        $MPOutput = Get-CimInstance -Namespace 'ROOT\Microsoft/Windows\Defender' -ClassName 'MSFT_MpPreference' -Property AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions -ErrorAction Stop

        if ($null -eq $MPOutput.AttackSurfaceReductionRules_Ids) {
 Write-Output "No ASR rules configured."
            return
        }

        # Iterate through defined ASR rules
        foreach ($rule in $ASRRules) {
            $index = $MPOutput.AttackSurfaceReductionRules_Ids.IndexOf($rule.GUID)
            $statusList = @("Not Configured", "Enabled", "Audit Mode", "Block", "Unknown")

            # Determine the current status of the ASR rule
            $status = "Not Configured"
            if ($index -ne -1) {
                $action = $MPOutput.AttackSurfaceReductionRules_Actions[$index]
                $status = switch ($action) {
                    0 { "Not Configured" }
                    1 { "Enabled" }
                    2 { "Audit Mode" }
                    6 { "Block" }
 default { "Unknown" }
                }
            }

            # Output each status type
 Write-Output "$($rule.Name)$Delimiter$($rule.GUID)$Delimiter$status"
        }

    } catch {
 Write-Output "Error: $($_.Exception.Message)"
    }
}

# Run the function with a pipe delimiter
Get-MDE-SpecificASRRulesStatus -Delimiter "|"
