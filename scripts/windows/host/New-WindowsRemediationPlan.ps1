<#
.SYNOPSIS
Creates a Windows remediation plan from a Windows security audit report.

.DESCRIPTION
This script reads the JSON output from Invoke-WindowsSecurityAudit.ps1 and
creates a reviewable remediation plan. It does not change system configuration.

The JSON plan is intended to become the machine-readable input for the Windows
hardening script after specific plan items are reviewed and approved. Markdown
and CSV outputs are optional human review artifacts.

.PARAMETER AuditReportPath
Path to a JSON report created by Invoke-WindowsSecurityAudit.ps1.

.PARAMETER OutputPath
Path for the JSON remediation plan. If omitted, the script writes beside the
audit report using the windows-remediation-plan-* naming pattern.

.PARAMETER IncludeMarkdown
Writes a Markdown review table beside the JSON plan, or to MarkdownPath when
provided.

.PARAMETER MarkdownPath
Optional path for the Markdown review table.

.PARAMETER IncludeCsv
Writes a CSV review table beside the JSON plan, or to CsvPath when provided.

.PARAMETER CsvPath
Optional path for the CSV review table.

.PARAMETER Quiet
Suppresses the console summary after the plan is written.

.EXAMPLE
.\New-WindowsRemediationPlan.ps1 -AuditReportPath .\reports\windows-security-audit-SERVER01-20260531-120000.json

Create a JSON remediation plan from an audit report.

.EXAMPLE
.\New-WindowsRemediationPlan.ps1 -AuditReportPath .\reports\windows-security-audit-SERVER01-20260531-120000.json -IncludeMarkdown -IncludeCsv

Create JSON, Markdown, and CSV remediation plan artifacts.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$AuditReportPath,
    [string]$OutputPath = "",
    [switch]$IncludeMarkdown,
    [string]$MarkdownPath = "",
    [switch]$IncludeCsv,
    [string]$CsvPath = "",
    [switch]$Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function New-ParentDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)

    $parent = Split-Path -Path $Path -Parent
    if ($parent -and -not (Test-Path -Path $parent)) {
        New-Item -Path $parent -ItemType Directory -Force | Out-Null
    }
}

function Get-ObjectValue {
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($null -eq $InputObject) {
        return $null
    }

    if ($InputObject -is [System.Collections.IDictionary] -and $InputObject.Contains($Name)) {
        return $InputObject[$Name]
    }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($property) {
        return $property.Value
    }

    return $null
}

function ConvertTo-PlainText {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return ""
    }

    return ($Value.ToString() -replace "\r?\n", " ").Trim()
}

function ConvertTo-BooleanSafe {
    param([AllowNull()][object]$Value)

    if ($Value -is [bool]) {
        return $Value
    }

    return "$Value" -in @("True", "true", "1", "Yes", "yes")
}

function Escape-MarkdownCell {
    param([AllowNull()][object]$Value)

    $text = ConvertTo-PlainText -Value $Value
    return $text -replace "\|", "\|"
}

function Join-StandardField {
    param(
        [object[]]$Standards,
        [string]$FieldName
    )

    $values = New-Object System.Collections.Generic.List[string]
    foreach ($standard in @($Standards)) {
        $value = Get-ObjectValue -InputObject $standard -Name $FieldName
        if ($value) {
            $values.Add("$value") | Out-Null
        }
    }

    return @(($values.ToArray() | Select-Object -Unique)) -join "; "
}

function Get-DefaultPlanPath {
    param(
        [Parameter(Mandatory = $true)][string]$ResolvedAuditReportPath,
        [Parameter(Mandatory = $true)][object]$Audit
    )

    $auditItem = Get-Item -Path $ResolvedAuditReportPath
    if ($auditItem.BaseName -like "windows-security-audit-*") {
        $planName = $auditItem.BaseName -replace "^windows-security-audit-", "windows-remediation-plan-"
        return Join-Path -Path $auditItem.DirectoryName -ChildPath "$planName.json"
    }

    $computerName = Get-ObjectValue -InputObject (Get-ObjectValue -InputObject $Audit -Name "ReportMetadata") -Name "ComputerName"
    if (-not $computerName) {
        $computerName = $env:COMPUTERNAME
    }

    return ".\reports\windows-remediation-plan-$computerName-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
}

function Get-RemediationDefinition {
    param([Parameter(Mandatory = $true)][object]$Finding)

    $findingId = Get-ObjectValue -InputObject $Finding -Name "Id"
    $area = Get-ObjectValue -InputObject $Finding -Name "Area"
    $severity = Get-ObjectValue -InputObject $Finding -Name "Severity"
    $riskLevel = Get-ObjectValue -InputObject $Finding -Name "RiskLevel"
    $autoFixEligible = ConvertTo-BooleanSafe -Value (Get-ObjectValue -InputObject $Finding -Name "AutoFixEligible")
    $evidence = ConvertTo-PlainText -Value (Get-ObjectValue -InputObject $Finding -Name "Evidence")

    $definition = [ordered]@{
        RemediationType        = "Manual review"
        ProposedStage          = "Review"
        HardeningControlId     = ""
        HardeningControlStatus = "ManualOnly"
        ReadinessReason        = "Review the finding and decide whether a scripted control is appropriate."
    }

    switch ($findingId) {
        "WIN-FW-001" {
            $definition.RemediationType = "Auto-fix candidate with approval"
            $definition.ProposedStage = "3 - Policy hardening candidate"
            $definition.HardeningControlId = "WIN-HARDEN-FW-001"
            $definition.HardeningControlStatus = "Implemented"
            $definition.ReadinessReason = "The hardening script has a firewall profile enablement control, but firewall changes should be reviewed for host role impact."
        }
        "WIN-FW-002" {
            $definition.RemediationType = "Auto-fix candidate with approval"
            $definition.ProposedStage = "3 - Policy hardening candidate"
            $definition.HardeningControlId = "WIN-HARDEN-FW-002"
            $definition.HardeningControlStatus = "Implemented"
            $definition.ReadinessReason = "The hardening script can set the default inbound action to Block after required allow rules are reviewed."
        }
        "WIN-DEF-001" {
            $definition.RemediationType = "Manual EDR decision"
            $definition.ProposedStage = "1 - Confirm EDR/Defender ownership"
            $definition.HardeningControlId = "WIN-HARDEN-DEF-001"
            $definition.HardeningControlStatus = "ManualApprovalRequired"
            $definition.ReadinessReason = "Endpoint protection ownership must be confirmed before enabling or changing Defender."
        }
        "WIN-DEF-002" {
            $definition.RemediationType = "Manual EDR decision"
            $definition.ProposedStage = "1 - Confirm EDR/Defender ownership"
            $definition.HardeningControlId = "WIN-HARDEN-DEF-001"
            $definition.HardeningControlStatus = "ManualApprovalRequired"
            $definition.ReadinessReason = "Defender may be intentionally replaced by ESET or another managed EDR."
        }
        "WIN-DEF-003" {
            $definition.RemediationType = "Manual EDR decision"
            $definition.ProposedStage = "1 - Confirm EDR/Defender ownership"
            $definition.HardeningControlId = "WIN-HARDEN-DEF-002"
            $definition.HardeningControlStatus = "ManualApprovalRequired"
            $definition.ReadinessReason = "The hardening script can clear the Defender-disable policy, but EDR ownership must be confirmed first."
        }
        "WIN-PWD-001" {
            $definition.RemediationType = "Auto-fix candidate with approval"
            $definition.ProposedStage = "3 - Policy hardening candidate"
            $definition.HardeningControlId = "WIN-HARDEN-PWD-001"
            $definition.HardeningControlStatus = "Implemented"
            $definition.ReadinessReason = "The hardening script can set the local minimum password length to 14."
        }
        "WIN-PWD-002" {
            $definition.RemediationType = "Auto-fix candidate with approval"
            $definition.ProposedStage = "3 - Policy hardening candidate"
            $definition.HardeningControlId = "WIN-HARDEN-PWD-002"
            $definition.HardeningControlStatus = "Implemented"
            $definition.ReadinessReason = "The hardening script can set the local account lockout threshold and supporting lockout timers."
        }
        "WIN-LOCAL-001" {
            $definition.RemediationType = "Verify with elevated audit"
            $definition.ProposedStage = "0 - Re-run audit as Administrator"
            $definition.HardeningControlId = "WIN-HARDEN-LOCAL-001"
            $definition.HardeningControlStatus = "Implemented"
            $definition.ReadinessReason = "Guest account state could not be verified; re-run elevated before approving."
        }
        "WIN-LOCAL-002" {
            $definition.RemediationType = "Safe auto-fix candidate"
            $definition.ProposedStage = "2 - Safe hardening candidate"
            $definition.HardeningControlId = "WIN-HARDEN-LOCAL-001"
            $definition.HardeningControlStatus = "Implemented"
            $definition.ReadinessReason = "The hardening script already has a Guest account disable control."
        }
        "WIN-RDP-001" {
            $definition.RemediationType = "Auto-fix candidate with approval"
            $definition.ProposedStage = "3 - Policy hardening candidate"
            $definition.HardeningControlId = "WIN-HARDEN-RDP-001"
            $definition.HardeningControlStatus = "Implemented"
            $definition.ReadinessReason = "The hardening script can require Network Level Authentication for RDP."
        }
        "WIN-RDP-002" {
            $definition.RemediationType = "Manual remote access decision"
            $definition.ProposedStage = "3 - Review remote access requirement"
            $definition.HardeningControlId = "WIN-HARDEN-RDP-002"
            $definition.HardeningControlStatus = "ManualApprovalRequired"
            $definition.ReadinessReason = "The hardening script can disable RDP, but this must be approved only when RDP is not required."
        }
        "WIN-UAC-001" {
            $definition.RemediationType = "Safe auto-fix candidate"
            $definition.ProposedStage = "2 - Safe hardening candidate"
            $definition.HardeningControlId = "WIN-HARDEN-UAC-001"
            $definition.HardeningControlStatus = "Implemented"
            $definition.ReadinessReason = "The hardening script already has a UAC enablement control."
        }
        "WIN-UAC-002" {
            $definition.RemediationType = "Safe auto-fix candidate"
            $definition.ProposedStage = "2 - Safe hardening candidate"
            $definition.HardeningControlId = "WIN-HARDEN-UAC-002"
            $definition.HardeningControlStatus = "Implemented"
            $definition.ReadinessReason = "The hardening script sets ConsentPromptBehaviorAdmin to the CIS-aligned consent prompt value."
        }
        "WIN-UAC-003" {
            $definition.RemediationType = "Safe auto-fix candidate"
            $definition.ProposedStage = "2 - Safe hardening candidate"
            $definition.HardeningControlId = "WIN-HARDEN-UAC-003"
            $definition.HardeningControlStatus = "Implemented"
            $definition.ReadinessReason = "The hardening script already has a secure desktop prompt control."
        }
        "WIN-SMB-001" {
            $definition.RemediationType = "Auto-fix candidate with approval"
            $definition.ProposedStage = "3 - Policy hardening candidate"
            $definition.HardeningControlId = "WIN-HARDEN-SMB-001"
            $definition.HardeningControlStatus = "Implemented"
            $definition.ReadinessReason = "The hardening script can disable SMBv1 server protocol; validate legacy dependencies first."
        }
        "WIN-SMB-002" {
            $definition.RemediationType = "Auto-fix candidate with approval"
            $definition.ProposedStage = "3 - Policy hardening candidate"
            $definition.HardeningControlId = "WIN-HARDEN-SMB-002"
            $definition.HardeningControlStatus = "Implemented"
            $definition.ReadinessReason = "The hardening script can disable the SMBv1 client driver and optional SMB1Protocol feature."
        }
        "WIN-SMB-003" {
            $definition.RemediationType = "Safe auto-fix candidate"
            $definition.ProposedStage = "2 - Safe hardening candidate"
            $definition.HardeningControlId = "WIN-HARDEN-SMB-003"
            $definition.HardeningControlStatus = "Implemented"
            $definition.ReadinessReason = "The hardening script can disable insecure SMB guest logons by policy."
        }
        "WIN-LLMNR-001" {
            $definition.RemediationType = "Safe auto-fix candidate"
            $definition.ProposedStage = "2 - Safe hardening candidate"
            $definition.HardeningControlId = "WIN-HARDEN-LLMNR-001"
            $definition.HardeningControlStatus = "Implemented"
            $definition.ReadinessReason = "The hardening script already has an LLMNR disable control."
        }
        "WIN-PS-001" {
            $definition.RemediationType = "Safe auto-fix candidate"
            $definition.ProposedStage = "2 - Safe hardening candidate"
            $definition.HardeningControlId = "WIN-HARDEN-PS-001"
            $definition.HardeningControlStatus = "Implemented"
            $definition.ReadinessReason = "The hardening script can enable PowerShell script block logging by policy."
        }
        "WIN-PS-002" {
            $definition.RemediationType = "Manual logging design decision"
            $definition.ProposedStage = "3 - Choose protected logging design"
            $definition.HardeningControlId = "WIN-HARDEN-PS-002"
            $definition.HardeningControlStatus = "ManualDesignRequired"
            $definition.ReadinessReason = "Transcription should not be enabled until a protected output path and retention design are chosen."
        }
        "WIN-WINRM-008" {
            $definition.RemediationType = "Safe auto-fix candidate"
            $definition.ProposedStage = "2 - Safe hardening candidate"
            $definition.HardeningControlId = "WIN-HARDEN-WINRM-008"
            $definition.HardeningControlStatus = "Implemented"
            $definition.ReadinessReason = "The hardening script can set WinRM DisableRunAs to 1 by policy."
        }
        "WIN-WINRM-001" {
            $definition.RemediationType = "Manual remote management decision"
            $definition.ProposedStage = "3 - Review remote management requirement"
            $definition.HardeningControlId = "WIN-HARDEN-WINRM-001"
            $definition.HardeningControlStatus = "ManualApprovalRequired"
            $definition.ReadinessReason = "The hardening script can disable WinRM, but this must be approved only when WinRM is not required."
        }
        "WIN-NET-001" {
            $definition.RemediationType = "Network/firewall review"
            $definition.ProposedStage = "3 - Review exposure and allowed networks"
            $definition.HardeningControlId = ""
            $definition.HardeningControlStatus = "ManualOnly"
            $definition.ReadinessReason = "Listening port exposure depends on host role and allowed source networks."
        }
        "WIN-SVC-001" {
            if ($evidence -like "WinDefend*") {
                $definition.RemediationType = "Manual EDR decision"
                $definition.ProposedStage = "1 - Confirm EDR/Defender ownership"
                $definition.HardeningControlId = "WIN-HARDEN-DEF-001"
                $definition.HardeningControlStatus = "ManualApprovalRequired"
                $definition.ReadinessReason = "WinDefend may be stopped because another EDR owns endpoint protection."
            }
            else {
                $definition.RemediationType = "Manual service decision"
                $definition.ProposedStage = "3 - Confirm security service ownership"
                $definition.HardeningControlId = "WIN-HARDEN-SVC-001"
                $definition.HardeningControlStatus = "ManualApprovalRequired"
                $definition.ReadinessReason = "The hardening script can start Windows Firewall and Event Log services, but service ownership should be confirmed first."
            }
        }
        default {
            if ($findingId -like "WIN-AUDIT-*") {
                $definition.RemediationType = "Verify with elevated audit"
                $definition.ProposedStage = "0 - Re-run audit as Administrator"
                $definition.HardeningControlId = $findingId -replace "^WIN-AUDIT-", "WIN-HARDEN-AUDIT-"
                $definition.HardeningControlStatus = "Implemented"
                $definition.ReadinessReason = "The audit did not verify this policy. Re-run elevated before approving an audit policy change."
            }
            elseif ($findingId -like "WIN-WINRM-*") {
                $definition.RemediationType = if ($autoFixEligible -and $riskLevel -eq "Low") { "Safe auto-fix candidate" } else { "Auto-fix candidate with approval" }
                $definition.ProposedStage = if ($definition.RemediationType -eq "Safe auto-fix candidate") { "2 - Safe hardening candidate" } else { "3 - Policy hardening candidate" }
                $definition.HardeningControlId = $findingId -replace "^WIN-", "WIN-HARDEN-"
                $definition.HardeningControlStatus = "Implemented"
                $definition.ReadinessReason = "The hardening script can set this WinRM policy value."
            }
            elseif ($severity -eq "Info" -and $area -eq "Audit policy") {
                $definition.RemediationType = "Verify with elevated audit"
                $definition.ProposedStage = "0 - Re-run audit as Administrator"
                $definition.HardeningControlStatus = "ManualOnly"
                $definition.ReadinessReason = "The finding is informational and should be verified before remediation."
            }
            elseif ($autoFixEligible -and $riskLevel -eq "Low") {
                $definition.RemediationType = "Safe auto-fix candidate"
                $definition.ProposedStage = "2 - Safe hardening candidate"
                $definition.HardeningControlStatus = "NotYetImplemented"
                $definition.ReadinessReason = "A dedicated hardening control is needed before automation."
            }
            elseif ($autoFixEligible) {
                $definition.RemediationType = "Auto-fix candidate with approval"
                $definition.ProposedStage = "3 - Policy hardening candidate"
                $definition.HardeningControlStatus = "NotYetImplemented"
                $definition.ReadinessReason = "The finding is auto-fix eligible, but needs explicit approval and a matching hardening control."
            }
        }
    }

    return [pscustomobject]$definition
}

function New-PlanItems {
    param([object[]]$Findings)

    $items = New-Object System.Collections.Generic.List[object]
    $index = 1
    foreach ($finding in @($Findings)) {
        $definition = Get-RemediationDefinition -Finding $finding
        $standards = @(Get-ObjectValue -InputObject $finding -Name "Standards")
        $findingId = Get-ObjectValue -InputObject $finding -Name "Id"
        $planItemId = "PLAN-{0:D3}-{1}" -f $index, $findingId

        $items.Add([ordered]@{
            PlanItemId              = $planItemId
            ApprovalStatus          = "NotApproved"
            ApprovedBy              = ""
            ApprovedAtUtc           = ""
            ApprovalNote            = ""
            FindingId               = $findingId
            Severity                = Get-ObjectValue -InputObject $finding -Name "Severity"
            Area                    = Get-ObjectValue -InputObject $finding -Name "Area"
            Title                   = Get-ObjectValue -InputObject $finding -Name "Title"
            Evidence                = ConvertTo-PlainText -Value (Get-ObjectValue -InputObject $finding -Name "Evidence")
            SuggestedFix            = Get-ObjectValue -InputObject $finding -Name "SuggestedFix"
            Recommendation          = Get-ObjectValue -InputObject $finding -Name "Recommendation"
            WhyItMatters            = Get-ObjectValue -InputObject $finding -Name "WhyItMatters"
            OperationalNote         = Get-ObjectValue -InputObject $finding -Name "OperationalNote"
            AutoFixEligible         = ConvertTo-BooleanSafe -Value (Get-ObjectValue -InputObject $finding -Name "AutoFixEligible")
            RequiresAdmin           = ConvertTo-BooleanSafe -Value (Get-ObjectValue -InputObject $finding -Name "RequiresAdmin")
            RiskLevel               = Get-ObjectValue -InputObject $finding -Name "RiskLevel"
            RemediationType         = Get-ObjectValue -InputObject $definition -Name "RemediationType"
            ProposedStage           = Get-ObjectValue -InputObject $definition -Name "ProposedStage"
            HardeningControlId      = Get-ObjectValue -InputObject $definition -Name "HardeningControlId"
            HardeningControlStatus  = Get-ObjectValue -InputObject $definition -Name "HardeningControlStatus"
            ReadinessReason         = Get-ObjectValue -InputObject $definition -Name "ReadinessReason"
            ExceptionGuidance       = Get-ObjectValue -InputObject $finding -Name "ExceptionGuidance"
            CISRecommendation       = Join-StandardField -Standards $standards -FieldName "Recommendation"
            CISLevel                = Join-StandardField -Standards $standards -FieldName "Level"
            WazuhWin2019CheckId     = Join-StandardField -Standards $standards -FieldName "WazuhWin2019CheckId"
            WazuhWin11EnterpriseCheckId = Join-StandardField -Standards $standards -FieldName "WazuhWin11EnterpriseCheckId"
            Standards               = @($standards)
        }) | Out-Null

        $index++
    }

    return @($items.ToArray())
}

function ConvertTo-PlanCsvRows {
    param(
        [Parameter(Mandatory = $true)][object]$Plan,
        [Parameter(Mandatory = $true)][object[]]$PlanItems
    )

    foreach ($item in @($PlanItems)) {
        [pscustomobject]@{
            SourceAuditReport       = Get-ObjectValue -InputObject (Get-ObjectValue -InputObject $Plan -Name "ReportMetadata") -Name "SourceAuditReport"
            ComputerName            = Get-ObjectValue -InputObject (Get-ObjectValue -InputObject $Plan -Name "ReportMetadata") -Name "ComputerName"
            PlanItemId              = Get-ObjectValue -InputObject $item -Name "PlanItemId"
            ApprovalStatus          = Get-ObjectValue -InputObject $item -Name "ApprovalStatus"
            FindingId               = Get-ObjectValue -InputObject $item -Name "FindingId"
            Severity                = Get-ObjectValue -InputObject $item -Name "Severity"
            Area                    = Get-ObjectValue -InputObject $item -Name "Area"
            RemediationType         = Get-ObjectValue -InputObject $item -Name "RemediationType"
            ProposedStage           = Get-ObjectValue -InputObject $item -Name "ProposedStage"
            AutoFixEligible         = Get-ObjectValue -InputObject $item -Name "AutoFixEligible"
            RequiresAdmin           = Get-ObjectValue -InputObject $item -Name "RequiresAdmin"
            RiskLevel               = Get-ObjectValue -InputObject $item -Name "RiskLevel"
            HardeningControlId      = Get-ObjectValue -InputObject $item -Name "HardeningControlId"
            HardeningControlStatus  = Get-ObjectValue -InputObject $item -Name "HardeningControlStatus"
            Title                   = Get-ObjectValue -InputObject $item -Name "Title"
            Evidence                = Get-ObjectValue -InputObject $item -Name "Evidence"
            SuggestedFix            = Get-ObjectValue -InputObject $item -Name "SuggestedFix"
            ReadinessReason         = Get-ObjectValue -InputObject $item -Name "ReadinessReason"
            ExceptionGuidance       = Get-ObjectValue -InputObject $item -Name "ExceptionGuidance"
            CISRecommendation       = Get-ObjectValue -InputObject $item -Name "CISRecommendation"
            CISLevel                = Get-ObjectValue -InputObject $item -Name "CISLevel"
            WazuhWin2019CheckId     = Get-ObjectValue -InputObject $item -Name "WazuhWin2019CheckId"
            WazuhWin11EnterpriseCheckId = Get-ObjectValue -InputObject $item -Name "WazuhWin11EnterpriseCheckId"
        }
    }
}

function Write-MarkdownPlan {
    param(
        [Parameter(Mandatory = $true)][object]$Plan,
        [Parameter(Mandatory = $true)][object[]]$PlanItems,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $metadata = Get-ObjectValue -InputObject $Plan -Name "ReportMetadata"
    $summary = Get-ObjectValue -InputObject $Plan -Name "Summary"
    $headers = @(
        "PlanItemId",
        "ApprovalStatus",
        "FindingId",
        "Severity",
        "RemediationType",
        "ProposedStage",
        "HardeningControlId",
        "HardeningControlStatus",
        "Title",
        "SuggestedFix"
    )

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("# Windows Remediation Plan") | Out-Null
    $lines.Add("") | Out-Null
    $lines.Add("Source audit report: ``$(Get-ObjectValue -InputObject $metadata -Name "SourceAuditReportName")``") | Out-Null
    $lines.Add("Computer: ``$(Get-ObjectValue -InputObject $metadata -Name "ComputerName")``") | Out-Null
    $lines.Add("Audit generated at UTC: ``$(Get-ObjectValue -InputObject $metadata -Name "SourceAuditGeneratedAtUtc")``") | Out-Null
    $lines.Add("Audit was administrator: ``$(Get-ObjectValue -InputObject $metadata -Name "AuditWasAdministrator")``") | Out-Null
    $lines.Add("") | Out-Null
    $lines.Add("This plan is review-only. All items start as ``NotApproved`` and no Windows setting is changed by this script.") | Out-Null
    $lines.Add("") | Out-Null
    $lines.Add("## Summary") | Out-Null
    $lines.Add("") | Out-Null
    $lines.Add("- Source posture: $(Get-ObjectValue -InputObject $summary -Name "SourcePosture")") | Out-Null
    $lines.Add("- Plan items: $(Get-ObjectValue -InputObject $summary -Name "PlanItemCount")") | Out-Null
    $lines.Add("- Approved items: $(Get-ObjectValue -InputObject $summary -Name "ApprovedCount")") | Out-Null
    $lines.Add("- Auto-fix eligible items: $(Get-ObjectValue -InputObject $summary -Name "AutoFixEligibleCount")") | Out-Null
    $lines.Add("") | Out-Null
    $lines.Add("## Matrix") | Out-Null
    $lines.Add("") | Out-Null
    $lines.Add("|" + (($headers | ForEach-Object { Escape-MarkdownCell -Value $_ }) -join "|") + "|") | Out-Null
    $lines.Add("|" + (($headers | ForEach-Object { "---" }) -join "|") + "|") | Out-Null

    foreach ($item in @($PlanItems)) {
        $cells = foreach ($header in $headers) {
            Escape-MarkdownCell -Value (Get-ObjectValue -InputObject $item -Name $header)
        }
        $lines.Add("|" + ($cells -join "|") + "|") | Out-Null
    }

    $lines.Add("") | Out-Null
    $lines.Add("## Review Rules") | Out-Null
    $lines.Add("") | Out-Null
    $lines.Add("- Do not approve Defender or WinDefend items until EDR ownership is confirmed.") | Out-Null
    $lines.Add("- Re-run audit policy checks as Administrator before approving audit policy remediation.") | Out-Null
    $lines.Add("- Items with ``HardeningControlStatus`` of ``NotYetImplemented``, ``NeedsAlignment``, ``ManualDesignRequired``, or ``ManualOnly`` cannot be applied by the hardening script.") | Out-Null
    $lines.Add("- Edit approval fields in the JSON plan only after review; Markdown and CSV are human-readable copies.") | Out-Null

    New-ParentDirectory -Path $Path
    $lines | Set-Content -Path $Path -Encoding UTF8
}

$resolvedAuditReportPath = (Resolve-Path -Path $AuditReportPath).Path
$audit = Get-Content -Path $resolvedAuditReportPath -Raw | ConvertFrom-Json
$findingsProperty = $audit.PSObject.Properties["Findings"]
if (-not $findingsProperty) {
    throw "Audit report '$resolvedAuditReportPath' does not contain Findings. Run Invoke-WindowsSecurityAudit.ps1 first."
}
$findings = @($findingsProperty.Value)

if (-not $OutputPath) {
    $OutputPath = Get-DefaultPlanPath -ResolvedAuditReportPath $resolvedAuditReportPath -Audit $audit
}

$planItems = @(New-PlanItems -Findings $findings)
$sourceMetadata = Get-ObjectValue -InputObject $audit -Name "ReportMetadata"
$sourceSummary = Get-ObjectValue -InputObject $audit -Name "Summary"
$sourceReportItem = Get-Item -Path $resolvedAuditReportPath

$countsByRemediationType = [ordered]@{}
$countsByStage = [ordered]@{}
$countsByControlStatus = [ordered]@{}
foreach ($item in @($planItems)) {
    foreach ($pair in @(
            @{ Target = $countsByRemediationType; Name = Get-ObjectValue -InputObject $item -Name "RemediationType" },
            @{ Target = $countsByStage; Name = Get-ObjectValue -InputObject $item -Name "ProposedStage" },
            @{ Target = $countsByControlStatus; Name = Get-ObjectValue -InputObject $item -Name "HardeningControlStatus" }
        )) {
        $name = $pair.Name
        if (-not $name) {
            $name = "Unspecified"
        }
        if (-not $pair.Target.Contains($name)) {
            $pair.Target[$name] = 0
        }
        $pair.Target[$name]++
    }
}

$plan = [ordered]@{
    ReportMetadata = [ordered]@{
        ScriptName                  = "New-WindowsRemediationPlan.ps1"
        GeneratedAtUtc              = (Get-Date).ToUniversalTime().ToString("o")
        SourceAuditReport           = $resolvedAuditReportPath
        SourceAuditReportName       = $sourceReportItem.Name
        SourceAuditGeneratedAtUtc   = Get-ObjectValue -InputObject $sourceMetadata -Name "GeneratedAtUtc"
        ComputerName                = Get-ObjectValue -InputObject $sourceMetadata -Name "ComputerName"
        AuditWasAdministrator       = Get-ObjectValue -InputObject $sourceMetadata -Name "IsAdministrator"
        PlanSchemaVersion           = "1.0"
    }
    Summary = [ordered]@{
        SourcePosture               = Get-ObjectValue -InputObject $sourceSummary -Name "Posture"
        SourceFindingCount          = @($findings).Count
        PlanItemCount               = @($planItems).Count
        ApprovedCount               = 0
        AutoFixEligibleCount        = @($planItems | Where-Object { ConvertTo-BooleanSafe -Value (Get-ObjectValue -InputObject $_ -Name "AutoFixEligible") }).Count
        CountsByRemediationType     = $countsByRemediationType
        CountsByProposedStage       = $countsByStage
        CountsByHardeningControlStatus = $countsByControlStatus
        Notes                       = @(
            "This remediation plan is generated from audit findings and does not apply changes.",
            "All plan items start with ApprovalStatus=NotApproved.",
            "Hardening scripts should apply only approved items and should ignore Markdown/CSV review copies.",
            "Manual EDR, network exposure, and logging design items require human review before approval."
        )
    }
    PlanItems = $planItems
}

New-ParentDirectory -Path $OutputPath
$plan | ConvertTo-Json -Depth 12 | Out-File -FilePath $OutputPath -Encoding utf8

if ($IncludeCsv) {
    if (-not $CsvPath) {
        $CsvPath = [System.IO.Path]::ChangeExtension($OutputPath, ".csv")
    }

    New-ParentDirectory -Path $CsvPath
    ConvertTo-PlanCsvRows -Plan $plan -PlanItems $planItems | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
}

if ($IncludeMarkdown) {
    if (-not $MarkdownPath) {
        $MarkdownPath = [System.IO.Path]::ChangeExtension($OutputPath, ".md")
    }

    Write-MarkdownPlan -Plan $plan -PlanItems $planItems -Path $MarkdownPath
}

if (-not $Quiet) {
    Write-Host "Windows remediation plan written to: $OutputPath"
    if ($IncludeMarkdown) {
        Write-Host "Markdown review copy written to: $MarkdownPath"
    }
    if ($IncludeCsv) {
        Write-Host "CSV review copy written to: $CsvPath"
    }
    Write-Host "Computer: $(Get-ObjectValue -InputObject $sourceMetadata -Name "ComputerName")"
    Write-Host "Plan items: $(@($planItems).Count)"
    Write-Host "Approved items: 0"
}
