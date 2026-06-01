<#
.SYNOPSIS
Applies a controlled Windows baseline hardening set.

.DESCRIPTION
The script is safe by default. Without -Apply it prints the planned actions
and writes a report, but does not change system configuration.

The baseline focuses on common enterprise controls that are usually safe for
servers and workstations. Review the code and test before production use.

.PARAMETER Apply
Applies the selected controls. Without this switch, the script runs in dry-run
mode and only writes the hardening plan.

.PARAMETER ReportPath
Path for the JSON hardening report. The parent directory is created when needed.
Default: .\reports\windows-hardening-plan-COMPUTER-TIMESTAMP.json

.PARAMETER BackupDirectory
Directory for selective registry backups and backup-manifest.json created
before changes are applied. Used only with -Apply.

.PARAMETER PlanPath
Path to a JSON remediation plan created by New-WindowsRemediationPlan.ps1. When
provided, only approved runnable plan items are selected. Items that are not
approved, not implemented, or not aligned are not applied.

.PARAMETER SkipDefender
Skips the Microsoft Defender real-time protection control. Use only when an
approved EDR replaces Defender.

.PARAMETER SkipAuditPolicy
Skips audit policy changes. Use when audit policy is centrally managed by Group
Policy, MDM, or another approved baseline.

.PARAMETER ExcludeControlId
One or more control IDs to exclude from the run. Use this when another approved
product owns the control, such as ESET managing host firewall policy.

.PARAMETER OnlyControlId
Runs only the specified control IDs and marks other controls as excluded.

.PARAMETER ListControls
Prints available control IDs, severities, operational impact, and default
actions, then exits without writing a report.

.EXAMPLE
.\Set-WindowsBaselineHardening.ps1

Preview all baseline controls without changing the host.

.EXAMPLE
.\Set-WindowsBaselineHardening.ps1 -Apply

Apply all default baseline controls. Run PowerShell as Administrator.

.EXAMPLE
.\Set-WindowsBaselineHardening.ps1 -ListControls

List stable control IDs that can be used with -ExcludeControlId or -OnlyControlId.

.EXAMPLE
.\Set-WindowsBaselineHardening.ps1 -ExcludeControlId WIN-HARDEN-FW-001

Preview the baseline while excluding the Windows Firewall control.

.EXAMPLE
.\Set-WindowsBaselineHardening.ps1 -ExcludeControlId WIN-HARDEN-FW-001,WIN-HARDEN-DEF-001

Preview the baseline while excluding multiple controls.

.EXAMPLE
.\Set-WindowsBaselineHardening.ps1 -OnlyControlId WIN-HARDEN-RDP-001 -Apply

Apply only the RDP Network Level Authentication control.

.EXAMPLE
.\Set-WindowsBaselineHardening.ps1 -PlanPath .\reports\server01-remediation-plan.json

Preview only controls approved in the remediation plan.

.EXAMPLE
.\Set-WindowsBaselineHardening.ps1 -PlanPath .\reports\server01-remediation-plan.json -Apply

Apply only approved runnable controls from the remediation plan.

.EXAMPLE
.\Set-WindowsBaselineHardening.ps1 -SkipDefender -SkipAuditPolicy -ReportPath .\reports\server01-hardening.json

Write a dry-run report while skipping Defender and audit policy controls.

.EXAMPLE
.\Set-WindowsBaselineHardening.ps1 -Apply -BackupDirectory .\backups\server01-baseline -ReportPath .\reports\server01-hardening.json

Apply the selected baseline with explicit backup and report paths.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Apply,
    [string]$ReportPath = ".\reports\windows-hardening-plan-$env:COMPUTERNAME-$(Get-Date -Format 'yyyyMMdd-HHmmss').json",
    [string]$BackupDirectory = ".\backups\windows-baseline-$env:COMPUTERNAME-$(Get-Date -Format 'yyyyMMdd-HHmmss')",
    [string]$PlanPath = "",
    [switch]$SkipDefender,
    [switch]$SkipAuditPolicy,
    [string[]]$ExcludeControlId = @(),
    [string[]]$OnlyControlId = @(),
    [switch]$ListControls
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$Results = New-Object System.Collections.Generic.List[object]
$script:PlanSelection = $null
$script:BackupManifest = $null
$script:BackupManifestPath = $null

function Get-KnownHardeningControls {
    @(
        [pscustomobject][ordered]@{ ControlId = "WIN-HARDEN-FW-001"; Severity = "High"; Control = "Windows Firewall"; DefaultAction = "Enable all firewall profiles"; OperationalImpact = "Medium" },
        [pscustomobject][ordered]@{ ControlId = "WIN-HARDEN-FW-002"; Severity = "Medium"; Control = "Windows Firewall"; DefaultAction = "Set default inbound action to Block for all profiles"; OperationalImpact = "Medium" },
        [pscustomobject][ordered]@{ ControlId = "WIN-HARDEN-PWD-001"; Severity = "Medium"; Control = "Password Policy"; DefaultAction = "Set minimum password length to 14"; OperationalImpact = "Medium" },
        [pscustomobject][ordered]@{ ControlId = "WIN-HARDEN-PWD-002"; Severity = "High"; Control = "Password Policy"; DefaultAction = "Set account lockout threshold to 5 attempts"; OperationalImpact = "Medium" },
        [pscustomobject][ordered]@{ ControlId = "WIN-HARDEN-SMB-001"; Severity = "Critical"; Control = "SMBv1"; DefaultAction = "Disable SMBv1 server protocol"; OperationalImpact = "Medium" },
        [pscustomobject][ordered]@{ ControlId = "WIN-HARDEN-SMB-002"; Severity = "High"; Control = "SMBv1 Client"; DefaultAction = "Disable SMBv1 client driver"; OperationalImpact = "Medium" },
        [pscustomobject][ordered]@{ ControlId = "WIN-HARDEN-SMB-003"; Severity = "High"; Control = "SMB Guest Auth"; DefaultAction = "Disable insecure SMB guest logons"; OperationalImpact = "Low" },
        [pscustomobject][ordered]@{ ControlId = "WIN-HARDEN-UAC-001"; Severity = "High"; Control = "UAC"; DefaultAction = "Set EnableLUA to 1"; OperationalImpact = "Medium" },
        [pscustomobject][ordered]@{ ControlId = "WIN-HARDEN-UAC-002"; Severity = "Medium"; Control = "UAC"; DefaultAction = "Set ConsentPromptBehaviorAdmin to 2"; OperationalImpact = "Low" },
        [pscustomobject][ordered]@{ ControlId = "WIN-HARDEN-UAC-003"; Severity = "Medium"; Control = "UAC"; DefaultAction = "Set PromptOnSecureDesktop to 1"; OperationalImpact = "Low" },
        [pscustomobject][ordered]@{ ControlId = "WIN-HARDEN-LLMNR-001"; Severity = "Medium"; Control = "LLMNR"; DefaultAction = "Set EnableMulticast to 0"; OperationalImpact = "Low" },
        [pscustomobject][ordered]@{ ControlId = "WIN-HARDEN-RDP-001"; Severity = "High"; Control = "RDP Network Level Authentication"; DefaultAction = "Set UserAuthentication to 1"; OperationalImpact = "Medium" },
        [pscustomobject][ordered]@{ ControlId = "WIN-HARDEN-RDP-002"; Severity = "Medium"; Control = "Remote Desktop"; DefaultAction = "Disable RDP if not required"; OperationalImpact = "High" },
        [pscustomobject][ordered]@{ ControlId = "WIN-HARDEN-LOCAL-001"; Severity = "High"; Control = "Guest Account"; DefaultAction = "Disable local Guest account"; OperationalImpact = "Low" },
        [pscustomobject][ordered]@{ ControlId = "WIN-HARDEN-DEF-001"; Severity = "High"; Control = "Microsoft Defender"; DefaultAction = "Ensure real-time monitoring is enabled"; OperationalImpact = "Low" },
        [pscustomobject][ordered]@{ ControlId = "WIN-HARDEN-DEF-002"; Severity = "High"; Control = "Microsoft Defender Policy"; DefaultAction = "Set DisableAntiSpyware to 0"; OperationalImpact = "Medium" },
        [pscustomobject][ordered]@{ ControlId = "WIN-HARDEN-PS-001"; Severity = "Medium"; Control = "PowerShell Logging"; DefaultAction = "Enable script block logging"; OperationalImpact = "Low" },
        [pscustomobject][ordered]@{ ControlId = "WIN-HARDEN-SVC-001"; Severity = "High"; Control = "Security Services"; DefaultAction = "Start Windows Firewall and Event Log services"; OperationalImpact = "Medium" },
        [pscustomobject][ordered]@{ ControlId = "WIN-HARDEN-WINRM-001"; Severity = "Medium"; Control = "WinRM Service"; DefaultAction = "Disable WinRM service if not required"; OperationalImpact = "High" },
        [pscustomobject][ordered]@{ ControlId = "WIN-HARDEN-WINRM-002"; Severity = "Medium"; Control = "WinRM Client"; DefaultAction = "Disable client Basic authentication"; OperationalImpact = "Low" },
        [pscustomobject][ordered]@{ ControlId = "WIN-HARDEN-WINRM-003"; Severity = "Medium"; Control = "WinRM Client"; DefaultAction = "Disable client unencrypted traffic"; OperationalImpact = "Low" },
        [pscustomobject][ordered]@{ ControlId = "WIN-HARDEN-WINRM-004"; Severity = "Medium"; Control = "WinRM Client"; DefaultAction = "Disable client Digest authentication"; OperationalImpact = "Low" },
        [pscustomobject][ordered]@{ ControlId = "WIN-HARDEN-WINRM-005"; Severity = "Medium"; Control = "WinRM Service"; DefaultAction = "Disable service Basic authentication"; OperationalImpact = "Low" },
        [pscustomobject][ordered]@{ ControlId = "WIN-HARDEN-WINRM-006"; Severity = "Medium"; Control = "WinRM Service"; DefaultAction = "Disable automatic listener configuration"; OperationalImpact = "Medium" },
        [pscustomobject][ordered]@{ ControlId = "WIN-HARDEN-WINRM-007"; Severity = "Medium"; Control = "WinRM Service"; DefaultAction = "Disable service unencrypted traffic"; OperationalImpact = "Low" },
        [pscustomobject][ordered]@{ ControlId = "WIN-HARDEN-WINRM-008"; Severity = "Medium"; Control = "WinRM Service"; DefaultAction = "Disable RunAs credential storage"; OperationalImpact = "Low" },
        [pscustomobject][ordered]@{ ControlId = "WIN-HARDEN-WINRM-009"; Severity = "Medium"; Control = "WinRM Remote Shell"; DefaultAction = "Disable remote shell access"; OperationalImpact = "Medium" },
        [pscustomobject][ordered]@{ ControlId = "WIN-HARDEN-AUDIT-LOGON"; Severity = "High"; Control = "Audit Policy"; DefaultAction = "Enable Logon success and failure auditing"; OperationalImpact = "Low" },
        [pscustomobject][ordered]@{ ControlId = "WIN-HARDEN-AUDIT-LOCKOUT"; Severity = "High"; Control = "Audit Policy"; DefaultAction = "Enable Account Lockout success and failure auditing"; OperationalImpact = "Low" },
        [pscustomobject][ordered]@{ ControlId = "WIN-HARDEN-AUDIT-UAM"; Severity = "Medium"; Control = "Audit Policy"; DefaultAction = "Enable User Account Management success and failure auditing"; OperationalImpact = "Low" },
        [pscustomobject][ordered]@{ ControlId = "WIN-HARDEN-AUDIT-SGM"; Severity = "Medium"; Control = "Audit Policy"; DefaultAction = "Enable Security Group Management success and failure auditing"; OperationalImpact = "Low" },
        [pscustomobject][ordered]@{ ControlId = "WIN-HARDEN-AUDIT-PROC"; Severity = "Medium"; Control = "Audit Policy"; DefaultAction = "Enable Process Creation success and failure auditing"; OperationalImpact = "Medium" },
        [pscustomobject][ordered]@{ ControlId = "WIN-HARDEN-AUDIT-POLICY"; Severity = "Medium"; Control = "Audit Policy"; DefaultAction = "Enable Audit Policy Change success and failure auditing"; OperationalImpact = "Low" }
    )
}

function Get-ManualApprovalControlIds {
    @(
        "WIN-HARDEN-DEF-002",
        "WIN-HARDEN-RDP-002",
        "WIN-HARDEN-SVC-001",
        "WIN-HARDEN-WINRM-001"
    )
}

function Get-ControlSelectionSkipReason {
    param([Parameter(Mandatory = $true)][string]$ControlId)

    if ($OnlyControlId.Count -gt 0 -and -not ($OnlyControlId -contains $ControlId)) {
        return "Excluded because it was not selected by -OnlyControlId."
    }

    if ($ExcludeControlId -contains $ControlId) {
        return "Excluded by -ExcludeControlId."
    }

    $manualApprovalControlIds = @(Get-ManualApprovalControlIds)
    if ($null -eq $script:PlanSelection -and $OnlyControlId.Count -eq 0 -and $manualApprovalControlIds -contains $ControlId) {
        return "Excluded by default because this control requires a remediation plan approval or explicit -OnlyControlId selection."
    }

    $planSkipReason = Get-PlanSelectionSkipReason -ControlId $ControlId
    if ($planSkipReason) {
        return $planSkipReason
    }

    return $null
}

function Assert-KnownControlIds {
    param(
        [string[]]$ControlIds,
        [string]$ParameterName
    )

    if (-not $ControlIds -or $ControlIds.Count -eq 0) {
        return
    }

    $knownIds = @(Get-KnownHardeningControls | ForEach-Object { $_.ControlId })
    foreach ($controlId in $ControlIds) {
        if ($knownIds -notcontains $controlId) {
            throw "Unknown control ID '$controlId' in $ParameterName. Run with -ListControls to see valid control IDs."
        }
    }
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function New-ParentDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)

    $parent = Split-Path -Path $Path -Parent
    if ($parent -and -not (Test-Path -Path $parent)) {
        New-Item -Path $parent -ItemType Directory -Force | Out-Null
    }
}

function Add-Result {
    param(
        [string]$ControlId,
        [string]$Control,
        [string]$Severity,
        [string]$Action,
        [string]$Status,
        [string]$Details,
        [string]$WhyItMatters,
        [string]$RiskIfNotApplied,
        [string]$OperationalImpact = "Low",
        [string]$Recommendation,
        [string]$Rollback = "Restore the related registry backup or revert the setting through Group Policy/local policy."
    )

    $planContext = Get-PlanContextForControlId -ControlId $ControlId
    $Results.Add([ordered]@{
        ControlId        = $ControlId
        PlanItemIds      = @(Get-ObjectValue -InputObject $planContext -Name "PlanItemIds")
        FindingIds       = @(Get-ObjectValue -InputObject $planContext -Name "FindingIds")
        Control          = $Control
        Severity         = $Severity
        Action           = $Action
        Status           = $Status
        Details          = $Details
        WhyItMatters     = $WhyItMatters
        RiskIfNotApplied = $RiskIfNotApplied
        OperationalImpact = $OperationalImpact
        Recommendation   = $Recommendation
        Rollback         = $Rollback
    }) | Out-Null
}

function Invoke-SafeChange {
    param(
        [string]$ControlId,
        [string]$Control,
        [string]$Severity,
        [string]$Action,
        [string]$WhyItMatters,
        [string]$RiskIfNotApplied,
        [string]$OperationalImpact = "Low",
        [string]$Recommendation,
        [string]$Rollback = "Restore the related registry backup or revert the setting through Group Policy/local policy.",
        [scriptblock]$ScriptBlock
    )

    $selectionSkipReason = Get-ControlSelectionSkipReason -ControlId $ControlId
    if ($selectionSkipReason) {
        Add-Result -ControlId $ControlId -Control $Control -Severity $Severity -Action $Action -Status "Excluded" -Details $selectionSkipReason -WhyItMatters $WhyItMatters -RiskIfNotApplied $RiskIfNotApplied -OperationalImpact $OperationalImpact -Recommendation $Recommendation -Rollback $Rollback
        return
    }

    if (-not $Apply) {
        Add-Result -ControlId $ControlId -Control $Control -Severity $Severity -Action $Action -Status "DryRun" -Details "No change applied. Run with -Apply to enforce." -WhyItMatters $WhyItMatters -RiskIfNotApplied $RiskIfNotApplied -OperationalImpact $OperationalImpact -Recommendation $Recommendation -Rollback $Rollback
        return
    }

    try {
        if ($PSCmdlet.ShouldProcess($Control, $Action)) {
            & $ScriptBlock
            Add-Result -ControlId $ControlId -Control $Control -Severity $Severity -Action $Action -Status "Applied" -Details "Completed" -WhyItMatters $WhyItMatters -RiskIfNotApplied $RiskIfNotApplied -OperationalImpact $OperationalImpact -Recommendation $Recommendation -Rollback $Rollback
        }
        else {
            Add-Result -ControlId $ControlId -Control $Control -Severity $Severity -Action $Action -Status "Skipped" -Details "ShouldProcess declined" -WhyItMatters $WhyItMatters -RiskIfNotApplied $RiskIfNotApplied -OperationalImpact $OperationalImpact -Recommendation $Recommendation -Rollback $Rollback
        }
    }
    catch {
        Add-Result -ControlId $ControlId -Control $Control -Severity $Severity -Action $Action -Status "Failed" -Details $_.Exception.Message -WhyItMatters $WhyItMatters -RiskIfNotApplied $RiskIfNotApplied -OperationalImpact $OperationalImpact -Recommendation $Recommendation -Rollback $Rollback
    }
}

function Set-RegistryDword {
    param(
        [string]$ControlId,
        [string]$Control,
        [string]$Severity,
        [string]$Path,
        [string]$Name,
        [int]$Value,
        [string]$WhyItMatters,
        [string]$RiskIfNotApplied,
        [string]$OperationalImpact = "Low",
        [string]$Recommendation,
        [string]$Rollback = "Restore the registry value from backup or Group Policy."
    )

    Invoke-SafeChange -ControlId $ControlId -Control $Control -Severity $Severity -Action "Set $Path\$Name to $Value" -WhyItMatters $WhyItMatters -RiskIfNotApplied $RiskIfNotApplied -OperationalImpact $OperationalImpact -Recommendation $Recommendation -Rollback $Rollback -ScriptBlock {
        if (-not (Test-Path -Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
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

function Test-ApprovedPlanItem {
    param([AllowNull()][object]$PlanItem)

    $approvalStatus = Get-ObjectValue -InputObject $PlanItem -Name "ApprovalStatus"
    return "$approvalStatus" -eq "Approved"
}

function New-PlanIssue {
    param(
        [AllowNull()][object]$PlanItem,
        [Parameter(Mandatory = $true)][string]$Reason
    )

    [ordered]@{
        PlanItemId             = Get-ObjectValue -InputObject $PlanItem -Name "PlanItemId"
        FindingId              = Get-ObjectValue -InputObject $PlanItem -Name "FindingId"
        Title                  = Get-ObjectValue -InputObject $PlanItem -Name "Title"
        HardeningControlId     = Get-ObjectValue -InputObject $PlanItem -Name "HardeningControlId"
        HardeningControlStatus = Get-ObjectValue -InputObject $PlanItem -Name "HardeningControlStatus"
        Reason                 = $Reason
    }
}

function Import-RemediationPlan {
    param([Parameter(Mandatory = $true)][string]$Path)

    $resolvedPath = (Resolve-Path -Path $Path).Path
    $plan = Get-Content -Path $resolvedPath -Raw | ConvertFrom-Json
    $planItems = @(Get-ObjectValue -InputObject $plan -Name "PlanItems")
    if (-not $planItems -or $planItems.Count -eq 0) {
        throw "Remediation plan '$resolvedPath' does not contain PlanItems."
    }

    $knownControlIds = @(Get-KnownHardeningControls | ForEach-Object { $_.ControlId })
    $allowedRunnableStatuses = @("Implemented", "ManualApprovalRequired")
    $approvedItems = @($planItems | Where-Object { Test-ApprovedPlanItem -PlanItem $_ })
    $runnableItems = New-Object System.Collections.Generic.List[object]
    $issues = New-Object System.Collections.Generic.List[object]
    $blockedReasonsByControlId = @{}
    $itemsByControlId = @{}

    foreach ($item in @($approvedItems)) {
        $controlId = Get-ObjectValue -InputObject $item -Name "HardeningControlId"
        $controlStatus = Get-ObjectValue -InputObject $item -Name "HardeningControlStatus"
        $issueReason = $null

        if (-not $controlId) {
            $issueReason = "Approved plan item has no hardening control ID and cannot be applied by this script."
        }
        elseif ($knownControlIds -notcontains $controlId) {
            $issueReason = "Approved plan item references '$controlId', but that control is not implemented by this script."
        }
        elseif ($allowedRunnableStatuses -notcontains $controlStatus) {
            $issueReason = "Approved plan item has HardeningControlStatus='$controlStatus'. Only Implemented or ManualApprovalRequired controls can run."
        }

        if ($issueReason) {
            $issues.Add((New-PlanIssue -PlanItem $item -Reason $issueReason)) | Out-Null
            if ($controlId) {
                if (-not $blockedReasonsByControlId.Contains($controlId)) {
                    $blockedReasonsByControlId[$controlId] = @()
                }
                $blockedReasonsByControlId[$controlId] = @($blockedReasonsByControlId[$controlId]) + $issueReason
            }
            continue
        }

        $runnableItems.Add($item) | Out-Null
        if (-not $itemsByControlId.Contains($controlId)) {
            $itemsByControlId[$controlId] = @()
        }
        $itemsByControlId[$controlId] = @($itemsByControlId[$controlId]) + $item
    }

    $metadata = Get-ObjectValue -InputObject $plan -Name "ReportMetadata"
    [ordered]@{
        Path                       = $resolvedPath
        SourceAuditReport          = Get-ObjectValue -InputObject $metadata -Name "SourceAuditReport"
        SourceAuditReportName      = Get-ObjectValue -InputObject $metadata -Name "SourceAuditReportName"
        ComputerName               = Get-ObjectValue -InputObject $metadata -Name "ComputerName"
        PlanSchemaVersion          = Get-ObjectValue -InputObject $metadata -Name "PlanSchemaVersion"
        PlanItemCount              = $planItems.Count
        ApprovedPlanItemCount      = $approvedItems.Count
        RunnablePlanItemCount      = $runnableItems.Count
        ApprovedControlIds         = @($itemsByControlId.Keys | Sort-Object)
        ItemsByControlId           = $itemsByControlId
        BlockedReasonsByControlId  = $blockedReasonsByControlId
        BlockedApprovedPlanItems   = @($issues.ToArray())
    }
}

function Get-PlanSelectionSkipReason {
    param([Parameter(Mandatory = $true)][string]$ControlId)

    if ($null -eq $script:PlanSelection) {
        return $null
    }

    $blockedReasonsByControlId = Get-ObjectValue -InputObject $script:PlanSelection -Name "BlockedReasonsByControlId"
    if ($blockedReasonsByControlId -and $blockedReasonsByControlId.Contains($ControlId)) {
        return "Excluded because the approved plan item is not runnable: $(@($blockedReasonsByControlId[$ControlId]) -join '; ')"
    }

    $approvedControlIds = @(Get-ObjectValue -InputObject $script:PlanSelection -Name "ApprovedControlIds")
    if ($approvedControlIds -notcontains $ControlId) {
        return "Excluded because no approved runnable remediation plan item selected this control."
    }

    return $null
}

function Get-PlanContextForControlId {
    param([Parameter(Mandatory = $true)][string]$ControlId)

    $context = [ordered]@{
        PlanItemIds = @()
        FindingIds  = @()
    }

    if ($null -eq $script:PlanSelection) {
        return $context
    }

    $itemsByControlId = Get-ObjectValue -InputObject $script:PlanSelection -Name "ItemsByControlId"
    if (-not $itemsByControlId -or -not $itemsByControlId.Contains($ControlId)) {
        return $context
    }

    $items = @($itemsByControlId[$ControlId])
    $context["PlanItemIds"] = @($items | ForEach-Object { Get-ObjectValue -InputObject $_ -Name "PlanItemId" })
    $context["FindingIds"] = @($items | ForEach-Object { Get-ObjectValue -InputObject $_ -Name "FindingId" })
    return $context
}

function Test-ControlWillRun {
    param([Parameter(Mandatory = $true)][string]$ControlId)

    if ($SkipDefender -and $ControlId -like "WIN-HARDEN-DEF-*") {
        return $false
    }

    if ($SkipAuditPolicy -and $ControlId -like "WIN-HARDEN-AUDIT-*") {
        return $false
    }

    return -not [bool](Get-ControlSelectionSkipReason -ControlId $ControlId)
}

function Get-SelectedHardeningControlIds {
    $knownControlIds = @(Get-KnownHardeningControls | ForEach-Object { $_.ControlId })
    return @($knownControlIds | Where-Object { Test-ControlWillRun -ControlId $_ })
}

function Get-ControlBackupDefinitions {
    @(
        [pscustomobject][ordered]@{
            Name       = "firewall-policy"
            RegPath    = "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
            ControlIds = @("WIN-HARDEN-FW-001", "WIN-HARDEN-FW-002")
            Reason     = "Windows Firewall profile state and default inbound policy."
            Rollback   = "Import this registry backup or restore firewall profile settings through Windows Defender Firewall or Group Policy."
        },
        [pscustomobject][ordered]@{
            Name       = "system-policies"
            RegPath    = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            ControlIds = @("WIN-HARDEN-UAC-001", "WIN-HARDEN-UAC-002", "WIN-HARDEN-UAC-003")
            Reason     = "UAC system policy values."
            Rollback   = "Import this registry backup or restore the UAC values through Group Policy/local policy."
        },
        [pscustomobject][ordered]@{
            Name       = "dnsclient-policy"
            RegPath    = "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
            ControlIds = @("WIN-HARDEN-LLMNR-001")
            Reason     = "DNS Client policy values used by the LLMNR control."
            Rollback   = "Import this registry backup or remove/restore EnableMulticast through Group Policy/local policy."
        },
        [pscustomobject][ordered]@{
            Name       = "terminal-server"
            RegPath    = "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server"
            ControlIds = @("WIN-HARDEN-RDP-001", "WIN-HARDEN-RDP-002")
            Reason     = "Remote Desktop and RDP listener policy values."
            Rollback   = "Import this registry backup or restore the RDP values during an approved maintenance window."
        },
        [pscustomobject][ordered]@{
            Name       = "smb-server"
            RegPath    = "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
            ControlIds = @("WIN-HARDEN-SMB-001")
            Reason     = "SMB server protocol configuration."
            Rollback   = "Import this registry backup or restore SMB server configuration with Set-SmbServerConfiguration."
        },
        [pscustomobject][ordered]@{
            Name       = "smb1-client"
            RegPath    = "HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10"
            ControlIds = @("WIN-HARDEN-SMB-002")
            Reason     = "SMBv1 client driver startup configuration."
            Rollback   = "Import this registry backup and reinstall SMB1Protocol only for an approved legacy exception."
        },
        [pscustomobject][ordered]@{
            Name       = "smb-workstation-policy"
            RegPath    = "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"
            ControlIds = @("WIN-HARDEN-SMB-003")
            Reason     = "SMB workstation policy values."
            Rollback   = "Import this registry backup or restore the LanmanWorkstation policy through Group Policy/local policy."
        },
        [pscustomobject][ordered]@{
            Name       = "powershell-policy"
            RegPath    = "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
            ControlIds = @("WIN-HARDEN-PS-001")
            Reason     = "PowerShell logging policy values."
            Rollback   = "Import this registry backup or restore PowerShell logging policy through Group Policy/local policy."
        },
        [pscustomobject][ordered]@{
            Name       = "mpssvc-service"
            RegPath    = "HKLM\SYSTEM\CurrentControlSet\Services\MpsSvc"
            ControlIds = @("WIN-HARDEN-SVC-001")
            Reason     = "Windows Firewall service startup configuration."
            Rollback   = "Import this registry backup and restore the approved service state if required."
        },
        [pscustomobject][ordered]@{
            Name       = "eventlog-service"
            RegPath    = "HKLM\SYSTEM\CurrentControlSet\Services\EventLog"
            ControlIds = @("WIN-HARDEN-SVC-001")
            Reason     = "Windows Event Log service startup configuration."
            Rollback   = "Import this registry backup and restore the approved service state if required."
        },
        [pscustomobject][ordered]@{
            Name       = "winrm-service"
            RegPath    = "HKLM\SYSTEM\CurrentControlSet\Services\WinRM"
            ControlIds = @("WIN-HARDEN-WINRM-001")
            Reason     = "WinRM service startup configuration."
            Rollback   = "Import this registry backup and restore the approved WinRM service state if required."
        },
        [pscustomobject][ordered]@{
            Name       = "winrm-policy"
            RegPath    = "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM"
            ControlIds = @("WIN-HARDEN-WINRM-002", "WIN-HARDEN-WINRM-003", "WIN-HARDEN-WINRM-004", "WIN-HARDEN-WINRM-005", "WIN-HARDEN-WINRM-006", "WIN-HARDEN-WINRM-007", "WIN-HARDEN-WINRM-008", "WIN-HARDEN-WINRM-009")
            Reason     = "WinRM client, service, and remote shell policy values."
            Rollback   = "Import this registry backup or restore WinRM policy through Group Policy/local policy."
        },
        [pscustomobject][ordered]@{
            Name       = "defender-policy"
            RegPath    = "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender"
            ControlIds = @("WIN-HARDEN-DEF-002")
            Reason     = "Microsoft Defender policy values."
            Rollback   = "Import this registry backup or restore Defender policy through central security management."
        }
    )
}

function Get-ControlBackupCoverageNotes {
    @(
        [pscustomobject][ordered]@{
            ControlIds = @("WIN-HARDEN-PWD-001", "WIN-HARDEN-PWD-002")
            Coverage   = "NoRegistryBackup"
            Reason     = "Uses net.exe accounts for local account policy; a .reg file is not a reliable rollback format for this setting."
            Rollback   = "Restore the previous local or domain password policy through net accounts, Group Policy, or identity policy."
        },
        [pscustomobject][ordered]@{
            ControlIds = @("WIN-HARDEN-SMB-002")
            Coverage   = "PartialRegistryBackup"
            Reason     = "Backs up the SMBv1 client driver registry key, but optional Windows feature state is not fully represented by the .reg file."
            Rollback   = "Restore the driver registry value and re-enable SMB1Protocol only for an approved legacy exception."
        },
        [pscustomobject][ordered]@{
            ControlIds = @("WIN-HARDEN-LOCAL-001")
            Coverage   = "NoRegistryBackup"
            Reason     = "Disables a local account through the LocalAccounts module; SAM account state is not exported as a .reg rollback."
            Rollback   = "Re-enable the account only for a documented exception."
        },
        [pscustomobject][ordered]@{
            ControlIds = @("WIN-HARDEN-DEF-001")
            Coverage   = "NoRegistryBackup"
            Reason     = "Uses Set-MpPreference for Defender runtime preferences; central EDR or Defender management may also control these values."
            Rollback   = "Restore previous Defender preferences from central management if required."
        },
        [pscustomobject][ordered]@{
            ControlIds = @("WIN-HARDEN-SVC-001", "WIN-HARDEN-WINRM-001")
            Coverage   = "PartialRegistryBackup"
            Reason     = "Backs up service registry configuration, but the live running/stopped state is not fully represented by the .reg file."
            Rollback   = "Restore service startup type and state to the approved management baseline."
        },
        [pscustomobject][ordered]@{
            ControlIds = @("WIN-HARDEN-AUDIT-LOGON", "WIN-HARDEN-AUDIT-LOCKOUT", "WIN-HARDEN-AUDIT-UAM", "WIN-HARDEN-AUDIT-SGM", "WIN-HARDEN-AUDIT-PROC", "WIN-HARDEN-AUDIT-POLICY")
            Coverage   = "NoRegistryBackup"
            Reason     = "Uses auditpol for audit subcategories; registry .reg export is not the right rollback artifact."
            Rollback   = "Disable or tune audit subcategories through auditpol or Group Policy."
        }
    )
}

function Convert-RegExportPathToProviderPath {
    param([Parameter(Mandatory = $true)][string]$RegPath)

    if ($RegPath.StartsWith("HKLM:\")) {
        return $RegPath
    }

    if ($RegPath.StartsWith("HKLM\")) {
        return "HKLM:\$($RegPath.Substring(5))"
    }

    return $RegPath
}

function Backup-RegistryKey {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$RegPath,
        [Parameter(Mandatory = $true)][string]$ResolvedBackupDirectory,
        [string[]]$ControlIds = @(),
        [string]$Reason = "",
        [string]$Rollback = ""
    )

    $providerPath = Convert-RegExportPathToProviderPath -RegPath $RegPath
    $target = Join-Path -Path $ResolvedBackupDirectory -ChildPath "$Name.reg"
    $entry = [ordered]@{
        Name         = $Name
        RegistryPath = $RegPath
        ProviderPath = $providerPath
        BackupFile   = $null
        ControlIds   = @($ControlIds)
        Reason       = $Reason
        Rollback     = $Rollback
        SourceExisted = $false
        Status       = "NotStarted"
        Details      = ""
    }

    if (-not (Test-Path -Path $providerPath)) {
        $entry["Status"] = "SkippedMissingSource"
        $entry["Details"] = "Registry key did not exist before remediation. If the control creates it, rollback may require removing the created value or key."
        return $entry
    }

    $entry["SourceExisted"] = $true
    $output = & reg.exe export $RegPath $target /y 2>&1
    if ($LASTEXITCODE -ne 0) {
        $details = @($output) -join " "
        throw "Failed to export registry backup '$RegPath' to '$target'. $details"
    }

    $entry["BackupFile"] = (Resolve-Path -Path $target).Path
    $entry["Status"] = "Exported"
    $entry["Details"] = "Registry key exported before remediation."
    return $entry
}

function Invoke-SelectiveBackups {
    if (-not $Apply) {
        return $null
    }

    New-Item -Path $BackupDirectory -ItemType Directory -Force | Out-Null
    $resolvedBackupDirectory = (Resolve-Path -Path $BackupDirectory).Path
    $manifestPath = Join-Path -Path $resolvedBackupDirectory -ChildPath "backup-manifest.json"
    $selectedControlIds = @(Get-SelectedHardeningControlIds)
    $registryBackups = New-Object System.Collections.Generic.List[object]
    $coverageNotes = New-Object System.Collections.Generic.List[object]

    foreach ($definition in @(Get-ControlBackupDefinitions)) {
        $definitionControlIds = @(Get-ObjectValue -InputObject $definition -Name "ControlIds")
        $selectedForBackup = @($definitionControlIds | Where-Object { $selectedControlIds -contains $_ })
        if ($selectedForBackup.Count -eq 0) {
            continue
        }

        $registryBackups.Add((Backup-RegistryKey `
                    -Name (Get-ObjectValue -InputObject $definition -Name "Name") `
                    -RegPath (Get-ObjectValue -InputObject $definition -Name "RegPath") `
                    -ResolvedBackupDirectory $resolvedBackupDirectory `
                    -ControlIds $selectedForBackup `
                    -Reason (Get-ObjectValue -InputObject $definition -Name "Reason") `
                    -Rollback (Get-ObjectValue -InputObject $definition -Name "Rollback"))) | Out-Null
    }

    foreach ($note in @(Get-ControlBackupCoverageNotes)) {
        $noteControlIds = @(Get-ObjectValue -InputObject $note -Name "ControlIds")
        $selectedForNote = @($noteControlIds | Where-Object { $selectedControlIds -contains $_ })
        if ($selectedForNote.Count -eq 0) {
            continue
        }

        $coverageNotes.Add([ordered]@{
                ControlIds = @($selectedForNote)
                Coverage   = Get-ObjectValue -InputObject $note -Name "Coverage"
                Reason     = Get-ObjectValue -InputObject $note -Name "Reason"
                Rollback   = Get-ObjectValue -InputObject $note -Name "Rollback"
            }) | Out-Null
    }

    $manifest = [ordered]@{
        SchemaVersion      = "1.0"
        BackupMode         = "Selective"
        ComputerName       = $env:COMPUTERNAME
        GeneratedAtUtc     = (Get-Date).ToUniversalTime().ToString("o")
        BackupDirectory    = $resolvedBackupDirectory
        ManifestPath       = $manifestPath
        PlanPath           = if ($script:PlanSelection) { Get-ObjectValue -InputObject $script:PlanSelection -Name "Path" } else { $null }
        ExcludeControlId   = @($ExcludeControlId)
        OnlyControlId      = @($OnlyControlId)
        SkipDefender       = [bool]$SkipDefender
        SkipAuditPolicy    = [bool]$SkipAuditPolicy
        SelectedControlIds = @($selectedControlIds)
        RegistryBackups    = @($registryBackups.ToArray())
        CoverageNotes      = @($coverageNotes.ToArray())
        Notes              = @(
            "Registry backups are created only for selected controls that map to registry-backed settings.",
            "A missing-source backup entry means the registry key did not exist before remediation.",
            "CoverageNotes identify selected controls where rollback is not fully captured by .reg files."
        )
    }

    $manifest | ConvertTo-Json -Depth 6 | Out-File -FilePath $manifestPath -Encoding utf8
    return $manifest
}

function Get-CountByField {
    param(
        [object[]]$Rows,
        [string]$FieldName
    )

    $counts = [ordered]@{}
    foreach ($row in @($Rows)) {
        $value = Get-ObjectValue -InputObject $row -Name $FieldName
        if (-not $value) {
            $value = "Unknown"
        }
        if (-not $counts.Contains($value)) {
            $counts[$value] = 0
        }
        $counts[$value]++
    }

    return $counts
}

function New-HardeningSummary {
    param([object[]]$Rows)

    $highPriority = New-Object System.Collections.Generic.List[object]
    $notes = New-Object System.Collections.Generic.List[string]
    foreach ($row in @($Rows)) {
        $severity = Get-ObjectValue -InputObject $row -Name "Severity"
        if ($severity -in @("Critical", "High")) {
            $highPriority.Add([ordered]@{
                ControlId         = Get-ObjectValue -InputObject $row -Name "ControlId"
                Severity          = $severity
                Control           = Get-ObjectValue -InputObject $row -Name "Control"
                Action            = Get-ObjectValue -InputObject $row -Name "Action"
                WhyItMatters      = Get-ObjectValue -InputObject $row -Name "WhyItMatters"
                OperationalImpact = Get-ObjectValue -InputObject $row -Name "OperationalImpact"
                Recommendation    = Get-ObjectValue -InputObject $row -Name "Recommendation"
            }) | Out-Null
        }
    }

    $notes.Add("Severity describes the risk reduced by the control, not proof that the current host is vulnerable.") | Out-Null
    $notes.Add("DryRun means no change was made. Review HighPriorityReview and operational impact before -Apply.") | Out-Null
    $notes.Add("Use the Windows security audit report to confirm which controls are already compliant.") | Out-Null
    if ($null -ne $script:PlanSelection) {
        $notes.Add("PlanPath mode selects only approved runnable remediation plan items from the JSON plan.") | Out-Null
        $notes.Add("Approved plan items with unimplemented, manual-only, or alignment-required controls are not applied.") | Out-Null
    }
    if ($Apply) {
        $notes.Add("Apply mode creates selective registry backups and backup-manifest.json before remediation.") | Out-Null
    }

    [ordered]@{
        Mode                  = if ($Apply) { "Apply" } else { "DryRun" }
        PlanMode              = [bool]($null -ne $script:PlanSelection)
        TotalControls         = $Rows.Count
        StatusCounts          = Get-CountByField -Rows $Rows -FieldName "Status"
        SeverityCounts        = Get-CountByField -Rows $Rows -FieldName "Severity"
        HighPriorityReview    = @($highPriority.ToArray())
        Notes                 = @($notes.ToArray())
    }
}

if ($ListControls) {
    Get-KnownHardeningControls | Format-Table ControlId, Severity, OperationalImpact, Control, DefaultAction -AutoSize
    return
}

Assert-KnownControlIds -ControlIds $ExcludeControlId -ParameterName "-ExcludeControlId"
Assert-KnownControlIds -ControlIds $OnlyControlId -ParameterName "-OnlyControlId"

if ($PlanPath) {
    $script:PlanSelection = Import-RemediationPlan -Path $PlanPath
    $blockedApprovedPlanItems = @(Get-ObjectValue -InputObject $script:PlanSelection -Name "BlockedApprovedPlanItems")
    if ($blockedApprovedPlanItems.Count -gt 0) {
        $blockedSummary = @($blockedApprovedPlanItems | ForEach-Object {
                "$(Get-ObjectValue -InputObject $_ -Name "PlanItemId") $(Get-ObjectValue -InputObject $_ -Name "HardeningControlId"): $(Get-ObjectValue -InputObject $_ -Name "Reason")"
            }) -join "; "
        if ($Apply) {
            throw "Approved remediation plan contains items that cannot be applied by this script: $blockedSummary"
        }
        Write-Warning "Some approved remediation plan items are not runnable and will be excluded: $blockedSummary"
    }
}

if ($Apply -and -not (Test-IsAdministrator)) {
    throw "Run PowerShell as Administrator when using -Apply."
}

if ($Apply) {
    $script:BackupManifest = Invoke-SelectiveBackups
    $script:BackupManifestPath = Get-ObjectValue -InputObject $script:BackupManifest -Name "ManifestPath"
}

Invoke-SafeChange -ControlId "WIN-HARDEN-FW-001" -Control "Windows Firewall" -Severity "High" -Action "Enable all firewall profiles" -WhyItMatters "Host firewall profiles reduce exposure from unwanted inbound traffic and lateral movement." -RiskIfNotApplied "The server may accept unexpected inbound connections if network firewalls or rules are incomplete." -OperationalImpact "Medium" -Recommendation "Review required RDP, application, monitoring, and management rules before applying on a production terminal server." -Rollback "Disable or adjust profiles/rules through Windows Defender Firewall or Group Policy." -ScriptBlock {
    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
}

Invoke-SafeChange -ControlId "WIN-HARDEN-FW-002" -Control "Windows Firewall" -Severity "Medium" -Action "Set default inbound action to Block for all firewall profiles" -WhyItMatters "A permissive default inbound policy can expose services that should only be reachable through explicit firewall rules." -RiskIfNotApplied "Unexpected services may become reachable if explicit allow rules are not required." -OperationalImpact "Medium" -Recommendation "Confirm required RDP, application, monitoring, and management allow rules before blocking inbound traffic by default." -Rollback "Restore DefaultInboundAction through Windows Defender Firewall or Group Policy if an approved exception is required." -ScriptBlock {
    Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block
}

Invoke-SafeChange -ControlId "WIN-HARDEN-PWD-001" -Control "Password Policy" -Severity "Medium" -Action "Set minimum password length to 14" -WhyItMatters "Shorter passwords are easier to guess, spray, or crack offline if hashes are exposed." -RiskIfNotApplied "Weak local password length requirements can increase account compromise risk." -OperationalImpact "Medium" -Recommendation "Use at least 14 characters unless domain, Entra ID, MFA, or passwordless controls supersede local policy." -Rollback "Restore the previous local or domain password policy through net accounts, Group Policy, or identity policy." -ScriptBlock {
    & net.exe accounts /minpwlen:14 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "net accounts /minpwlen:14 failed with exit code $LASTEXITCODE."
    }
}

Invoke-SafeChange -ControlId "WIN-HARDEN-PWD-002" -Control "Password Policy" -Severity "High" -Action "Set account lockout threshold to 5 attempts" -WhyItMatters "A lockout threshold slows online password guessing and password spray attempts against local accounts." -RiskIfNotApplied "Attackers may have unlimited attempts against local accounts if no lockout threshold is configured." -OperationalImpact "Medium" -Recommendation "Use a nonzero threshold of 5 or fewer invalid attempts and align duration/window with identity policy." -Rollback "Restore the previous lockout policy through net accounts, Group Policy, or identity policy." -ScriptBlock {
    & net.exe accounts /lockoutthreshold:5 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "net accounts /lockoutthreshold:5 failed with exit code $LASTEXITCODE."
    }
    & net.exe accounts /lockoutduration:15 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "net accounts /lockoutduration:15 failed with exit code $LASTEXITCODE."
    }
    & net.exe accounts /lockoutwindow:15 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "net accounts /lockoutwindow:15 failed with exit code $LASTEXITCODE."
    }
}

Invoke-SafeChange -ControlId "WIN-HARDEN-SMB-001" -Control "SMBv1" -Severity "Critical" -Action "Disable SMBv1 server protocol" -WhyItMatters "SMBv1 is obsolete and has a long history of severe exploitation and lateral movement risk." -RiskIfNotApplied "Legacy SMB exposure can increase ransomware and worm-style propagation risk." -OperationalImpact "Medium" -Recommendation "Confirm no legacy scanner, NAS, or line-of-business dependency requires SMBv1 before applying." -Rollback "Re-enable SMBv1 only through an approved exception and maintenance window." -ScriptBlock {
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
}

Invoke-SafeChange -ControlId "WIN-HARDEN-SMB-002" -Control "SMBv1 Client" -Severity "High" -Action "Disable SMBv1 client driver and optional feature if present" -WhyItMatters "The legacy SMBv1 client increases exposure to obsolete file-sharing protocol risks." -RiskIfNotApplied "The host may still connect to legacy SMBv1 endpoints and inherit protocol weaknesses." -OperationalImpact "Medium" -Recommendation "Apply after confirming no legacy scanner, NAS, or line-of-business dependency requires SMBv1." -Rollback "Restore the mrxsmb10 Start value or reinstall SMB1Protocol only for an approved legacy exception." -ScriptBlock {
    if (-not (Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10")) {
        New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" -Force | Out-Null
    }
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" -Name "Start" -Value 4 -PropertyType DWord -Force | Out-Null
    $feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
    if ($feature -and $feature.State -ne "Disabled") {
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart | Out-Null
    }
}

Set-RegistryDword -ControlId "WIN-HARDEN-SMB-003" -Control "SMB Guest Auth" -Severity "High" -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" -Name "AllowInsecureGuestAuth" -Value 0 -WhyItMatters "Guest SMB logons weaken authentication and can expose file-sharing paths without accountable user identity." -RiskIfNotApplied "Legacy shares may allow weak or unaudited access paths." -OperationalImpact "Low" -Recommendation "Disable insecure guest logons unless a documented legacy exception exists." -Rollback "Restore the previous policy value only for a documented legacy NAS or application exception."

Set-RegistryDword -ControlId "WIN-HARDEN-UAC-001" -Control "UAC" -Severity "High" -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -WhyItMatters "UAC keeps administrative elevation explicit and reduces the impact of user-session compromise." -RiskIfNotApplied "Processes can run with broader administrative impact once a user session is compromised." -OperationalImpact "Medium" -Recommendation "Enable UAC and validate admin workflows." -Rollback "Set EnableLUA back to the previous value from backup if an approved exception is required."
Set-RegistryDword -ControlId "WIN-HARDEN-UAC-002" -Control "UAC" -Severity "Medium" -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2 -WhyItMatters "Prompting administrators on the secure desktop makes elevation explicit and harder to spoof." -RiskIfNotApplied "Administrative elevation prompts may be less resistant to spoofing or accidental approval." -OperationalImpact "Low" -Recommendation "Use consent on the secure desktop unless the approved baseline requires credential prompt on secure desktop."
Set-RegistryDword -ControlId "WIN-HARDEN-UAC-003" -Control "UAC" -Severity "Medium" -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 1 -WhyItMatters "Secure desktop prompts reduce tampering or spoofing of elevation prompts." -RiskIfNotApplied "Malware in the user session may have more opportunity to interfere with prompts." -OperationalImpact "Low" -Recommendation "Keep secure desktop enabled for administrator elevation prompts."
Set-RegistryDword -ControlId "WIN-HARDEN-LLMNR-001" -Control "LLMNR" -Severity "Medium" -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -WhyItMatters "LLMNR can support spoofing and credential capture attacks on local networks." -RiskIfNotApplied "Attackers on the same network may abuse name resolution fallback to capture credentials." -OperationalImpact "Low" -Recommendation "Disable LLMNR unless a documented legacy name-resolution dependency exists."
Set-RegistryDword -ControlId "WIN-HARDEN-RDP-001" -Control "RDP Network Level Authentication" -Severity "High" -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1 -WhyItMatters "NLA reduces RDP pre-authentication attack surface." -RiskIfNotApplied "RDP exposes more attack surface before user authentication." -OperationalImpact "Medium" -Recommendation "Require NLA for terminal servers unless legacy clients need a documented exception."
Set-RegistryDword -ControlId "WIN-HARDEN-RDP-002" -Control "Remote Desktop" -Severity "Medium" -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1 -WhyItMatters "Disabling unused RDP removes a high-value remote access surface." -RiskIfNotApplied "RDP may remain reachable if network firewall policy is incomplete or changes later." -OperationalImpact "High" -Recommendation "Disable RDP only on hosts that do not require Remote Desktop administration." -Rollback "Set fDenyTSConnections to 0 during an approved maintenance window if RDP is required."

Invoke-SafeChange -ControlId "WIN-HARDEN-LOCAL-001" -Control "Guest Account" -Severity "High" -Action "Disable local Guest account" -WhyItMatters "Guest access can provide unaudited or weakly controlled local access paths." -RiskIfNotApplied "Unexpected guest access may weaken accountability and local access control." -OperationalImpact "Low" -Recommendation "Keep the local Guest account disabled." -Rollback "Re-enable only for a documented temporary support exception." -ScriptBlock {
    Disable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
}

if (-not $SkipDefender) {
    Invoke-SafeChange -ControlId "WIN-HARDEN-DEF-001" -Control "Microsoft Defender" -Severity "High" -Action "Ensure real-time monitoring is enabled" -WhyItMatters "Real-time protection is a core malware prevention and detection layer." -RiskIfNotApplied "Malware may execute or persist with reduced detection." -OperationalImpact "Low" -Recommendation "Enable Defender real-time components unless an approved EDR fully replaces them." -Rollback "Restore previous Defender preferences from central management if required." -ScriptBlock {
        Set-MpPreference -DisableRealtimeMonitoring $false
        Set-MpPreference -DisableBehaviorMonitoring $false
        Set-MpPreference -DisableIOAVProtection $false
    }
}
else {
    Add-Result -ControlId "WIN-HARDEN-DEF-001" -Control "Microsoft Defender" -Severity "High" -Action "Ensure real-time monitoring is enabled" -Status "Skipped" -Details "Skipped by parameter" -WhyItMatters "Real-time protection is a core malware prevention and detection layer." -RiskIfNotApplied "Malware may execute or persist with reduced detection." -OperationalImpact "Low" -Recommendation "Confirm an approved EDR replacement before skipping." -Rollback "Remove -SkipDefender on a future run."
}

if (-not $SkipDefender) {
    Set-RegistryDword -ControlId "WIN-HARDEN-DEF-002" -Control "Microsoft Defender Policy" -Severity "High" -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 0 -WhyItMatters "A policy that turns off antivirus can remove a core malware prevention and detection layer." -RiskIfNotApplied "Defender may remain disabled by policy even when the service or preferences are changed." -OperationalImpact "Medium" -Recommendation "Set DisableAntiSpyware to 0 only when Defender should be active; skip when an approved EDR owns this control." -Rollback "Restore the previous Defender policy value or central EDR policy if required."
}
else {
    Add-Result -ControlId "WIN-HARDEN-DEF-002" -Control "Microsoft Defender Policy" -Severity "High" -Action "Set DisableAntiSpyware to 0" -Status "Skipped" -Details "Skipped by -SkipDefender." -WhyItMatters "A policy that turns off antivirus can remove a core malware prevention and detection layer." -RiskIfNotApplied "Defender may remain disabled by policy even when the service or preferences are changed." -OperationalImpact "Medium" -Recommendation "Confirm an approved EDR replacement before skipping." -Rollback "Remove -SkipDefender on a future run."
}

Set-RegistryDword -ControlId "WIN-HARDEN-PS-001" -Control "PowerShell Logging" -Severity "Medium" -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -WhyItMatters "Script block logging improves visibility into suspicious PowerShell execution during investigations." -RiskIfNotApplied "Endpoint investigations may lack PowerShell execution evidence." -OperationalImpact "Low" -Recommendation "Enable script block logging and forward PowerShell logs to protected central collection." -Rollback "Set EnableScriptBlockLogging back to the previous policy value if a documented alternate control is required."

Invoke-SafeChange -ControlId "WIN-HARDEN-SVC-001" -Control "Security Services" -Severity "High" -Action "Start Windows Firewall and Event Log services" -WhyItMatters "Stopped security services reduce protection, filtering, or logging coverage." -RiskIfNotApplied "Firewall or event logging services may remain unavailable, reducing protection and investigation evidence." -OperationalImpact "Medium" -Recommendation "Start critical Windows security services unless an approved replacement control owns the function." -Rollback "Restore service startup type and state to the approved baseline if a documented exception is required." -ScriptBlock {
    foreach ($serviceName in @("MpsSvc", "EventLog")) {
        $service = Get-Service -Name $serviceName -ErrorAction Stop
        Set-Service -Name $serviceName -StartupType Automatic
        if ($service.Status -ne "Running") {
            Start-Service -Name $serviceName
        }
    }
}

Invoke-SafeChange -ControlId "WIN-HARDEN-WINRM-001" -Control "WinRM Service" -Severity "Medium" -Action "Disable WinRM service if not required" -WhyItMatters "WinRM is useful for administration but increases remote management exposure if broadly reachable." -RiskIfNotApplied "Remote management may remain reachable through WinRM if network or firewall policy is incomplete." -OperationalImpact "High" -Recommendation "Disable WinRM only when it is not required, or restrict it to trusted management networks with approved authentication and logging." -Rollback "Set WinRM startup type and service state back to the approved management baseline." -ScriptBlock {
    Stop-Service -Name WinRM -Force -ErrorAction SilentlyContinue
    Set-Service -Name WinRM -StartupType Disabled
}

Set-RegistryDword -ControlId "WIN-HARDEN-WINRM-002" -Control "WinRM Client" -Severity "Medium" -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowBasic" -Value 0 -WhyItMatters "Basic authentication can expose credentials if transport protections are weak or misconfigured." -RiskIfNotApplied "WinRM clients may use weaker authentication paths." -OperationalImpact "Low" -Recommendation "Disable WinRM client Basic authentication unless a documented management exception exists."
Set-RegistryDword -ControlId "WIN-HARDEN-WINRM-003" -Control "WinRM Client" -Severity "Medium" -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowUnencryptedTraffic" -Value 0 -WhyItMatters "Unencrypted WinRM traffic can expose management data and credentials." -RiskIfNotApplied "WinRM client sessions may allow unencrypted management traffic." -OperationalImpact "Low" -Recommendation "Disable unencrypted WinRM client traffic."
Set-RegistryDword -ControlId "WIN-HARDEN-WINRM-004" -Control "WinRM Client" -Severity "Medium" -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowDigest" -Value 0 -WhyItMatters "Digest authentication is weaker than modern integrated authentication options." -RiskIfNotApplied "WinRM clients may use legacy authentication." -OperationalImpact "Low" -Recommendation "Disable WinRM client Digest authentication unless a documented exception exists."
Set-RegistryDword -ControlId "WIN-HARDEN-WINRM-005" -Control "WinRM Service" -Severity "Medium" -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowBasic" -Value 0 -WhyItMatters "Basic authentication can expose credentials if transport protections are weak or misconfigured." -RiskIfNotApplied "The WinRM service may accept weaker authentication." -OperationalImpact "Low" -Recommendation "Disable WinRM service Basic authentication."
Set-RegistryDword -ControlId "WIN-HARDEN-WINRM-006" -Control "WinRM Service" -Severity "Medium" -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowAutoConfig" -Value 0 -WhyItMatters "Automatic listener configuration can expose remote management unexpectedly." -RiskIfNotApplied "WinRM listeners may be created without the intended management restrictions." -OperationalImpact "Medium" -Recommendation "Disable automatic WinRM listener configuration unless a managed remote administration baseline requires it."
Set-RegistryDword -ControlId "WIN-HARDEN-WINRM-007" -Control "WinRM Service" -Severity "Medium" -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowUnencryptedTraffic" -Value 0 -WhyItMatters "Unencrypted WinRM traffic can expose management data and credentials." -RiskIfNotApplied "The WinRM service may accept unencrypted management traffic." -OperationalImpact "Low" -Recommendation "Disable unencrypted WinRM service traffic."
Set-RegistryDword -ControlId "WIN-HARDEN-WINRM-008" -Control "WinRM Service" -Severity "Medium" -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "DisableRunAs" -Value 1 -WhyItMatters "Stored RunAs credentials can increase account compromise impact if the host or a management plug-in is abused." -RiskIfNotApplied "WinRM plug-ins may store credentials that increase compromise impact." -OperationalImpact "Low" -Recommendation "Disable WinRM RunAs credential storage unless a documented management plug-in requires it."
Set-RegistryDword -ControlId "WIN-HARDEN-WINRM-009" -Control "WinRM Remote Shell" -Severity "Medium" -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" -Name "AllowRemoteShellAccess" -Value 0 -WhyItMatters "Remote shell access increases remote command execution exposure." -RiskIfNotApplied "WinRM may allow remote shell access beyond approved management workflows." -OperationalImpact "Medium" -Recommendation "Disable remote shell access unless explicitly required and controlled."

if (-not $SkipAuditPolicy) {
    $auditCommands = @(
        @{ Id = "WIN-HARDEN-AUDIT-LOGON"; Name = "Logon"; Command = 'auditpol /set /subcategory:"Logon" /success:enable /failure:enable'; Severity = "High"; Why = "Logon events are essential for detecting brute force, suspicious access, and lateral movement."; Risk = "Investigations may lack evidence for successful or failed logon activity." },
        @{ Id = "WIN-HARDEN-AUDIT-LOCKOUT"; Name = "Account Lockout"; Command = 'auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable'; Severity = "High"; Why = "Lockout events help identify password spray and user-impacting authentication attacks."; Risk = "Password attacks may be harder to detect and correlate." },
        @{ Id = "WIN-HARDEN-AUDIT-UAM"; Name = "User Account Management"; Command = 'auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable'; Severity = "Medium"; Why = "Account creation, deletion, and modification events are important for privilege abuse investigations."; Risk = "Unauthorized account changes may have poor audit trail coverage." },
        @{ Id = "WIN-HARDEN-AUDIT-SGM"; Name = "Security Group Management"; Command = 'auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable'; Severity = "Medium"; Why = "Security group changes can grant administrative or application access."; Risk = "Privilege changes may be missed during investigation." },
        @{ Id = "WIN-HARDEN-AUDIT-PROC"; Name = "Process Creation"; Command = 'auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable'; Severity = "Medium"; Why = "Process creation events improve visibility into suspicious command execution."; Risk = "Endpoint investigations may lack execution evidence."; Impact = "Medium" },
        @{ Id = "WIN-HARDEN-AUDIT-POLICY"; Name = "Audit Policy Change"; Command = 'auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable'; Severity = "Medium"; Why = "Audit policy changes can indicate attempts to reduce logging."; Risk = "Tampering with logging may be harder to detect." }
    )

    foreach ($item in $auditCommands) {
        $command = $item.Command
        $impact = if ($item.Contains("Impact")) { $item.Impact } else { "Low" }
        Invoke-SafeChange -ControlId $item.Id -Control "Audit Policy" -Severity $item.Severity -Action $command -WhyItMatters $item.Why -RiskIfNotApplied $item.Risk -OperationalImpact $impact -Recommendation "Enable success and failure auditing for $($item.Name), then confirm event volume is acceptable for the SIEM/log retention plan." -Rollback "Disable or tune this audit subcategory through auditpol or Group Policy." -ScriptBlock {
            cmd.exe /c $command | Out-Null
        }
    }
}
else {
    Add-Result -ControlId "WIN-HARDEN-AUDIT" -Control "Audit Policy" -Severity "High" -Action "Configure audit policy" -Status "Skipped" -Details "Skipped by parameter" -WhyItMatters "Audit policy provides investigation evidence for logon, account, process, and policy activity." -RiskIfNotApplied "Security investigations may lack important Windows event evidence." -OperationalImpact "Medium" -Recommendation "Confirm audit policy is centrally managed before skipping." -Rollback "Remove -SkipAuditPolicy on a future run."
}

$resultRows = @($Results.ToArray())
$backupRegistryBackups = if ($script:BackupManifest) { @(Get-ObjectValue -InputObject $script:BackupManifest -Name "RegistryBackups") } else { @() }
$backupCoverageNotes = if ($script:BackupManifest) { @(Get-ObjectValue -InputObject $script:BackupManifest -Name "CoverageNotes") } else { @() }
$report = [ordered]@{
    ComputerName = $env:COMPUTERNAME
    GeneratedAtUtc = (Get-Date).ToUniversalTime().ToString("o")
    Applied = [bool]$Apply
    BackupDirectory = if ($script:BackupManifest) { Get-ObjectValue -InputObject $script:BackupManifest -Name "BackupDirectory" } elseif ($Apply) { $BackupDirectory } else { $null }
    BackupManifestPath = if ($script:BackupManifestPath) { $script:BackupManifestPath } else { $null }
    BackupSummary = if ($script:BackupManifest) {
        [ordered]@{
            BackupMode                 = Get-ObjectValue -InputObject $script:BackupManifest -Name "BackupMode"
            SelectedControlIds         = @(Get-ObjectValue -InputObject $script:BackupManifest -Name "SelectedControlIds")
            RegistryBackupCount        = @($backupRegistryBackups | Where-Object { (Get-ObjectValue -InputObject $_ -Name "Status") -eq "Exported" }).Count
            MissingSourceBackupCount   = @($backupRegistryBackups | Where-Object { (Get-ObjectValue -InputObject $_ -Name "Status") -eq "SkippedMissingSource" }).Count
            CoverageNoteCount          = $backupCoverageNotes.Count
        }
    } else { $null }
    PlanPath = if ($script:PlanSelection) { Get-ObjectValue -InputObject $script:PlanSelection -Name "Path" } else { $null }
    PlanSelection = if ($script:PlanSelection) {
        [ordered]@{
            SourceAuditReport        = Get-ObjectValue -InputObject $script:PlanSelection -Name "SourceAuditReport"
            SourceAuditReportName    = Get-ObjectValue -InputObject $script:PlanSelection -Name "SourceAuditReportName"
            ComputerName             = Get-ObjectValue -InputObject $script:PlanSelection -Name "ComputerName"
            PlanSchemaVersion        = Get-ObjectValue -InputObject $script:PlanSelection -Name "PlanSchemaVersion"
            PlanItemCount            = Get-ObjectValue -InputObject $script:PlanSelection -Name "PlanItemCount"
            ApprovedPlanItemCount    = Get-ObjectValue -InputObject $script:PlanSelection -Name "ApprovedPlanItemCount"
            RunnablePlanItemCount    = Get-ObjectValue -InputObject $script:PlanSelection -Name "RunnablePlanItemCount"
            ApprovedControlIds       = @(Get-ObjectValue -InputObject $script:PlanSelection -Name "ApprovedControlIds")
            BlockedApprovedPlanItems = @(Get-ObjectValue -InputObject $script:PlanSelection -Name "BlockedApprovedPlanItems")
        }
    } else { $null }
    ExcludeControlId = @($ExcludeControlId)
    OnlyControlId = @($OnlyControlId)
    Summary = New-HardeningSummary -Rows $resultRows
    Results = $resultRows
}

New-ParentDirectory -Path $ReportPath
$report | ConvertTo-Json -Depth 6 | Out-File -FilePath $ReportPath -Encoding utf8

Write-Host "Windows hardening report written to: $ReportPath"
if ($script:BackupManifestPath) {
    Write-Host "Backup manifest written to: $script:BackupManifestPath"
}
if ($script:PlanSelection) {
    Write-Host "Plan mode: $(@(Get-ObjectValue -InputObject $script:PlanSelection -Name "ApprovedControlIds").Count) approved runnable controls selected."
}
if (-not $Apply) {
    Write-Host "Dry run complete. Run with -Apply to enforce the baseline."
}
