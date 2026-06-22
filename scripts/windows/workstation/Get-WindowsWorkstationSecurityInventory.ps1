<#
.SYNOPSIS
Collects Windows workstation security posture evidence.

.DESCRIPTION
Audits Microsoft Defender state, BitLocker fixed-volume protection, Windows
Firewall profiles, local users, Remote Assistance policy, LLMNR policy, and
PowerShell Script Block Logging policy. It writes JSON, CSV, and Markdown
reports and does not change endpoint configuration.

.PARAMETER OutputDirectory
Directory where windows-workstation-security.json,
windows-workstation-security-findings.csv, and
windows-workstation-security-review.md are written.

.PARAMETER Quiet
Suppress console summary.
#>

[CmdletBinding()]
param(
    [string]$OutputDirectory = ".\reports\windows-workstation-security-$env:COMPUTERNAME-$(Get-Date -Format 'yyyyMMdd-HHmmss')",
    [switch]$Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function New-Directory {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -Path $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
}

function Invoke-Safe {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$ScriptBlock,
        [AllowNull()][object]$Default = $null
    )
    try {
        & $ScriptBlock
    }
    catch {
        $Default
    }
}

function Get-RegistryValueSafe {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )
    Invoke-Safe -ScriptBlock {
        $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        $item.$Name
    } -Default $null
}

function New-WorkstationFinding {
    param(
        [Parameter(Mandatory = $true)][string]$FindingType,
        [Parameter(Mandatory = $true)][string]$Severity,
        [Parameter(Mandatory = $true)][string]$Title,
        [Parameter(Mandatory = $true)][string]$Evidence,
        [Parameter(Mandatory = $true)][string]$Recommendation,
        [AllowEmptyString()][string]$Name = ""
    )
    [pscustomobject][ordered]@{
        FindingType          = $FindingType
        Severity             = $Severity
        Name                 = $Name
        Title                = $Title
        Evidence             = $Evidence
        Recommendation       = $Recommendation
        RequiresOwnerReview  = $true
        SafeToAutoRemediate  = $false
    }
}

function Write-CsvReport {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [object[]]$Rows
    )
    $Rows | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
}

function Add-MarkdownLine {
    param(
        [Parameter(Mandatory = $true)][object]$Lines,
        [AllowEmptyString()][string]$Text = ""
    )
    $Lines.Add($Text) | Out-Null
}

function Escape-MarkdownCell {
    param([AllowNull()][object]$Value)
    return ("$Value" -replace "\r?\n", " " -replace "\|", "\|").Trim()
}

function Write-MarkdownReport {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][object]$Report
    )
    $lines = New-Object System.Collections.Generic.List[string]
    Add-MarkdownLine -Lines $lines -Text "# Windows Workstation Security Inventory"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "Generated at UTC: ``$($Report.GeneratedAtUtc)``"
    Add-MarkdownLine -Lines $lines -Text "Computer: ``$($Report.ComputerName)``"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "## Summary"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "- Defender real-time protection: $($Report.Summary.DefenderRealTimeProtectionEnabled)"
    Add-MarkdownLine -Lines $lines -Text "- BitLocker fixed volumes: $($Report.Summary.BitLockerFixedVolumeCount)"
    Add-MarkdownLine -Lines $lines -Text "- Unprotected fixed volumes: $($Report.Summary.BitLockerUnprotectedFixedVolumeCount)"
    Add-MarkdownLine -Lines $lines -Text "- Disabled firewall profiles: $($Report.Summary.DisabledFirewallProfileCount)"
    Add-MarkdownLine -Lines $lines -Text "- Finding count: $($Report.Summary.FindingCount)"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "## Findings"
    Add-MarkdownLine -Lines $lines
    if ($Report.Findings.Count -eq 0) {
        Add-MarkdownLine -Lines $lines -Text "- None identified."
    }
    else {
        Add-MarkdownLine -Lines $lines -Text "| Severity | Area | Finding | Recommendation |"
        Add-MarkdownLine -Lines $lines -Text "|---|---|---|---|"
        foreach ($finding in $Report.Findings) {
            Add-MarkdownLine -Lines $lines -Text "| $(Escape-MarkdownCell $finding.Severity) | $(Escape-MarkdownCell $finding.Name) | $(Escape-MarkdownCell $finding.Title) | $(Escape-MarkdownCell $finding.Recommendation) |"
        }
    }
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "## Safety Notes"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "- This script does not change Defender, BitLocker, firewall, local policy, or users."
    Add-MarkdownLine -Lines $lines -Text "- Endpoint hardening changes require owner review and approved change control."

    $lines | Out-File -FilePath $Path -Encoding utf8
}

New-Directory -Path $OutputDirectory
$resolvedOutputDirectory = (Resolve-Path -Path $OutputDirectory).Path
$jsonPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "windows-workstation-security.json"
$csvPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "windows-workstation-security-findings.csv"
$markdownPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "windows-workstation-security-review.md"
$generatedAtUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$findings = New-Object System.Collections.Generic.List[object]
$reportErrors = New-Object System.Collections.Generic.List[string]

$defender = Invoke-Safe -ScriptBlock {
    $status = Get-MpComputerStatus -ErrorAction Stop
    [pscustomobject][ordered]@{
        AMServiceEnabled                = [bool]$status.AMServiceEnabled
        AntivirusEnabled                = [bool]$status.AntivirusEnabled
        AntispywareEnabled              = [bool]$status.AntispywareEnabled
        RealTimeProtectionEnabled       = [bool]$status.RealTimeProtectionEnabled
        BehaviorMonitorEnabled          = [bool]$status.BehaviorMonitorEnabled
        IoavProtectionEnabled           = [bool]$status.IoavProtectionEnabled
        AntivirusSignatureLastUpdated   = "$($status.AntivirusSignatureLastUpdated)"
        AntispywareSignatureLastUpdated = "$($status.AntispywareSignatureLastUpdated)"
    }
} -Default $null
if (-not $defender) {
    $reportErrors.Add("Microsoft Defender status could not be collected. Get-MpComputerStatus may be unavailable.") | Out-Null
}

$bitLockerVolumes = @(Invoke-Safe -ScriptBlock {
        Get-BitLockerVolume -ErrorAction Stop | ForEach-Object {
            [pscustomobject][ordered]@{
                MountPoint       = "$($_.MountPoint)"
                VolumeType       = "$($_.VolumeType)"
                ProtectionStatus = "$($_.ProtectionStatus)"
                VolumeStatus     = "$($_.VolumeStatus)"
                EncryptionMethod = "$($_.EncryptionMethod)"
                LockStatus       = "$($_.LockStatus)"
            }
        }
    } -Default @())
if ($bitLockerVolumes.Count -eq 0) {
    $reportErrors.Add("BitLocker volume status could not be collected or no volumes were returned.") | Out-Null
}

$firewallProfiles = @(Invoke-Safe -ScriptBlock {
        Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object {
            [pscustomobject][ordered]@{
                Name                 = "$($_.Name)"
                Enabled              = [bool]$_.Enabled
                DefaultInboundAction = "$($_.DefaultInboundAction)"
                DefaultOutboundAction = "$($_.DefaultOutboundAction)"
            }
        }
    } -Default @())

$localUsers = @(Invoke-Safe -ScriptBlock {
        Get-LocalUser -ErrorAction Stop | ForEach-Object {
            [pscustomobject][ordered]@{
                Name             = "$($_.Name)"
                Enabled          = [bool]$_.Enabled
                LastLogon        = "$($_.LastLogon)"
                PasswordRequired = $_.PasswordRequired
                PasswordLastSet  = "$($_.PasswordLastSet)"
            }
        }
    } -Default @())

$remoteAssistance = [pscustomobject][ordered]@{
    fAllowToGetHelp = Get-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp"
}
$llmnrPolicy = [pscustomobject][ordered]@{
    EnableMulticast = Get-RegistryValueSafe -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast"
}
$powerShellLogging = [pscustomobject][ordered]@{
    EnableScriptBlockLogging = Get-RegistryValueSafe -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging"
}

if ($defender) {
    if (-not $defender.AntivirusEnabled -or -not $defender.AMServiceEnabled) {
        $findings.Add((New-WorkstationFinding -FindingType "DefenderDisabled" -Severity "High" -Name "Defender" -Title "Microsoft Defender antivirus is not fully enabled" -Evidence "AMServiceEnabled=$($defender.AMServiceEnabled); AntivirusEnabled=$($defender.AntivirusEnabled)." -Recommendation "Confirm approved endpoint protection and restore Defender or equivalent controls through approved change control.")) | Out-Null
    }
    if (-not $defender.RealTimeProtectionEnabled) {
        $findings.Add((New-WorkstationFinding -FindingType "DefenderRealTimeProtectionDisabled" -Severity "High" -Name "Defender" -Title "Defender real-time protection is disabled" -Evidence "RealTimeProtectionEnabled=False." -Recommendation "Re-enable real-time protection unless an approved endpoint security exception exists.")) | Out-Null
    }
}

$fixedVolumes = @($bitLockerVolumes | Where-Object { $_.VolumeType -eq "OperatingSystem" -or $_.VolumeType -eq "FixedData" })
foreach ($volume in $fixedVolumes) {
    if ($volume.ProtectionStatus -ne "On" -or $volume.VolumeStatus -ne "FullyEncrypted") {
        $findings.Add((New-WorkstationFinding -FindingType "BitLockerVolumeNotProtected" -Severity "High" -Name $volume.MountPoint -Title "Fixed volume is not fully protected by BitLocker" -Evidence "$($volume.MountPoint) ProtectionStatus=$($volume.ProtectionStatus); VolumeStatus=$($volume.VolumeStatus)." -Recommendation "Confirm encryption policy and enable BitLocker only through approved endpoint management workflow.")) | Out-Null
    }
}

foreach ($profile in $firewallProfiles) {
    if (-not $profile.Enabled) {
        $severity = if ($profile.Name -eq "Public") { "High" } else { "Medium" }
        $findings.Add((New-WorkstationFinding -FindingType "FirewallProfileDisabled" -Severity $severity -Name $profile.Name -Title "Windows Firewall profile is disabled" -Evidence "$($profile.Name) profile Enabled=False." -Recommendation "Enable the firewall profile after validating endpoint management and allow rules.")) | Out-Null
    }
}

if ($remoteAssistance.fAllowToGetHelp -eq 1) {
    $findings.Add((New-WorkstationFinding -FindingType "RemoteAssistanceEnabled" -Severity "Medium" -Name "Remote Assistance" -Title "Remote Assistance is enabled" -Evidence "fAllowToGetHelp=1." -Recommendation "Confirm support requirement and restrict/disable Remote Assistance through approved policy if not needed.")) | Out-Null
}
if ($null -eq $llmnrPolicy.EnableMulticast -or $llmnrPolicy.EnableMulticast -ne 0) {
    $findings.Add((New-WorkstationFinding -FindingType "LlmnrNotDisabledByPolicy" -Severity "Medium" -Name "LLMNR" -Title "LLMNR is not disabled by policy" -Evidence "EnableMulticast=$($llmnrPolicy.EnableMulticast)." -Recommendation "Disable LLMNR via approved policy after validating name-resolution dependencies.")) | Out-Null
}
if ($powerShellLogging.EnableScriptBlockLogging -ne 1) {
    $findings.Add((New-WorkstationFinding -FindingType "PowerShellScriptBlockLoggingNotEnabled" -Severity "Medium" -Name "PowerShell" -Title "PowerShell Script Block Logging is not enabled by policy" -Evidence "EnableScriptBlockLogging=$($powerShellLogging.EnableScriptBlockLogging)." -Recommendation "Enable Script Block Logging through approved endpoint policy and confirm log forwarding capacity.")) | Out-Null
}

$severityCounts = [ordered]@{
    Critical = @($findings | Where-Object { $_.Severity -eq "Critical" }).Count
    High     = @($findings | Where-Object { $_.Severity -eq "High" }).Count
    Medium   = @($findings | Where-Object { $_.Severity -eq "Medium" }).Count
    Low      = @($findings | Where-Object { $_.Severity -eq "Low" }).Count
    Info     = @($findings | Where-Object { $_.Severity -eq "Info" }).Count
}

$report = [pscustomobject][ordered]@{
    ToolName        = "Get-WindowsWorkstationSecurityInventory"
    ReportType      = "windows-workstation-security-inventory"
    GeneratedAtUtc  = $generatedAtUtc
    ComputerName    = $env:COMPUTERNAME
    Summary         = [ordered]@{
        DefenderRealTimeProtectionEnabled = if ($defender) { [bool]$defender.RealTimeProtectionEnabled } else { $false }
        BitLockerFixedVolumeCount         = $fixedVolumes.Count
        BitLockerUnprotectedFixedVolumeCount = @($fixedVolumes | Where-Object { $_.ProtectionStatus -ne "On" -or $_.VolumeStatus -ne "FullyEncrypted" }).Count
        FirewallProfileCount              = $firewallProfiles.Count
        DisabledFirewallProfileCount      = @($firewallProfiles | Where-Object { -not $_.Enabled }).Count
        LocalUserCount                     = $localUsers.Count
        EnabledLocalUserCount              = @($localUsers | Where-Object { $_.Enabled }).Count
        FindingCount                       = $findings.Count
        SeverityCounts                     = $severityCounts
    }
    DefenderStatus     = $defender
    BitLockerVolumes   = @($bitLockerVolumes)
    FirewallProfiles   = @($firewallProfiles)
    LocalUsers         = @($localUsers)
    RemoteAssistance   = $remoteAssistance
    LlmnrPolicy        = $llmnrPolicy
    PowerShellLogging  = $powerShellLogging
    Findings           = @($findings.ToArray())
    ReportErrors       = @($reportErrors.ToArray())
    Notes              = @(
        "This report is audit-only and does not change workstation configuration.",
        "Endpoint hardening changes require owner review and approved change control."
    )
}

$report | ConvertTo-Json -Depth 8 | Out-File -FilePath $jsonPath -Encoding utf8
Write-CsvReport -Path $csvPath -Rows @($findings.ToArray())
Write-MarkdownReport -Path $markdownPath -Report $report

if (-not $Quiet) {
    Write-Host "Windows workstation security report written to: $jsonPath"
    Write-Host "Findings: $($findings.Count)"
}
