<#
.SYNOPSIS
Collects audit-only Windows backup readiness evidence.

.DESCRIPTION
Collects local backup readiness signals without deleting, modifying, restoring,
or reading backup contents. The script checks Windows Server Backup feature
visibility where available, backup-related service names, recent backup-related
event log metadata, Volume Shadow Copy / restore point metadata, and optional
expected backup path timestamps.

The script does not change backup software, backup jobs, backup storage,
services, event logs, shadow copies, restore points, or local configuration.

Service presence is never treated as proof of healthy backups. Missing or
limited evidence is reported as an evidence gap.

.PARAMETER ExpectedBackupPaths
Optional backup target paths to verify with Test-Path/Get-Item only. Directory
or file contents are not enumerated or read.

.PARAMETER ExpectedBackupSoftware
Optional expected backup software names to look for in visible service names or
display names. Absence is reported as a configuration review item.

.PARAMETER WarningAgeDays
Age threshold for stale backup evidence. The default is 14 days.

.PARAMETER CriticalAgeDays
Age threshold for critical stale backup evidence. The default is 30 days.

.PARAMETER OutputDirectory
Directory where backup-readiness.json, backup-readiness-findings.csv, and
backup-readiness-review.md are written.

.PARAMETER Quiet
Suppress console summary output.

.EXAMPLE
.\scripts\windows\backup\Get-WindowsBackupReadinessAudit.ps1

Run a local audit-only backup readiness collection.

.EXAMPLE
.\scripts\windows\backup\Get-WindowsBackupReadinessAudit.ps1 -ExpectedBackupPaths "E:\Backups" -ExpectedBackupSoftware "Windows Server Backup" -OutputDirectory .\reports\backup

Check a fictional expected backup path and expected software signal without
reading backup contents.
#>

[CmdletBinding()]
param(
    [string[]]$ExpectedBackupPaths = @(),
    [string[]]$ExpectedBackupSoftware = @(),
    [int]$WarningAgeDays = 14,
    [int]$CriticalAgeDays = 30,
    [string]$OutputDirectory = ".\reports\backup-readiness-$env:COMPUTERNAME-$(Get-Date -Format 'yyyyMMdd-HHmmss')",
    [switch]$Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function New-Directory {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
}

function Invoke-Safe {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$ScriptBlock,
        [AllowNull()][object]$Default = $null,
        [string]$ErrorMessage = ""
    )
    try {
        & $ScriptBlock
    }
    catch {
        if ($ErrorMessage) {
            $script:ReportErrors.Add("$ErrorMessage $($_.Exception.Message)") | Out-Null
        }
        $Default
    }
}

function Get-UtcTimestamp {
    return (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
}

function Convert-DateToUtcString {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value -or "$Value" -eq "") {
        return ""
    }
    if ($Value -is [datetime]) {
        return $Value.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    }
    try {
        return ([System.Management.ManagementDateTimeConverter]::ToDateTime("$Value")).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    }
    catch {
        try {
            return ([datetime]::Parse("$Value")).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        }
        catch {
            return "$Value"
        }
    }
}

function Test-BackupTextMatch {
    param([AllowNull()][object]$Value)
    $text = "$Value".ToLowerInvariant()
    foreach ($pattern in @("backup", "wbengine", "vss", "shadow", "snapshot", "veeam", "rubrik", "commvault", "netbackup", "arcserve", "acronis", "datto", "dpm")) {
        if ($text -match [regex]::Escape($pattern)) {
            return $true
        }
    }
    return $false
}

function New-BackupFinding {
    param(
        [Parameter(Mandatory = $true)][string]$FindingType,
        [Parameter(Mandatory = $true)][string]$Severity,
        [Parameter(Mandatory = $true)][string]$Title,
        [Parameter(Mandatory = $true)][string]$AffectedObject,
        [Parameter(Mandatory = $true)][string]$Evidence,
        [Parameter(Mandatory = $true)][string]$Recommendation,
        [string]$BackupEvidenceSource = "",
        [string]$BackupEvidenceConfidence = "low",
        [string]$LastBackupEvidenceTimestamp = "",
        [string]$RestoreTestEvidenceStatus = "not_provided",
        [string]$MonitoringEvidenceStatus = "not_provided",
        [string[]]$Limitations = @()
    )
    [pscustomobject][ordered]@{
        FindingType                 = $FindingType
        Severity                    = $Severity
        Title                       = $Title
        AffectedObject              = $AffectedObject
        Evidence                    = $Evidence
        Recommendation              = $Recommendation
        BackupEvidenceSource        = $BackupEvidenceSource
        BackupEvidenceConfidence    = $BackupEvidenceConfidence
        LastBackupEvidenceTimestamp = $LastBackupEvidenceTimestamp
        RestoreTestEvidenceStatus   = $RestoreTestEvidenceStatus
        MonitoringEvidenceStatus    = $MonitoringEvidenceStatus
        Limitations                 = @($Limitations)
        RequiresOwnerReview         = $true
        SafeToAutoRemediate         = $false
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
    Add-MarkdownLine -Lines $lines -Text "# Windows Backup Readiness Audit"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "Generated at UTC: ``$($Report.GeneratedAtUtc)``"
    Add-MarkdownLine -Lines $lines -Text "Computer: ``$($Report.ComputerName)``"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "## Summary"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "- Backup health status: $($Report.Summary.BackupHealthStatus)"
    Add-MarkdownLine -Lines $lines -Text "- Backup-related services visible: $($Report.Summary.BackupServiceCount)"
    Add-MarkdownLine -Lines $lines -Text "- Recent backup event signals: $($Report.Summary.RecentBackupEventCount)"
    Add-MarkdownLine -Lines $lines -Text "- Expected backup paths checked: $($Report.Summary.ExpectedBackupPathCount)"
    Add-MarkdownLine -Lines $lines -Text "- Finding count: $($Report.Summary.FindingCount)"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "## Findings"
    Add-MarkdownLine -Lines $lines
    if ($Report.Findings.Count -eq 0) {
        Add-MarkdownLine -Lines $lines -Text "- None identified."
    }
    else {
        Add-MarkdownLine -Lines $lines -Text "| Severity | Object | Finding | Recommendation |"
        Add-MarkdownLine -Lines $lines -Text "|---|---|---|---|"
        foreach ($finding in $Report.Findings) {
            Add-MarkdownLine -Lines $lines -Text "| $(Escape-MarkdownCell $finding.Severity) | $(Escape-MarkdownCell $finding.AffectedObject) | $(Escape-MarkdownCell $finding.Title) | $(Escape-MarkdownCell $finding.Recommendation) |"
        }
    }
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "## Safety Notes"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "- This script does not delete, modify, restore, or read backup contents."
    Add-MarkdownLine -Lines $lines -Text "- Service presence is not treated as proof of successful or recoverable backups."
    Add-MarkdownLine -Lines $lines -Text "- Restore testing and backup monitoring evidence should be validated with owners."

    $lines | Out-File -FilePath $Path -Encoding utf8
}

if ($WarningAgeDays -lt 1) {
    throw "-WarningAgeDays must be at least 1."
}
if ($CriticalAgeDays -lt $WarningAgeDays) {
    throw "-CriticalAgeDays must be greater than or equal to -WarningAgeDays."
}

New-Directory -Path $OutputDirectory
$resolvedOutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path
$jsonPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "backup-readiness.json"
$csvPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "backup-readiness-findings.csv"
$markdownPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "backup-readiness-review.md"
$generatedAtUtc = Get-UtcTimestamp
$script:ReportErrors = New-Object System.Collections.Generic.List[string]
$findings = New-Object System.Collections.Generic.List[object]
$limitations = New-Object System.Collections.Generic.List[string]

$backupFeature = Invoke-Safe -ScriptBlock {
    Get-WindowsFeature -Name Windows-Server-Backup -ErrorAction Stop | Select-Object -First 1
} -Default $null -ErrorMessage "Windows Server Backup feature inventory unavailable:"

$backupFeatureEvidence = [ordered]@{
    EvidenceAvailable = $false
    Name              = "Windows-Server-Backup"
    DisplayName       = "Windows Server Backup"
    Installed         = $null
    InstallState      = ""
}
if ($null -ne $backupFeature) {
    $backupFeatureEvidence.EvidenceAvailable = $true
    $backupFeatureEvidence.Name = "$($backupFeature.Name)"
    $backupFeatureEvidence.DisplayName = "$($backupFeature.DisplayName)"
    $backupFeatureEvidence.Installed = [bool]$backupFeature.Installed
    $backupFeatureEvidence.InstallState = "$($backupFeature.InstallState)"
}
else {
    $limitations.Add("Windows Server Backup feature visibility may be unavailable on non-server editions or limited PowerShell contexts.") | Out-Null
}

$backupServices = @(Invoke-Safe -ScriptBlock {
    Get-CimInstance -ClassName Win32_Service -ErrorAction Stop |
        Where-Object { Test-BackupTextMatch "$($_.Name) $($_.DisplayName)" } |
        Sort-Object Name |
        ForEach-Object {
            [pscustomobject][ordered]@{
                Name        = "$($_.Name)"
                DisplayName = "$($_.DisplayName)"
                State       = "$($_.State)"
                StartMode   = "$($_.StartMode)"
            }
        }
} -Default @() -ErrorMessage "Backup-related service inventory unavailable:")

$cutoff = (Get-Date).AddDays(-1 * $CriticalAgeDays)
$backupEvents = New-Object System.Collections.Generic.List[object]
foreach ($providerName in @("Microsoft-Windows-Backup", "Backup", "VSS")) {
    $events = @(Invoke-Safe -ScriptBlock {
        Get-WinEvent -FilterHashtable @{ ProviderName = $providerName; StartTime = $cutoff } -MaxEvents 40 -ErrorAction Stop |
            ForEach-Object {
                [pscustomobject][ordered]@{
                    TimeCreated      = Convert-DateToUtcString $_.TimeCreated
                    Id               = $_.Id
                    ProviderName     = "$($_.ProviderName)"
                    LogName          = "$($_.LogName)"
                    LevelDisplayName = "$($_.LevelDisplayName)"
                }
            }
    } -Default @())
    foreach ($event in $events) {
        $backupEvents.Add($event) | Out-Null
    }
}

$shadowCopies = @(Invoke-Safe -ScriptBlock {
    Get-CimInstance -ClassName Win32_ShadowCopy -ErrorAction Stop |
        Sort-Object InstallDate -Descending |
        Select-Object -First 20 |
        ForEach-Object {
            [pscustomobject][ordered]@{
                Id         = "$($_.ID)"
                InstallUtc = Convert-DateToUtcString $_.InstallDate
            }
        }
} -Default @() -ErrorMessage "Volume Shadow Copy metadata unavailable:")

$restorePoints = @(Invoke-Safe -ScriptBlock {
    Get-ComputerRestorePoint -ErrorAction Stop |
        Sort-Object CreationTime -Descending |
        Select-Object -First 20 |
        ForEach-Object {
            [pscustomobject][ordered]@{
                SequenceNumber = $_.SequenceNumber
                CreationUtc    = Convert-DateToUtcString $_.CreationTime
                RestorePointType = "$($_.RestorePointType)"
            }
        }
} -Default @() -ErrorMessage "System restore point metadata unavailable:")

$expectedPathResults = New-Object System.Collections.Generic.List[object]
$latestEvidenceUtc = ""
$latestEvidenceDate = $null

function Update-LatestEvidenceDate {
    param([AllowNull()][datetime]$Value)
    if ($null -eq $Value) {
        return
    }
    if ($null -eq $script:LatestEvidenceDate -or $Value -gt $script:LatestEvidenceDate) {
        $script:LatestEvidenceDate = $Value
    }
}

$script:LatestEvidenceDate = $null

foreach ($path in @($ExpectedBackupPaths | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
    $result = [ordered]@{
        Path             = "$path"
        Exists           = $false
        IsDirectory      = $false
        LastWriteTimeUtc = ""
        AgeDays          = $null
        Status           = "missing"
        Limitation       = "Only the expected path metadata was checked. Backup contents were not enumerated or read."
    }
    if (Test-Path -LiteralPath $path) {
        $item = Get-Item -LiteralPath $path -Force
        $ageDays = [math]::Round(((Get-Date).ToUniversalTime() - $item.LastWriteTimeUtc).TotalDays, 1)
        $result.Exists = $true
        $result.IsDirectory = [bool]$item.PSIsContainer
        $result.LastWriteTimeUtc = $item.LastWriteTimeUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")
        $result.AgeDays = $ageDays
        $result.Status = if ($ageDays -ge $WarningAgeDays) { "stale" } else { "recent" }
        Update-LatestEvidenceDate -Value $item.LastWriteTimeUtc
    }
    $expectedPathResults.Add([pscustomobject]$result) | Out-Null
}

foreach ($event in $backupEvents) {
    try {
        Update-LatestEvidenceDate -Value ([datetime]::Parse($event.TimeCreated))
    }
    catch {
    }
}
foreach ($copy in $shadowCopies) {
    try {
        if ($copy.InstallUtc) {
            Update-LatestEvidenceDate -Value ([datetime]::Parse($copy.InstallUtc))
        }
    }
    catch {
    }
}

if ($null -ne $script:LatestEvidenceDate) {
    $latestEvidenceUtc = $script:LatestEvidenceDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
}

foreach ($pathResult in $expectedPathResults) {
    if (-not $pathResult.Exists) {
        $findings.Add((New-BackupFinding -FindingType "ExpectedBackupPathMissing" -Severity "High" -Title "Expected backup path is missing" -AffectedObject $pathResult.Path -Evidence "The expected backup path was not present. Contents were not enumerated." -Recommendation "Confirm the expected backup target, mount state, permissions, and backup job ownership." -BackupEvidenceSource "expected_backup_path" -BackupEvidenceConfidence "high" -Limitations @($pathResult.Limitation))) | Out-Null
    }
    elseif ($pathResult.AgeDays -ge $WarningAgeDays) {
        $title = if ($pathResult.AgeDays -ge $CriticalAgeDays) { "Expected backup path is critically stale" } else { "Expected backup path is stale" }
        $findings.Add((New-BackupFinding -FindingType "ExpectedBackupPathStale" -Severity "High" -Title $title -AffectedObject $pathResult.Path -Evidence "LastWriteTimeUtc=$($pathResult.LastWriteTimeUtc); AgeDays=$($pathResult.AgeDays); WarningAgeDays=$WarningAgeDays; CriticalAgeDays=$CriticalAgeDays." -Recommendation "Validate the backup job, schedule, storage target, and monitoring alerts before relying on this evidence." -BackupEvidenceSource "expected_backup_path" -BackupEvidenceConfidence "medium" -LastBackupEvidenceTimestamp $pathResult.LastWriteTimeUtc -Limitations @($pathResult.Limitation))) | Out-Null
    }
}

if ($backupServices.Count -gt 0) {
    $serviceNames = (@($backupServices | Select-Object -ExpandProperty Name) -join ", ")
    $findings.Add((New-BackupFinding -FindingType "BackupServicePresentHealthUnverified" -Severity "Info" -Title "Backup-related service is present but health is unverified" -AffectedObject $env:COMPUTERNAME -Evidence "Visible backup-related services: $serviceNames. Service presence does not prove successful or recoverable backups." -Recommendation "Review backup job history, alerts, recent successful backup evidence, and restore test evidence with the system owner." -BackupEvidenceSource "service_inventory" -BackupEvidenceConfidence "low" -LastBackupEvidenceTimestamp $latestEvidenceUtc -Limitations @("Service inventory does not prove backup success, restoreability, or monitoring coverage."))) | Out-Null
}

foreach ($expectedSoftware in @($ExpectedBackupSoftware | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
    $matched = $false
    foreach ($service in $backupServices) {
        $serviceText = "$($service.Name) $($service.DisplayName)".ToLowerInvariant()
        if ($serviceText.Contains($expectedSoftware.ToLowerInvariant())) {
            $matched = $true
        }
    }
    if (-not $matched) {
        $findings.Add((New-BackupFinding -FindingType "BackupConfigurationReviewRequired" -Severity "Medium" -Title "Expected backup software was not visible in service inventory" -AffectedObject $expectedSoftware -Evidence "ExpectedBackupSoftware=$expectedSoftware was not matched in visible backup-related services." -Recommendation "Confirm whether the backup agent is installed, renamed, service-based, or managed externally." -BackupEvidenceSource "service_inventory" -BackupEvidenceConfidence "low" -Limitations @("Some backup tools may not expose a service name that matches the expected software label."))) | Out-Null
    }
}

$recentCutoff = (Get-Date).AddDays(-1 * $WarningAgeDays)
$hasRecentBackupEvidence = $false
if ($null -ne $script:LatestEvidenceDate -and $script:LatestEvidenceDate -ge $recentCutoff) {
    $hasRecentBackupEvidence = $true
}
if (-not $hasRecentBackupEvidence) {
    $severity = if ($ExpectedBackupPaths.Count -gt 0) { "High" } else { "Medium" }
    $findings.Add((New-BackupFinding -FindingType "NoRecentBackupEvidenceFound" -Severity $severity -Title "No recent backup evidence was found" -AffectedObject $env:COMPUTERNAME -Evidence "No backup event, VSS/restore point, or expected path timestamp was observed within $WarningAgeDays day(s)." -Recommendation "Collect backup job history or storage target evidence and confirm the most recent successful backup with the owner." -BackupEvidenceSource "collector_summary" -BackupEvidenceConfidence "low" -LastBackupEvidenceTimestamp $latestEvidenceUtc -Limitations @("Absence of local evidence does not prove backups do not exist; centralized backup platforms may hold authoritative job history."))) | Out-Null
}

if ($backupEvents.Count -eq 0 -and $expectedPathResults.Count -eq 0 -and $shadowCopies.Count -eq 0 -and $restorePoints.Count -eq 0) {
    $findings.Add((New-BackupFinding -FindingType "BackupEvidenceUnavailable" -Severity "Info" -Title "Backup readiness evidence is unavailable or incomplete" -AffectedObject $env:COMPUTERNAME -Evidence "No local backup event, expected path, shadow copy, or restore point metadata was available to the collector." -Recommendation "Provide approved backup job history, monitoring evidence, or expected backup path metadata for review." -BackupEvidenceSource "collector_summary" -BackupEvidenceConfidence "low" -Limitations @($limitations.ToArray()))) | Out-Null
}

$findings.Add((New-BackupFinding -FindingType "RestoreTestEvidenceMissing" -Severity "Medium" -Title "Restore test evidence was not provided" -AffectedObject $env:COMPUTERNAME -Evidence "This collector does not run restore operations and did not receive separate restore test evidence." -Recommendation "Confirm the date, scope, and result of the latest approved restore test." -BackupEvidenceSource "governance_review" -BackupEvidenceConfidence "low" -LastBackupEvidenceTimestamp $latestEvidenceUtc -RestoreTestEvidenceStatus "missing" -Limitations @("Restore readiness cannot be proven without a documented restore test."))) | Out-Null

$findings.Add((New-BackupFinding -FindingType "BackupMonitoringEvidenceMissing" -Severity "Medium" -Title "Backup monitoring evidence was not provided" -AffectedObject $env:COMPUTERNAME -Evidence "No backup monitoring alert or success/failure notification evidence was collected." -Recommendation "Confirm backup monitoring ownership, alert routing, and failure escalation procedures." -BackupEvidenceSource "governance_review" -BackupEvidenceConfidence "low" -LastBackupEvidenceTimestamp $latestEvidenceUtc -MonitoringEvidenceStatus "missing" -Limitations @("Monitoring coverage should be validated in the backup or monitoring platform."))) | Out-Null

$severityCounts = [ordered]@{
    Critical = @($findings | Where-Object { $_.Severity -eq "Critical" }).Count
    High     = @($findings | Where-Object { $_.Severity -eq "High" }).Count
    Medium   = @($findings | Where-Object { $_.Severity -eq "Medium" }).Count
    Low      = @($findings | Where-Object { $_.Severity -eq "Low" }).Count
    Info     = @($findings | Where-Object { $_.Severity -eq "Info" }).Count
}

$report = [pscustomobject][ordered]@{
    ToolName              = "Get-WindowsBackupReadinessAudit"
    ReportType            = "backup-readiness"
    Platform              = "windows"
    GeneratedAtUtc        = $generatedAtUtc
    ComputerName          = $env:COMPUTERNAME
    WarningAgeDays        = $WarningAgeDays
    CriticalAgeDays       = $CriticalAgeDays
    Summary               = [ordered]@{
        BackupHealthStatus          = "Unverified"
        BackupFeatureEvidence       = $backupFeatureEvidence
        BackupServiceCount          = $backupServices.Count
        RecentBackupEventCount      = @($backupEvents | Where-Object { $_.TimeCreated -and ([datetime]::Parse($_.TimeCreated)) -ge $recentCutoff }).Count
        BackupEventSignalCount      = $backupEvents.Count
        ShadowCopyCount             = $shadowCopies.Count
        RestorePointCount           = $restorePoints.Count
        ExpectedBackupPathCount     = $expectedPathResults.Count
        MissingExpectedPathCount    = @($expectedPathResults | Where-Object { -not $_.Exists }).Count
        StaleExpectedPathCount      = @($expectedPathResults | Where-Object { $_.Exists -and $_.AgeDays -ge $WarningAgeDays }).Count
        LastBackupEvidenceTimestamp = $latestEvidenceUtc
        RestoreTestEvidenceStatus   = "missing"
        MonitoringEvidenceStatus    = "missing"
        FindingCount                = $findings.Count
        SeverityCounts              = $severityCounts
    }
    BackupEvidence        = [ordered]@{
        Feature              = $backupFeatureEvidence
        Services             = @($backupServices)
        Events               = @($backupEvents.ToArray())
        ShadowCopies         = @($shadowCopies)
        RestorePoints        = @($restorePoints)
        ExpectedBackupPaths  = @($expectedPathResults.ToArray())
        ExpectedSoftware     = @($ExpectedBackupSoftware)
    }
    Findings              = @($findings.ToArray())
    ReportErrors          = @($script:ReportErrors.ToArray())
    Limitations           = @($limitations.ToArray() + @(
        "This collector does not read backup contents.",
        "This collector does not run restore operations.",
        "Local service or event evidence may not include centralized backup platform status."
    ))
    Notes                 = @(
        "Audit-only backup readiness evidence. No backup data is deleted, modified, restored, or read.",
        "Service presence is not proof of healthy, successful, or recoverable backups.",
        "Owner review is required before relying on any backup readiness conclusion."
    )
}

$report | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding utf8
Write-CsvReport -Path $csvPath -Rows @($findings.ToArray())
Write-MarkdownReport -Path $markdownPath -Report $report

if (-not $Quiet) {
    Write-Host "Windows backup readiness report written to: $jsonPath"
    Write-Host "Backup health status: Unverified"
    Write-Host "Findings: $($findings.Count)"
}
