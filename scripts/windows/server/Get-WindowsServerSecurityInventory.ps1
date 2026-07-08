<#
.SYNOPSIS
Collects Windows Server security inventory evidence.

.DESCRIPTION
Audits installed server roles where available, services, scheduled tasks, SMB
shares, and SMB share access. It writes JSON, CSV, and Markdown reports and
does not change services, tasks, roles, shares, or permissions.

.PARAMETER OutputDirectory
Directory where windows-server-security.json,
windows-server-security-findings.csv, and windows-server-security-review.md are
written.

.PARAMETER Quiet
Suppress console summary.
#>

[CmdletBinding()]
param(
    [string]$OutputDirectory = ".\reports\windows-server-security-$env:COMPUTERNAME-$(Get-Date -Format 'yyyyMMdd-HHmmss')",
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

function Test-ManagedServiceAccount {
    param([AllowNull()][object]$Value)
    return "$Value" -match "\$$"
}

function Test-ServiceAccountNeedsReview {
    param([AllowNull()][object]$Value)
    $text = "$Value"
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $false
    }
    if ($text -in @("LocalSystem", "NT AUTHORITY\LocalService", "NT AUTHORITY\NetworkService")) {
        return $false
    }
    if ($text -match "^(LocalService|NetworkService)$") {
        return $false
    }
    return $true
}

function Get-ServiceCommandExecutablePath {
    param([AllowNull()][object]$Value)
    $text = "$Value".Trim()
    if ([string]::IsNullOrWhiteSpace($text)) {
        return ""
    }
    if ($text.StartsWith('"')) {
        return ""
    }
    $match = [regex]::Match($text, "\.exe\b", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if (-not $match.Success) {
        return ""
    }
    return $text.Substring(0, $match.Index + $match.Length).Trim()
}

function Test-UnquotedServicePath {
    param([AllowNull()][object]$Value)
    $text = "$Value".Trim()
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $false
    }
    if ($text.StartsWith('"')) {
        return $false
    }
    $executablePath = Get-ServiceCommandExecutablePath -Value $text
    if ([string]::IsNullOrWhiteSpace($executablePath)) {
        return $false
    }
    return ($executablePath -match "\s")
}

function Test-BroadPrincipal {
    param([AllowNull()][object]$Value)
    $text = "$Value"
    return $text -match "^(Everyone|BUILTIN\\Users|NT AUTHORITY\\Authenticated Users|Authenticated Users|Users)$"
}

function New-ServerFinding {
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
    Add-MarkdownLine -Lines $lines -Text "# Windows Server Security Inventory"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "Generated at UTC: ``$($Report.GeneratedAtUtc)``"
    Add-MarkdownLine -Lines $lines -Text "Computer: ``$($Report.ComputerName)``"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "## Summary"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "- Installed roles/features: $($Report.Summary.InstalledFeatureCount)"
    Add-MarkdownLine -Lines $lines -Text "- Services: $($Report.Summary.ServiceCount)"
    Add-MarkdownLine -Lines $lines -Text "- Domain or custom service accounts: $($Report.Summary.CustomServiceAccountCount)"
    Add-MarkdownLine -Lines $lines -Text "- Scheduled tasks: $($Report.Summary.ScheduledTaskCount)"
    Add-MarkdownLine -Lines $lines -Text "- SMB shares: $($Report.Summary.SmbShareCount)"
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
            Add-MarkdownLine -Lines $lines -Text "| $(Escape-MarkdownCell $finding.Severity) | $(Escape-MarkdownCell $finding.Name) | $(Escape-MarkdownCell $finding.Title) | $(Escape-MarkdownCell $finding.Recommendation) |"
        }
    }
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "## Safety Notes"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "- This script does not change services, tasks, roles, shares, or ACLs."
    Add-MarkdownLine -Lines $lines -Text "- Service, task, and share changes require owner review and approved change control."

    $lines | Out-File -FilePath $Path -Encoding utf8
}

New-Directory -Path $OutputDirectory
$resolvedOutputDirectory = (Resolve-Path -Path $OutputDirectory).Path
$jsonPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "windows-server-security.json"
$csvPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "windows-server-security-findings.csv"
$markdownPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "windows-server-security-review.md"
$generatedAtUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$findings = New-Object System.Collections.Generic.List[object]
$reportErrors = New-Object System.Collections.Generic.List[string]

$features = @(Invoke-Safe -ScriptBlock {
        Get-WindowsFeature -ErrorAction Stop |
            Where-Object { $_.Installed } |
            ForEach-Object {
                [pscustomobject][ordered]@{
                    Name        = "$($_.Name)"
                    DisplayName = "$($_.DisplayName)"
                    FeatureType = "$($_.FeatureType)"
                    Path        = "$($_.Path)"
                }
            }
    } -Default @())
if ($features.Count -eq 0) {
    $reportErrors.Add("No WindowsFeature inventory was collected. The ServerManager module may be unavailable.") | Out-Null
}

$services = @(Invoke-Safe -ScriptBlock {
        Get-CimInstance -ClassName Win32_Service -ErrorAction Stop | ForEach-Object {
            [pscustomobject][ordered]@{
                Name        = "$($_.Name)"
                DisplayName = "$($_.DisplayName)"
                State       = "$($_.State)"
                StartMode   = "$($_.StartMode)"
                StartName   = "$($_.StartName)"
                PathName    = "$($_.PathName)"
            }
        }
    } -Default @())

$scheduledTasks = @(Invoke-Safe -ScriptBlock {
        Get-ScheduledTask -ErrorAction Stop | ForEach-Object {
            [pscustomobject][ordered]@{
                TaskName = "$($_.TaskName)"
                TaskPath = "$($_.TaskPath)"
                State    = "$($_.State)"
                UserId   = "$($_.Principal.UserId)"
                RunLevel = "$($_.Principal.RunLevel)"
            }
        }
    } -Default @())

$smbShares = @(Invoke-Safe -ScriptBlock {
        Get-SmbShare -ErrorAction Stop | ForEach-Object {
            [pscustomobject][ordered]@{
                Name        = "$($_.Name)"
                Path        = "$($_.Path)"
                Description = "$($_.Description)"
                ShareState  = "$($_.ShareState)"
                ShareType   = "$($_.ShareType)"
                Special     = [bool]$_.Special
            }
        }
    } -Default @())

$smbShareAccess = @(Invoke-Safe -ScriptBlock {
        Get-SmbShare -ErrorAction Stop | ForEach-Object {
            $shareName = "$($_.Name)"
            Get-SmbShareAccess -Name $shareName -ErrorAction Stop | ForEach-Object {
                [pscustomobject][ordered]@{
                    ShareName         = $shareName
                    AccountName       = "$($_.AccountName)"
                    AccessControlType = "$($_.AccessControlType)"
                    AccessRight       = "$($_.AccessRight)"
                }
            }
        }
    } -Default @())

foreach ($service in $services) {
    if (Test-ServiceAccountNeedsReview -Value $service.StartName) {
        $severity = if (Test-ManagedServiceAccount -Value $service.StartName) { "Medium" } else { "High" }
        $findings.Add((New-ServerFinding -FindingType "ServiceRunsAsCustomAccount" -Severity $severity -Name $service.Name -Title "Service runs as a custom or domain account" -Evidence "$($service.Name) starts as $($service.StartName); StartMode=$($service.StartMode)." -Recommendation "Confirm owner, credential rotation, least privilege, and dependency before changing the service account.")) | Out-Null
    }
    if (Test-UnquotedServicePath -Value $service.PathName) {
        $findings.Add((New-ServerFinding -FindingType "UnquotedServicePath" -Severity "High" -Name $service.Name -Title "Service path is unquoted and contains spaces" -Evidence "$($service.Name) PathName=$($service.PathName)." -Recommendation "Validate the executable path and quote it during approved maintenance if required.")) | Out-Null
    }
}

foreach ($task in $scheduledTasks) {
    if ($task.RunLevel -eq "Highest" -and -not [string]::IsNullOrWhiteSpace($task.UserId) -and $task.UserId -notmatch "^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE)$") {
        $findings.Add((New-ServerFinding -FindingType "ScheduledTaskRunsHighest" -Severity "Medium" -Name "$($task.TaskPath)$($task.TaskName)" -Title "Scheduled task runs with highest privileges" -Evidence "$($task.TaskPath)$($task.TaskName) runs as $($task.UserId) with RunLevel=$($task.RunLevel)." -Recommendation "Confirm task owner, action path, and whether highest privileges are required.")) | Out-Null
    }
}

foreach ($access in $smbShareAccess) {
    $share = $smbShares | Where-Object { $_.Name -eq $access.ShareName } | Select-Object -First 1
    if ($share -and $share.Special) {
        continue
    }
    if ($access.AccessControlType -eq "Allow" -and (Test-BroadPrincipal -Value $access.AccountName)) {
        $severity = if ($access.AccessRight -in @("Full", "Change")) { "High" } else { "Medium" }
        $findings.Add((New-ServerFinding -FindingType "BroadSmbShareAccess" -Severity $severity -Name $access.ShareName -Title "SMB share grants broad access" -Evidence "$($access.ShareName) grants $($access.AccessRight) to $($access.AccountName)." -Recommendation "Validate business need and narrow share permissions through approved change control.")) | Out-Null
    }
}

$severityCounts = [ordered]@{
    Critical = @($findings | Where-Object { $_.Severity -eq "Critical" }).Count
    High     = @($findings | Where-Object { $_.Severity -eq "High" }).Count
    Medium   = @($findings | Where-Object { $_.Severity -eq "Medium" }).Count
    Low      = @($findings | Where-Object { $_.Severity -eq "Low" }).Count
    Info     = @($findings | Where-Object { $_.Severity -eq "Info" }).Count
}

$report = [pscustomobject][ordered]@{
    ToolName        = "Get-WindowsServerSecurityInventory"
    ReportType      = "windows-server-security-inventory"
    GeneratedAtUtc  = $generatedAtUtc
    ComputerName    = $env:COMPUTERNAME
    Summary         = [ordered]@{
        InstalledFeatureCount      = $features.Count
        ServiceCount               = $services.Count
        CustomServiceAccountCount  = @($services | Where-Object { Test-ServiceAccountNeedsReview -Value $_.StartName }).Count
        ScheduledTaskCount         = $scheduledTasks.Count
        SmbShareCount              = $smbShares.Count
        SmbShareAccessEntryCount   = $smbShareAccess.Count
        FindingCount               = $findings.Count
        SeverityCounts             = $severityCounts
    }
    InstalledFeatures = @($features)
    Services          = @($services)
    ScheduledTasks    = @($scheduledTasks)
    SmbShares         = @($smbShares)
    SmbShareAccess    = @($smbShareAccess)
    Findings          = @($findings.ToArray())
    ReportErrors      = @($reportErrors.ToArray())
    Notes             = @(
        "This report is audit-only and does not change server configuration.",
        "Service, scheduled task, and share permission changes require owner review and approved change control."
    )
}

$report | ConvertTo-Json -Depth 8 | Out-File -FilePath $jsonPath -Encoding utf8
Write-CsvReport -Path $csvPath -Rows @($findings.ToArray())
Write-MarkdownReport -Path $markdownPath -Report $report

if (-not $Quiet) {
    Write-Host "Windows server security report written to: $jsonPath"
    Write-Host "Services: $($services.Count)"
    Write-Host "Findings: $($findings.Count)"
}
