<#
.SYNOPSIS
Reports stale Active Directory computer accounts with cleanup guidance.

.DESCRIPTION
This script audits Active Directory computer accounts and writes JSON, CSV, and
Markdown reports for computers that have not logged on within the selected
threshold.

It does not change Active Directory.

The report is conservative by design. It classifies domain controllers, servers,
workstations, disabled devices, never-logged-on devices, SPN-bearing computers,
and cleanup candidates. No computer account is marked safe for immediate
deletion.

.PARAMETER DaysInactive
Number of days since last logon before a computer is reported as stale.
Default: 90

.PARAMETER SearchBase
Optional distinguished name for the OU or domain path to search.

.PARAMETER Server
Optional domain controller or AD LDS instance to query.

.PARAMETER Credential
Optional credential for the AD query.

.PARAMETER IncludeDisabled
Include disabled computer accounts in the report. By default, only enabled
computers are scanned.

.PARAMETER ExcludeNeverLoggedOn
Exclude computers that have never logged on. By default, never-logged-on
computers older than the inactivity threshold are included.

.PARAMETER OutputDirectory
Directory where stale-computers.json, stale-computers.csv, and
stale-computers-review.md are written.
Default: .\reports\ad-stale-computers-COMPUTER-TIMESTAMP

.PARAMETER Quiet
Suppress console summary. Useful for scheduled reporting.

.EXAMPLE
.\Get-ADStaleComputerReport.ps1

Report enabled computers stale for 90 days or more.

.EXAMPLE
.\Get-ADStaleComputerReport.ps1 -DaysInactive 180 -SearchBase "OU=Computers,DC=example,DC=com"

Report enabled computers in a specific OU stale for 180 days or more.

.EXAMPLE
.\Get-ADStaleComputerReport.ps1 -IncludeDisabled -OutputDirectory .\reports\ad-computers

Include disabled computers and write reports to a known directory.
#>

[CmdletBinding()]
param(
    [ValidateRange(1, 3650)]
    [int]$DaysInactive = 90,

    [string]$SearchBase = "",
    [string]$Server = "",
    [System.Management.Automation.PSCredential]$Credential,
    [switch]$IncludeDisabled,
    [switch]$ExcludeNeverLoggedOn,
    [string]$OutputDirectory = ".\reports\ad-stale-computers-$env:COMPUTERNAME-$(Get-Date -Format 'yyyyMMdd-HHmmss')",
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

function Format-DateTimeUtc {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return $null
    }

    try {
        return ([datetime]$Value).ToUniversalTime().ToString("o")
    }
    catch {
        return $null
    }
}

function Convert-ADFileTimeToUtc {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return $null
    }

    try {
        $fileTime = [int64]$Value
        if ($fileTime -le 0) {
            return $null
        }
        return [datetime]::FromFileTimeUtc($fileTime).ToString("o")
    }
    catch {
        return $null
    }
}

function Get-ADCommonParameters {
    $parameters = @{}

    if ($Server) {
        $parameters["Server"] = $Server
    }
    if ($Credential) {
        $parameters["Credential"] = $Credential
    }

    return $parameters
}

function Write-CsvReport {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Rows
    )

    $columns = @(
        "ReviewPriority",
        "ActionPriority",
        "ComputerCategory",
        "LifecycleStage",
        "CleanupReadiness",
        "CanDeleteNow",
        "PotentialCleanupCandidate",
        "NextReviewStep",
        "Name",
        "DNSHostName",
        "Enabled",
        "InactiveDays",
        "DaysSinceCreated",
        "NeverLoggedOn",
        "LastLogonDateUtc",
        "LastLogonTimestampUtc",
        "PasswordLastSetUtc",
        "ComputerPasswordAgeDays",
        "OperatingSystem",
        "OperatingSystemVersion",
        "IsDomainController",
        "IsServerOS",
        "IsWorkstationOS",
        "HasSPN",
        "SPNCount",
        "DirectGroupCount",
        "DirectGroupsText",
        "PrivilegedGroupCount",
        "PrivilegedGroupsText",
        "ManagedBy",
        "Description",
        "RiskFlagsText",
        "ReviewReasonsText",
        "RecommendedAction",
        "CleanupGuidance",
        "DistinguishedName"
    )

    if ($Rows.Count -eq 0) {
        Set-Content -Path $Path -Value ($columns -join ",") -Encoding UTF8
        return
    }

    $Rows | Select-Object $columns | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
}

function Write-FailedReport {
    param(
        [Parameter(Mandatory = $true)][string]$JsonPath,
        [Parameter(Mandatory = $true)][string]$Reason
    )

    $report = [ordered]@{
        ReportMetadata = [ordered]@{
            SchemaVersion        = "1.0"
            ReportType           = "ADStaleComputers"
            Status               = "Failed"
            GeneratedAtUtc       = (Get-Date).ToUniversalTime().ToString("o")
            ComputerName         = $env:COMPUTERNAME
            RunBy                = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            DaysInactive         = $DaysInactive
            SearchBase           = if ($SearchBase) { $SearchBase } else { $null }
            Server               = if ($Server) { $Server } else { $null }
            IncludeDisabled      = [bool]$IncludeDisabled
            ExcludeNeverLoggedOn = [bool]$ExcludeNeverLoggedOn
        }
        Summary = [ordered]@{
            Status = "Failed"
            Reason = $Reason
        }
        StaleComputers = @()
    }

    $report | ConvertTo-Json -Depth 6 | Out-File -FilePath $JsonPath -Encoding utf8
}

function ConvertTo-MarkdownSafeText {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return ""
    }

    $text = "$Value"
    $text = $text -replace '\|', '\|'
    $text = $text -replace "`r?`n", " "
    return $text.Trim()
}

function Add-MarkdownLine {
    param(
        [Parameter(Mandatory = $true)][object]$Lines,
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Text = ""
    )

    if (-not $Lines.PSObject.Methods["Add"]) {
        throw "Markdown line collection does not support Add()."
    }

    $Lines.Add($Text) | Out-Null
}

function Add-MarkdownComputerTable {
    param(
        [Parameter(Mandatory = $true)][object]$Lines,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Rows,
        [int]$Limit = 50
    )

    if ($Rows.Count -eq 0) {
        Add-MarkdownLine -Lines $Lines -Text "None."
        Add-MarkdownLine -Lines $Lines
        return
    }

    Add-MarkdownLine -Lines $Lines -Text "| Priority | Computer | Category | Enabled | Inactive | OS | Risk flags | Next step |"
    Add-MarkdownLine -Lines $Lines -Text "|---|---|---|---:|---:|---|---|---|"
    foreach ($row in @($Rows | Select-Object -First $Limit)) {
        $inactive = if ($null -ne $row.InactiveDays) { $row.InactiveDays } elseif ($row.NeverLoggedOn) { "Never" } else { "" }
        Add-MarkdownLine -Lines $Lines -Text ("| {0} | {1} | {2} | {3} | {4} | {5} | {6} | {7} |" -f `
                (ConvertTo-MarkdownSafeText $row.ActionPriority),
            (ConvertTo-MarkdownSafeText $row.Name),
            (ConvertTo-MarkdownSafeText $row.ComputerCategory),
            (ConvertTo-MarkdownSafeText $row.Enabled),
            (ConvertTo-MarkdownSafeText $inactive),
            (ConvertTo-MarkdownSafeText $row.OperatingSystem),
            (ConvertTo-MarkdownSafeText $row.RiskFlagsText),
            (ConvertTo-MarkdownSafeText $row.NextReviewStep))
    }

    if ($Rows.Count -gt $Limit) {
        Add-MarkdownLine -Lines $Lines -Text ""
        Add-MarkdownLine -Lines $Lines -Text "Showing first $Limit of $($Rows.Count). See CSV/JSON for the full list."
    }

    Add-MarkdownLine -Lines $Lines
}

function Write-MarkdownReport {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Report
    )

    $metadata = $Report["ReportMetadata"]
    $summary = $Report["Summary"]
    $rows = @($Report["StaleComputers"])
    $lines = New-Object System.Collections.Generic.List[string]

    Add-MarkdownLine -Lines $lines -Text "# AD Stale Computer Review"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "Generated UTC: ``$($metadata.GeneratedAtUtc)``"
    Add-MarkdownLine -Lines $lines -Text "Computer: ``$($metadata.ComputerName)``"
    Add-MarkdownLine -Lines $lines -Text "Days inactive: ``$($metadata.DaysInactive)``"
    $searchBaseText = if ($metadata.SearchBase) { $metadata.SearchBase } else { "Domain default" }
    Add-MarkdownLine -Lines $lines -Text "Search base: ``$searchBaseText``"
    Add-MarkdownLine -Lines $lines

    Add-MarkdownLine -Lines $lines -Text "## Summary"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "| Metric | Count |"
    Add-MarkdownLine -Lines $lines -Text "|---|---:|"
    foreach ($metric in @("TotalComputersScanned", "StaleComputers", "EnabledStaleComputers", "DisabledStaleComputers", "CriticalPriorityComputers", "HighPriorityReviewComputers", "ServerStaleComputers", "WorkstationStaleComputers", "DomainControllerComputers", "PotentialCleanupCandidates", "CanDeleteNowComputers")) {
        Add-MarkdownLine -Lines $lines -Text ("| {0} | {1} |" -f $metric, $summary.$metric)
    }
    Add-MarkdownLine -Lines $lines

    Add-MarkdownLine -Lines $lines -Text "## Admin Action Plan"
    Add-MarkdownLine -Lines $lines
    if ($summary.CriticalPriorityComputers -gt 0) {
        Add-MarkdownLine -Lines $lines -Text "Critical items exist. Review domain controllers or protected infrastructure devices first. Do not disable or delete them from this cleanup report."
    }
    elseif ($summary.HighPriorityReviewComputers -gt 0) {
        Add-MarkdownLine -Lines $lines -Text "No Critical items were detected, but High review computers exist. Review stale servers, SPN-bearing computers, and enabled unknown devices before cleanup work."
    }
    else {
        Add-MarkdownLine -Lines $lines -Text "No Critical or High stale-computer items were detected in this run. Treat remaining items as controlled cleanup candidates, not automatic deletion approvals."
    }
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "> CanDeleteNow is always false. Disable/quarantine first, verify no dependency, then delete only through approved change control."
    Add-MarkdownLine -Lines $lines

    Add-MarkdownLine -Lines $lines -Text "## Critical"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownComputerTable -Lines $lines -Rows @($rows | Where-Object { $_.ReviewPriority -eq "Critical" })

    Add-MarkdownLine -Lines $lines -Text "## High"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownComputerTable -Lines $lines -Rows @($rows | Where-Object { $_.ReviewPriority -eq "High" })

    Add-MarkdownLine -Lines $lines -Text "## Medium"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownComputerTable -Lines $lines -Rows @($rows | Where-Object { $_.ReviewPriority -eq "Medium" })

    Add-MarkdownLine -Lines $lines -Text "## Potential Cleanup Candidates"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "These are still not approved for deletion. They are only cleanup candidates after owner approval, disabled-account quarantine, dependency checks, and rollback planning."
    Add-MarkdownLine -Lines $lines
    Add-MarkdownComputerTable -Lines $lines -Rows @($rows | Where-Object { $_.PotentialCleanupCandidate })

    Add-MarkdownLine -Lines $lines -Text "## Review Rules"
    Add-MarkdownLine -Lines $lines
    foreach ($note in @($summary.Notes)) {
        Add-MarkdownLine -Lines $lines -Text "- $note"
    }

    $lines | Out-File -FilePath $Path -Encoding utf8
}

function Import-ActiveDirectoryModule {
    $module = Get-Module -ListAvailable -Name ActiveDirectory | Select-Object -First 1
    if (-not $module) {
        return $false
    }

    Import-Module ActiveDirectory -ErrorAction Stop
    return $true
}

function Get-DomainSummary {
    param([Parameter(Mandatory = $true)][hashtable]$CommonParameters)

    try {
        $domain = Get-ADDomain @CommonParameters -ErrorAction Stop
        return [ordered]@{
            Name              = $domain.Name
            DNSRoot           = $domain.DNSRoot
            DistinguishedName = $domain.DistinguishedName
            DomainMode        = "$($domain.DomainMode)"
            PDCEmulator       = $domain.PDCEmulator
        }
    }
    catch {
        return [ordered]@{
            Name              = $null
            DNSRoot           = $null
            DistinguishedName = $null
            DomainMode        = $null
            PDCEmulator       = $null
            QueryError        = $_.Exception.Message
        }
    }
}

function Get-CnFromDistinguishedName {
    param([AllowNull()][string]$DistinguishedName)

    if (-not $DistinguishedName) {
        return ""
    }

    if ($DistinguishedName -match "CN=([^,]+)") {
        return $Matches[1]
    }

    return $DistinguishedName
}

function Convert-DistinguishedNamesToNames {
    param([AllowNull()][object[]]$DistinguishedNames)

    return @($DistinguishedNames | Where-Object { $_ } | ForEach-Object { Get-CnFromDistinguishedName -DistinguishedName "$_" })
}

function Get-PrivilegedGroupNames {
    param([AllowNull()][object[]]$GroupDistinguishedNames)

    $privilegedGroupPattern = '(?i)^(Domain Controllers|Enterprise Domain Controllers|Domain Admins|Enterprise Admins|Schema Admins|Administrators|Server Operators|Backup Operators|DnsAdmins|Group Policy Creator Owners)$'
    return @(Convert-DistinguishedNamesToNames -DistinguishedNames $GroupDistinguishedNames | Where-Object { $_ -match $privilegedGroupPattern })
}

function Test-DomainControllerComputer {
    param(
        [AllowNull()][object]$PrimaryGroupId,
        [AllowNull()][string]$OperatingSystem,
        [AllowNull()][object[]]$GroupNames
    )

    if ($PrimaryGroupId -eq 516) {
        return $true
    }
    if ($OperatingSystem -and $OperatingSystem -match "(?i)domain controller") {
        return $true
    }
    if (@($GroupNames | Where-Object { $_ -match "(?i)^Domain Controllers$" }).Count -gt 0) {
        return $true
    }
    return $false
}

function Test-ServerOS {
    param([AllowNull()][string]$OperatingSystem)

    return [bool]($OperatingSystem -and $OperatingSystem -match "(?i)server")
}

function Test-WorkstationOS {
    param([AllowNull()][string]$OperatingSystem)

    if (-not $OperatingSystem) {
        return $false
    }

    return [bool]($OperatingSystem -match "(?i)Windows (7|8|10|11|XP|Vista)")
}

function Get-ComputerCategory {
    param(
        [bool]$IsDomainController,
        [bool]$IsServerOS,
        [bool]$IsWorkstationOS,
        [bool]$HasSPN
    )

    if ($IsDomainController) {
        return "DomainController"
    }
    if ($IsServerOS) {
        return "Server"
    }
    if ($IsWorkstationOS) {
        return "Workstation"
    }
    if ($HasSPN) {
        return "ServiceComputer"
    }
    return "UnknownComputer"
}

function Get-ReviewPriority {
    param(
        [Parameter(Mandatory = $true)][object]$Computer,
        [string]$ComputerCategory,
        [bool]$HasSPN,
        [bool]$IsEnabled
    )

    if ($ComputerCategory -eq "DomainController") {
        return "Critical"
    }
    if ($ComputerCategory -eq "Server" -or $HasSPN) {
        return "High"
    }
    if ($IsEnabled) {
        return "Medium"
    }
    return "Low"
}

function Get-ActionPriority {
    param([string]$ReviewPriority)

    switch ($ReviewPriority) {
        "Critical" { "P1 - Critical infrastructure review" }
        "High" { "P2 - Owner and dependency review" }
        "Medium" { "P3 - Device cleanup review" }
        "Low" { "P4 - Cleanup candidate" }
        default { "P5 - Document" }
    }
}

function Get-PrioritySortOrder {
    param([string]$ReviewPriority)

    switch ($ReviewPriority) {
        "Critical" { 0 }
        "High" { 1 }
        "Medium" { 2 }
        "Low" { 3 }
        default { 9 }
    }
}

function Get-LifecycleStage {
    param(
        [bool]$IsEnabled,
        [bool]$NeverLoggedOn,
        [bool]$PotentialCleanupCandidate
    )

    if ($PotentialCleanupCandidate) {
        return "CleanupCandidateAfterQuarantine"
    }
    if (-not $IsEnabled) {
        return "DisabledNeedsReview"
    }
    if ($NeverLoggedOn) {
        return "EnabledNeverLoggedOn"
    }
    return "EnabledStale"
}

function Get-CleanupReadiness {
    param(
        [bool]$IsEnabled,
        [string]$ComputerCategory,
        [bool]$HasSPN,
        [int]$PrivilegedGroupCount
    )

    if ($ComputerCategory -eq "DomainController") {
        return "HoldDomainControllerDoNotDelete"
    }
    if ($IsEnabled) {
        return "NotReadyEnabledComputer"
    }
    if ($ComputerCategory -eq "Server" -or $HasSPN -or $PrivilegedGroupCount -gt 0) {
        return "NeedsOwnerAndDependencyReview"
    }
    return "CleanupCandidateAfterQuarantineAndOwnerApproval"
}

function Get-NextReviewStep {
    param(
        [string]$ReviewPriority,
        [string]$CleanupReadiness
    )

    if ($ReviewPriority -eq "Critical") {
        return "Confirm this is expected domain-controller infrastructure. Do not disable or delete from this report."
    }
    if ($ReviewPriority -eq "High") {
        return "Confirm server/service owner, CMDB role, SPNs, DNS, backup, monitoring, and application dependencies."
    }
    if ($CleanupReadiness -eq "CleanupCandidateAfterQuarantineAndOwnerApproval") {
        return "Confirm owner, disable/quarantine first, monitor for impact, then remove only after approved change control."
    }
    if ($ReviewPriority -eq "Medium") {
        return "Confirm device owner and current inventory. Disable/quarantine before deletion if the device is retired."
    }
    return "Document decision and cleanup after backup/export and approval."
}

function Get-RiskFlags {
    param(
        [bool]$IsEnabled,
        [bool]$NeverLoggedOn,
        [bool]$IsDomainController,
        [bool]$IsServerOS,
        [bool]$HasSPN,
        [int]$PrivilegedGroupCount,
        [AllowNull()][int]$ComputerPasswordAgeDays
    )

    $flags = New-Object System.Collections.Generic.List[string]

    if ($IsDomainController) {
        $flags.Add("DomainController") | Out-Null
    }
    if ($IsServerOS) {
        $flags.Add("ServerOS") | Out-Null
    }
    if ($IsEnabled) {
        $flags.Add("Enabled") | Out-Null
    }
    if ($NeverLoggedOn) {
        $flags.Add("NeverLoggedOn") | Out-Null
    }
    if ($HasSPN) {
        $flags.Add("HasSPN") | Out-Null
    }
    if ($PrivilegedGroupCount -gt 0) {
        $flags.Add("PrivilegedGroupMember") | Out-Null
    }
    if ($null -ne $ComputerPasswordAgeDays -and $ComputerPasswordAgeDays -ge 90) {
        $flags.Add("ComputerPasswordOld:$ComputerPasswordAgeDays") | Out-Null
    }

    return @($flags.ToArray())
}

function Get-ReviewReasons {
    param(
        [bool]$IsEnabled,
        [bool]$NeverLoggedOn,
        [string]$ComputerCategory,
        [bool]$HasSPN,
        [int]$PrivilegedGroupCount,
        [AllowNull()][int]$InactiveDays
    )

    $reasons = New-Object System.Collections.Generic.List[string]

    if ($ComputerCategory -eq "DomainController") {
        $reasons.Add("Computer is a domain controller or belongs to the Domain Controllers group.") | Out-Null
    }
    elseif ($ComputerCategory -eq "Server") {
        $reasons.Add("Computer appears to be a server and may host applications or infrastructure services.") | Out-Null
    }
    elseif ($ComputerCategory -eq "Workstation") {
        $reasons.Add("Computer appears to be a workstation or endpoint.") | Out-Null
    }
    else {
        $reasons.Add("Computer type is unknown and needs inventory confirmation.") | Out-Null
    }

    if ($IsEnabled) {
        $reasons.Add("Computer account is still enabled.") | Out-Null
    }
    if ($NeverLoggedOn) {
        $reasons.Add("No replicated logon evidence was found.") | Out-Null
    }
    elseif ($null -ne $InactiveDays) {
        $reasons.Add("Last logon evidence is $InactiveDays days old.") | Out-Null
    }
    if ($HasSPN) {
        $reasons.Add("Computer has SPNs and may be used by services.") | Out-Null
    }
    if ($PrivilegedGroupCount -gt 0) {
        $reasons.Add("Computer is a member of privileged or infrastructure groups.") | Out-Null
    }

    return @($reasons.ToArray())
}

function Get-Recommendation {
    param(
        [string]$ReviewPriority,
        [string]$CleanupReadiness,
        [string]$ComputerCategory
    )

    if ($ReviewPriority -eq "Critical") {
        return "Do not disable or delete. Review domain-controller/infrastructure health and inventory ownership."
    }
    if ($ReviewPriority -eq "High") {
        return "Review owner, role, DNS, SPNs, backup, monitoring, and service dependencies before any disable action."
    }
    if ($CleanupReadiness -eq "CleanupCandidateAfterQuarantineAndOwnerApproval") {
        return "Potential cleanup candidate after owner approval, disabled quarantine, dependency checks, and rollback planning."
    }
    if ($ComputerCategory -eq "UnknownComputer") {
        return "Confirm inventory type and owner before deciding whether to quarantine or retain."
    }
    return "Review owner and device inventory. Disable/quarantine before deletion if retired."
}

function Get-CleanupGuidance {
    param([string]$CleanupReadiness)

    switch ($CleanupReadiness) {
        "HoldDomainControllerDoNotDelete" {
            return "Never delete as stale-computer cleanup. Use domain-controller demotion and infrastructure change procedures."
        }
        "NotReadyEnabledComputer" {
            return "Enabled computer accounts need owner confirmation and quarantine before cleanup."
        }
        "NeedsOwnerAndDependencyReview" {
            return "Review server/service dependencies, SPNs, DNS, monitoring, backup, and application owners before disabling."
        }
        "CleanupCandidateAfterQuarantineAndOwnerApproval" {
            return "Backup/export evidence, disable/quarantine first, monitor for impact, then delete only after approved change control."
        }
        default {
            return "Review manually before any AD change."
        }
    }
}

New-Directory -Path $OutputDirectory
$resolvedOutputDirectory = (Resolve-Path -Path $OutputDirectory).Path
$jsonPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "stale-computers.json"
$csvPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "stale-computers.csv"
$markdownPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "stale-computers-review.md"

if (-not (Import-ActiveDirectoryModule)) {
    $reason = "ActiveDirectory PowerShell module was not found. Install RSAT Active Directory tools or run this script on a domain management host."
    Write-FailedReport -JsonPath $jsonPath -Reason $reason
    throw $reason
}

$now = Get-Date
$cutoff = $now.AddDays(-1 * $DaysInactive)
$commonParameters = Get-ADCommonParameters
$domainSummary = Get-DomainSummary -CommonParameters $commonParameters

$computerParameters = @{
    Filter      = if ($IncludeDisabled) { "*" } else { "Enabled -eq `$true" }
    Properties  = @(
        "Description",
        "DNSHostName",
        "Enabled",
        "IPv4Address",
        "LastLogonDate",
        "lastLogonTimestamp",
        "ManagedBy",
        "memberOf",
        "OperatingSystem",
        "OperatingSystemVersion",
        "PasswordLastSet",
        "PrimaryGroupID",
        "ServicePrincipalName",
        "SID",
        "userAccountControl",
        "whenChanged",
        "WhenCreated"
    )
    ErrorAction = "Stop"
}

foreach ($key in $commonParameters.Keys) {
    $computerParameters[$key] = $commonParameters[$key]
}
if ($SearchBase) {
    $computerParameters["SearchBase"] = $SearchBase
}

try {
    $computers = @(Get-ADComputer @computerParameters)
}
catch {
    $reason = "Active Directory computer query failed: $($_.Exception.Message)"
    Write-FailedReport -JsonPath $jsonPath -Reason $reason
    throw $reason
}

$staleComputers = New-Object System.Collections.Generic.List[object]

foreach ($computer in $computers) {
    $lastLogonDate = Get-ObjectValue -InputObject $computer -Name "LastLogonDate"
    $whenCreated = Get-ObjectValue -InputObject $computer -Name "WhenCreated"
    $neverLoggedOn = $null -eq $lastLogonDate
    $createdBeforeCutoff = $whenCreated -and ([datetime]$whenCreated -le $cutoff)

    $isStale = $false
    if ($lastLogonDate -and ([datetime]$lastLogonDate -le $cutoff)) {
        $isStale = $true
    }
    elseif ($neverLoggedOn -and -not $ExcludeNeverLoggedOn -and $createdBeforeCutoff) {
        $isStale = $true
    }

    if (-not $isStale) {
        continue
    }

    $spns = @(Get-ObjectValue -InputObject $computer -Name "ServicePrincipalName" | Where-Object { $_ })
    $hasSpn = $spns.Count -gt 0
    $memberOf = @(Get-ObjectValue -InputObject $computer -Name "memberOf" | Where-Object { $_ })
    $directGroupNames = @(Convert-DistinguishedNamesToNames -DistinguishedNames $memberOf)
    $privilegedGroupNames = @(Get-PrivilegedGroupNames -GroupDistinguishedNames $memberOf)
    $operatingSystem = Get-ObjectValue -InputObject $computer -Name "OperatingSystem"
    $primaryGroupId = Get-ObjectValue -InputObject $computer -Name "PrimaryGroupID"
    $isDomainController = Test-DomainControllerComputer -PrimaryGroupId $primaryGroupId -OperatingSystem $operatingSystem -GroupNames $directGroupNames
    $isServerOS = Test-ServerOS -OperatingSystem $operatingSystem
    $isWorkstationOS = Test-WorkstationOS -OperatingSystem $operatingSystem
    $isEnabled = [bool](Get-ObjectValue -InputObject $computer -Name "Enabled")
    $inactiveDays = if ($lastLogonDate) { [int](New-TimeSpan -Start ([datetime]$lastLogonDate) -End $now).TotalDays } else { $null }
    $daysSinceCreated = if ($whenCreated) { [int](New-TimeSpan -Start ([datetime]$whenCreated) -End $now).TotalDays } else { $null }
    $passwordLastSet = Get-ObjectValue -InputObject $computer -Name "PasswordLastSet"
    $computerPasswordAgeDays = if ($passwordLastSet) { [int](New-TimeSpan -Start ([datetime]$passwordLastSet) -End $now).TotalDays } else { $null }
    $computerCategory = Get-ComputerCategory -IsDomainController $isDomainController -IsServerOS $isServerOS -IsWorkstationOS $isWorkstationOS -HasSPN $hasSpn
    $reviewPriority = Get-ReviewPriority -Computer $computer -ComputerCategory $computerCategory -HasSPN $hasSpn -IsEnabled $isEnabled
    $cleanupReadiness = Get-CleanupReadiness -IsEnabled $isEnabled -ComputerCategory $computerCategory -HasSPN $hasSpn -PrivilegedGroupCount $privilegedGroupNames.Count
    $potentialCleanupCandidate = $cleanupReadiness -eq "CleanupCandidateAfterQuarantineAndOwnerApproval"
    $lifecycleStage = Get-LifecycleStage -IsEnabled $isEnabled -NeverLoggedOn $neverLoggedOn -PotentialCleanupCandidate $potentialCleanupCandidate
    $riskFlags = @(Get-RiskFlags -IsEnabled $isEnabled -NeverLoggedOn $neverLoggedOn -IsDomainController $isDomainController -IsServerOS $isServerOS -HasSPN $hasSpn -PrivilegedGroupCount $privilegedGroupNames.Count -ComputerPasswordAgeDays $computerPasswordAgeDays)
    $reviewReasons = @(Get-ReviewReasons -IsEnabled $isEnabled -NeverLoggedOn $neverLoggedOn -ComputerCategory $computerCategory -HasSPN $hasSpn -PrivilegedGroupCount $privilegedGroupNames.Count -InactiveDays $inactiveDays)
    $nextReviewStep = Get-NextReviewStep -ReviewPriority $reviewPriority -CleanupReadiness $cleanupReadiness

    $staleComputers.Add([pscustomobject][ordered]@{
            ReviewPriority        = $reviewPriority
            ActionPriority        = Get-ActionPriority -ReviewPriority $reviewPriority
            ComputerCategory      = $computerCategory
            LifecycleStage        = $lifecycleStage
            CleanupReadiness      = $cleanupReadiness
            CanDeleteNow          = $false
            PotentialCleanupCandidate = $potentialCleanupCandidate
            NextReviewStep        = $nextReviewStep
            Name                  = Get-ObjectValue -InputObject $computer -Name "Name"
            DNSHostName           = Get-ObjectValue -InputObject $computer -Name "DNSHostName"
            SID                   = "$(Get-ObjectValue -InputObject $computer -Name "SID")"
            Enabled               = $isEnabled
            InactiveDays          = $inactiveDays
            DaysSinceCreated      = $daysSinceCreated
            NeverLoggedOn         = [bool]$neverLoggedOn
            LastLogonDateUtc      = Format-DateTimeUtc -Value $lastLogonDate
            LastLogonTimestampUtc = Convert-ADFileTimeToUtc -Value (Get-ObjectValue -InputObject $computer -Name "lastLogonTimestamp")
            LastLogonEvidence     = if ($neverLoggedOn) { "No LastLogonDate/lastLogonTimestamp present." } else { "LastLogonDate from replicated lastLogonTimestamp." }
            WhenCreatedUtc        = Format-DateTimeUtc -Value $whenCreated
            WhenChangedUtc        = Format-DateTimeUtc -Value (Get-ObjectValue -InputObject $computer -Name "whenChanged")
            PasswordLastSetUtc    = Format-DateTimeUtc -Value $passwordLastSet
            ComputerPasswordAgeDays = $computerPasswordAgeDays
            OperatingSystem       = $operatingSystem
            OperatingSystemVersion = Get-ObjectValue -InputObject $computer -Name "OperatingSystemVersion"
            IPv4Address           = Get-ObjectValue -InputObject $computer -Name "IPv4Address"
            IsDomainController    = [bool]$isDomainController
            IsServerOS            = [bool]$isServerOS
            IsWorkstationOS       = [bool]$isWorkstationOS
            PrimaryGroupID        = $primaryGroupId
            UserAccountControl    = Get-ObjectValue -InputObject $computer -Name "userAccountControl"
            HasSPN                = [bool]$hasSpn
            SPNCount              = $spns.Count
            ServicePrincipalNames = @($spns)
            DirectGroupCount      = $directGroupNames.Count
            DirectGroups          = @($directGroupNames)
            DirectGroupsText      = if ($directGroupNames.Count -gt 0) { $directGroupNames -join "; " } else { "" }
            PrivilegedGroupCount  = $privilegedGroupNames.Count
            PrivilegedGroups      = @($privilegedGroupNames)
            PrivilegedGroupsText  = if ($privilegedGroupNames.Count -gt 0) { $privilegedGroupNames -join "; " } else { "" }
            ManagedBy             = Get-ObjectValue -InputObject $computer -Name "ManagedBy"
            Description           = Get-ObjectValue -InputObject $computer -Name "Description"
            RiskFlags             = @($riskFlags)
            RiskFlagsText         = if ($riskFlags.Count -gt 0) { $riskFlags -join "; " } else { "" }
            ReviewReasons         = @($reviewReasons)
            ReviewReasonsText     = if ($reviewReasons.Count -gt 0) { $reviewReasons -join " " } else { "" }
            RecommendedAction     = Get-Recommendation -ReviewPriority $reviewPriority -CleanupReadiness $cleanupReadiness -ComputerCategory $computerCategory
            CleanupGuidance       = Get-CleanupGuidance -CleanupReadiness $cleanupReadiness
            DistinguishedName     = Get-ObjectValue -InputObject $computer -Name "DistinguishedName"
        }) | Out-Null
}

$staleRows = @($staleComputers.ToArray() | Sort-Object @{ Expression = {
            Get-PrioritySortOrder -ReviewPriority $_.ReviewPriority
        } }, Name)
$enabledStale = @($staleRows | Where-Object { $_.Enabled }).Count
$disabledStale = @($staleRows | Where-Object { -not $_.Enabled }).Count
$neverLoggedOnCount = @($staleRows | Where-Object { $_.NeverLoggedOn }).Count
$criticalPriorityCount = @($staleRows | Where-Object { $_.ReviewPriority -eq "Critical" }).Count
$highPriorityCount = @($staleRows | Where-Object { $_.ReviewPriority -eq "High" }).Count
$mediumPriorityCount = @($staleRows | Where-Object { $_.ReviewPriority -eq "Medium" }).Count
$lowPriorityCount = @($staleRows | Where-Object { $_.ReviewPriority -eq "Low" }).Count
$domainControllerCount = @($staleRows | Where-Object { $_.IsDomainController }).Count
$serverCount = @($staleRows | Where-Object { $_.IsServerOS -and -not $_.IsDomainController }).Count
$workstationCount = @($staleRows | Where-Object { $_.IsWorkstationOS }).Count
$spnCount = @($staleRows | Where-Object { $_.HasSPN }).Count
$privilegedGroupMemberCount = @($staleRows | Where-Object { $_.PrivilegedGroupCount -gt 0 }).Count
$potentialCleanupCandidateCount = @($staleRows | Where-Object { $_.PotentialCleanupCandidate }).Count
$priorityCounts = [ordered]@{
    Critical = $criticalPriorityCount
    High     = $highPriorityCount
    Medium   = $mediumPriorityCount
    Low      = $lowPriorityCount
}

$report = [ordered]@{
    ReportMetadata = [ordered]@{
        SchemaVersion        = "1.0"
        ReportType           = "ADStaleComputers"
        Status               = "Completed"
        GeneratedAtUtc       = (Get-Date).ToUniversalTime().ToString("o")
        ComputerName         = $env:COMPUTERNAME
        RunBy                = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        DaysInactive         = $DaysInactive
        CutoffUtc            = Format-DateTimeUtc -Value $cutoff
        SearchBase           = if ($SearchBase) { $SearchBase } else { $null }
        Server               = if ($Server) { $Server } else { $null }
        IncludeDisabled      = [bool]$IncludeDisabled
        ExcludeNeverLoggedOn = [bool]$ExcludeNeverLoggedOn
        JsonPath             = $jsonPath
        CsvPath              = $csvPath
        MarkdownPath         = $markdownPath
    }
    Domain = $domainSummary
    Summary = [ordered]@{
        TotalComputersScanned       = $computers.Count
        StaleComputers              = $staleRows.Count
        EnabledStaleComputers       = $enabledStale
        DisabledStaleComputers      = $disabledStale
        NeverLoggedOnComputers      = $neverLoggedOnCount
        CriticalPriorityComputers   = $criticalPriorityCount
        HighPriorityReviewComputers = $highPriorityCount
        MediumPriorityComputers     = $mediumPriorityCount
        LowPriorityComputers        = $lowPriorityCount
        PriorityCounts              = $priorityCounts
        DomainControllerComputers   = $domainControllerCount
        ServerStaleComputers        = $serverCount
        WorkstationStaleComputers   = $workstationCount
        SPNStaleComputers           = $spnCount
        PrivilegedGroupMembers      = $privilegedGroupMemberCount
        PotentialCleanupCandidates  = $potentialCleanupCandidateCount
        CanDeleteNowComputers       = 0
        RecommendedFirstReview      = "Review Critical domain controllers first, then High stale servers or SPN-bearing computers. No computer account is safe to delete directly."
        Notes                       = @(
            "This script is audit-only and does not disable, delete, move, or modify computer accounts.",
            "LastLogonDate is based on replicated lastLogonTimestamp and can lag behind actual logon activity.",
            "Never-logged-on computers are included only when the account was created before the inactivity cutoff.",
            "CanDeleteNow is always false because computer cleanup needs owner approval, quarantine, dependency checks, and rollback planning.",
            "Domain controllers must be handled through demotion and infrastructure change procedures, not stale-account cleanup.",
            "Servers and SPN-bearing computers may have DNS, monitoring, backup, application, LDAP, SMB, WinRM, RDP, or service dependencies.",
            "For cleanup candidates, backup/export evidence, disable or quarantine first, monitor for impact, then delete only after approved change control."
        )
    }
    StaleComputers = @($staleRows)
}

$report | ConvertTo-Json -Depth 8 | Out-File -FilePath $jsonPath -Encoding utf8
Write-CsvReport -Path $csvPath -Rows $staleRows
Write-MarkdownReport -Path $markdownPath -Report $report

if (-not $Quiet) {
    Write-Host "AD stale computer report written to: $jsonPath"
    Write-Host "AD stale computer CSV written to: $csvPath"
    Write-Host "AD stale computer review written to: $markdownPath"
    Write-Host "Stale computers: $($staleRows.Count)"
    Write-Host "Critical priority: $criticalPriorityCount"
    Write-Host "High priority: $highPriorityCount"
    Write-Host "Potential cleanup candidates: $potentialCleanupCandidateCount"
    Write-Host "Can delete now: 0"
}
