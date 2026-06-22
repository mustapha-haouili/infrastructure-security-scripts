<#
.SYNOPSIS
Inventories local Administrators group membership on a Windows host.

.DESCRIPTION
This script collects local Administrators membership and writes JSON, CSV, and
Markdown reports. It does not change local users, groups, or policy.

The report is intended for server and workstation evidence collection. Review
domain groups, enabled local users, unknown members, and nonstandard admin
entries with the system owner before making changes.

.PARAMETER OutputDirectory
Directory where windows-local-admins.json, windows-local-admins.csv, and
windows-local-admins-review.md are written.
Default: .\reports\windows-local-admins-COMPUTER-TIMESTAMP

.PARAMETER Quiet
Suppress console summary. Useful for client collection automation.

.EXAMPLE
.\Get-WindowsLocalAdminInventory.ps1

Collect local Administrators membership and write reports.

.EXAMPLE
.\Get-WindowsLocalAdminInventory.ps1 -OutputDirectory .\reports\server01-local-admins -Quiet

Write reports to a known folder without console summary.
#>

[CmdletBinding()]
param(
    [string]$OutputDirectory = ".\reports\windows-local-admins-$env:COMPUTERNAME-$(Get-Date -Format 'yyyyMMdd-HHmmss')",
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

function Get-AdministratorsGroup {
    $group = Invoke-Safe -ScriptBlock { Get-LocalGroup -SID "S-1-5-32-544" -ErrorAction Stop } -Default $null
    if ($group) {
        return $group
    }

    return Invoke-Safe -ScriptBlock { Get-LocalGroup -Name "Administrators" -ErrorAction Stop } -Default $null
}

function Get-MemberNameLeaf {
    param([AllowNull()][object]$Name)

    $text = "$Name"
    if ($text -match "^[^\\]+\\(.+)$") {
        return $Matches[1]
    }
    return $text
}

function Get-LocalUserDetails {
    param([AllowNull()][object]$Member)

    $memberName = Get-MemberNameLeaf -Name $Member.Name
    if ([string]::IsNullOrWhiteSpace($memberName)) {
        return $null
    }

    Invoke-Safe -ScriptBlock {
        Get-LocalUser -Name $memberName -ErrorAction Stop
    } -Default $null
}

function Get-PrincipalCategory {
    param([AllowNull()][object]$Member)

    $source = "$($Member.PrincipalSource)"
    $objectClass = "$($Member.ObjectClass)"
    $name = "$($Member.Name)"

    if ($source -eq "Local" -and $objectClass -eq "User") {
        return "LocalUser"
    }
    if ($source -eq "Local" -and $objectClass -eq "Group") {
        return "LocalGroup"
    }
    if ($source -eq "ActiveDirectory" -and $objectClass -eq "Group") {
        return "DomainGroup"
    }
    if ($source -eq "ActiveDirectory" -and $objectClass -eq "User") {
        return "DomainUser"
    }
    if ($name -match "^S-\d-\d+") {
        return "UnresolvedSid"
    }
    return "Other"
}

function New-AdminFinding {
    param(
        [Parameter(Mandatory = $true)][string]$FindingType,
        [Parameter(Mandatory = $true)][string]$Severity,
        [Parameter(Mandatory = $true)][string]$Principal,
        [Parameter(Mandatory = $true)][string]$Title,
        [Parameter(Mandatory = $true)][string]$Evidence,
        [Parameter(Mandatory = $true)][string]$Recommendation
    )

    [pscustomobject][ordered]@{
        FindingType       = $FindingType
        Severity          = $Severity
        Principal         = $Principal
        Title             = $Title
        Evidence          = $Evidence
        Recommendation    = $Recommendation
        RequiresOwnerReview = $true
        SafeToAutoRemediate = $false
    }
}

function Get-AdminAssessment {
    param(
        [Parameter(Mandatory = $true)][object]$Row,
        [AllowNull()][object]$LocalUser
    )

    $findings = @()
    $principal = "$($Row.Name)"

    if ($Row.PrincipalCategory -eq "UnresolvedSid") {
        $findings += New-AdminFinding -FindingType "UnresolvedLocalAdmin" -Severity "High" -Principal $principal -Title "Unresolved SID has local administrator rights" -Evidence "The Administrators group contains unresolved SID $principal." -Recommendation "Verify whether the SID belongs to a removed account or trusted domain. Remove only after owner review."
    }
    elseif ($Row.PrincipalCategory -eq "DomainGroup") {
        $findings += New-AdminFinding -FindingType "DomainGroupLocalAdmin" -Severity "High" -Principal $principal -Title "Domain group has local administrator rights" -Evidence "$principal is a domain group in the local Administrators group." -Recommendation "Confirm this group is approved for local administration and has controlled membership."
    }
    elseif ($Row.PrincipalCategory -eq "DomainUser") {
        $findings += New-AdminFinding -FindingType "DomainUserLocalAdmin" -Severity "High" -Principal $principal -Title "Domain user has direct local administrator rights" -Evidence "$principal is a domain user directly assigned to local Administrators." -Recommendation "Prefer managed groups over direct user assignment and confirm business need."
    }
    elseif ($Row.PrincipalCategory -eq "LocalUser" -and $LocalUser) {
        if ($LocalUser.Enabled) {
            $findings += New-AdminFinding -FindingType "EnabledLocalAdminUser" -Severity "Medium" -Principal $principal -Title "Enabled local user has administrator rights" -Evidence "$principal is enabled and belongs to local Administrators." -Recommendation "Confirm owner, password management, and whether the account should remain enabled."
        }
        if ($LocalUser.PasswordRequired -eq $false) {
            $findings += New-AdminFinding -FindingType "LocalAdminPasswordNotRequired" -Severity "High" -Principal $principal -Title "Local admin user does not require a password" -Evidence "$principal has PasswordRequired set to false." -Recommendation "Require a password or disable the account after approved review."
        }
    }

    return $findings
}

function ConvertTo-CsvValue {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return ""
    }
    return "$Value"
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
    Add-MarkdownLine -Lines $lines -Text "# Windows Local Administrators Inventory"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "Generated at UTC: ``$($Report.GeneratedAtUtc)``"
    Add-MarkdownLine -Lines $lines -Text "Computer: ``$($Report.ComputerName)``"
    Add-MarkdownLine -Lines $lines -Text "Administrators group: ``$($Report.AdministratorsGroupName)``"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "## Summary"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "- Member count: $($Report.Summary.MemberCount)"
    Add-MarkdownLine -Lines $lines -Text "- Finding count: $($Report.Summary.FindingCount)"
    Add-MarkdownLine -Lines $lines -Text "- Domain admins/groups: $($Report.Summary.DomainPrincipalCount)"
    Add-MarkdownLine -Lines $lines -Text "- Enabled local admin users: $($Report.Summary.EnabledLocalAdminUserCount)"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "## Findings"
    Add-MarkdownLine -Lines $lines
    if ($Report.Findings.Count -eq 0) {
        Add-MarkdownLine -Lines $lines -Text "- None identified."
    }
    else {
        Add-MarkdownLine -Lines $lines -Text "| Severity | Principal | Finding | Recommendation |"
        Add-MarkdownLine -Lines $lines -Text "|---|---|---|---|"
        foreach ($finding in $Report.Findings) {
            Add-MarkdownLine -Lines $lines -Text "| $(Escape-MarkdownCell $finding.Severity) | $(Escape-MarkdownCell $finding.Principal) | $(Escape-MarkdownCell $finding.Title) | $(Escape-MarkdownCell $finding.Recommendation) |"
        }
    }
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "## Members"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "| Name | Category | Object class | Source | Enabled | Last logon UTC |"
    Add-MarkdownLine -Lines $lines -Text "|---|---|---|---|---|---|"
    foreach ($member in $Report.LocalAdministrators) {
        Add-MarkdownLine -Lines $lines -Text "| $(Escape-MarkdownCell $member.Name) | $(Escape-MarkdownCell $member.PrincipalCategory) | $(Escape-MarkdownCell $member.ObjectClass) | $(Escape-MarkdownCell $member.PrincipalSource) | $(Escape-MarkdownCell $member.Enabled) | $(Escape-MarkdownCell $member.LastLogonUtc) |"
    }
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "## Safety Notes"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "- This script does not change local users or groups."
    Add-MarkdownLine -Lines $lines -Text "- Remove local administrators only after owner review and approved change control."

    $lines | Out-File -FilePath $Path -Encoding utf8
}

New-Directory -Path $OutputDirectory
$resolvedOutputDirectory = (Resolve-Path -Path $OutputDirectory).Path
$jsonPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "windows-local-admins.json"
$csvPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "windows-local-admins.csv"
$markdownPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "windows-local-admins-review.md"
$generatedAtUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$reportErrors = New-Object System.Collections.Generic.List[string]
$members = New-Object System.Collections.Generic.List[object]
$findings = New-Object System.Collections.Generic.List[object]

$adminGroup = Get-AdministratorsGroup
if (-not $adminGroup) {
    throw "Unable to find the local Administrators group."
}

$groupMembers = Invoke-Safe -ScriptBlock {
    Get-LocalGroupMember -Group $adminGroup.Name -ErrorAction Stop
} -Default $null

if ($null -eq $groupMembers) {
    $reportErrors.Add("Get-LocalGroupMember failed. Try running PowerShell as Administrator for complete local group membership evidence.") | Out-Null
    $groupMembers = @()
}

foreach ($member in @($groupMembers)) {
    $localUser = $null
    $category = Get-PrincipalCategory -Member $member
    if ($category -eq "LocalUser") {
        $localUser = Get-LocalUserDetails -Member $member
    }

    $row = [pscustomobject][ordered]@{
        Name              = "$($member.Name)"
        ObjectClass       = "$($member.ObjectClass)"
        PrincipalSource   = "$($member.PrincipalSource)"
        PrincipalCategory = $category
        Sid               = "$($member.SID)"
        Enabled           = if ($localUser) { [bool]$localUser.Enabled } else { $null }
        LastLogonUtc      = if ($localUser) { Format-DateTimeUtc -Value $localUser.LastLogon } else { $null }
        PasswordRequired  = if ($localUser) { $localUser.PasswordRequired } else { $null }
        Description       = if ($localUser) { "$($localUser.Description)" } else { "" }
    }
    $members.Add($row) | Out-Null
    foreach ($finding in @(Get-AdminAssessment -Row $row -LocalUser $localUser)) {
        $findings.Add($finding) | Out-Null
    }
}

$domainPrincipalCount = @($members | Where-Object { $_.PrincipalCategory -in @("DomainGroup", "DomainUser") }).Count
$enabledLocalAdminUserCount = @($members | Where-Object { $_.PrincipalCategory -eq "LocalUser" -and $_.Enabled }).Count
$severityCounts = [ordered]@{
    Critical = @($findings | Where-Object { $_.Severity -eq "Critical" }).Count
    High     = @($findings | Where-Object { $_.Severity -eq "High" }).Count
    Medium   = @($findings | Where-Object { $_.Severity -eq "Medium" }).Count
    Low      = @($findings | Where-Object { $_.Severity -eq "Low" }).Count
    Info     = @($findings | Where-Object { $_.Severity -eq "Info" }).Count
}

$report = [pscustomobject][ordered]@{
    ToolName                = "Get-WindowsLocalAdminInventory"
    ReportType              = "windows-local-admin-inventory"
    GeneratedAtUtc          = $generatedAtUtc
    ComputerName            = $env:COMPUTERNAME
    AdministratorsGroupName = "$($adminGroup.Name)"
    AdministratorsGroupSid  = "$($adminGroup.SID)"
    Summary                 = [ordered]@{
        MemberCount                 = $members.Count
        FindingCount                = $findings.Count
        DomainPrincipalCount        = $domainPrincipalCount
        EnabledLocalAdminUserCount  = $enabledLocalAdminUserCount
        SeverityCounts              = $severityCounts
    }
    LocalAdministrators     = @($members.ToArray())
    Findings                = @($findings.ToArray())
    ReportErrors            = @($reportErrors.ToArray())
    Notes                   = @(
        "This report is inventory-only and does not change local group membership.",
        "Local administrator changes require owner review and approved change control."
    )
}

$report | ConvertTo-Json -Depth 8 | Out-File -FilePath $jsonPath -Encoding utf8
Write-CsvReport -Path $csvPath -Rows @($members.ToArray())
Write-MarkdownReport -Path $markdownPath -Report $report

if (-not $Quiet) {
    Write-Host "Windows local administrators report written to: $jsonPath"
    Write-Host "Members: $($members.Count)"
    Write-Host "Findings: $($findings.Count)"
}
