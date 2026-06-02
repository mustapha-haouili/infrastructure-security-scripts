<#
.SYNOPSIS
Audits privileged Active Directory group membership changes against a baseline.

.DESCRIPTION
This script inventories high-value Active Directory groups, writes current
membership evidence, and compares direct members against a saved baseline. The
first run creates the baseline automatically. Later runs report added and
removed members, nested privileged group membership, foreign security
principals, computer accounts in privileged groups, and group query failures.

It is audit-only. It does not change Active Directory group membership.

.PARAMETER BaselinePath
Path to the stable JSON baseline used for comparison. If the file does not
exist, the current membership snapshot is written as the initial baseline.
Default: .\reports\ad-privileged-groups-baseline.json

.PARAMETER OutputDirectory
Directory where privileged-groups.json, privileged-groups.csv,
privileged-group-members.csv, privileged-group-changes.csv, and
privileged-groups-review.md are written.

.PARAMETER GroupName
Optional extra AD group identities to audit in addition to the built-in
privileged group set. Values can be names, distinguished names, GUIDs, or SIDs
accepted by Get-ADGroup -Identity.

.PARAMETER Server
Optional domain controller or AD LDS instance to query.

.PARAMETER Credential
Optional credential for the AD query.

.PARAMETER IncludeRecursiveMembers
Also collect recursive/effective members for visibility. Direct membership is
still the source of truth for baseline change comparison.

.PARAMETER UpdateBaseline
After writing the report, replace the baseline with the current snapshot. Use
only after reviewing and accepting the reported changes.

.PARAMETER Quiet
Suppress console summary.

.EXAMPLE
.\Watch-ADPrivilegedGroupChanges.ps1

Audit default privileged groups. Create the baseline if it does not exist;
otherwise compare current membership to the baseline.

.EXAMPLE
.\Watch-ADPrivilegedGroupChanges.ps1 -IncludeRecursiveMembers

Include recursive/effective group members in the evidence.

.EXAMPLE
.\Watch-ADPrivilegedGroupChanges.ps1 -UpdateBaseline

Accept the current state as the new baseline after reviewing the report.
#>

[CmdletBinding()]
param(
    [string]$BaselinePath = ".\reports\ad-privileged-groups-baseline.json",
    [string]$OutputDirectory = ".\reports\ad-privileged-groups-$env:COMPUTERNAME-$(Get-Date -Format 'yyyyMMdd-HHmmss')",
    [string[]]$GroupName = @(),
    [string]$Server = "",
    [System.Management.Automation.PSCredential]$Credential,
    [switch]$IncludeRecursiveMembers,
    [switch]$UpdateBaseline,
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
            DomainSID         = "$($domain.DomainSID)"
            PDCEmulator       = $domain.PDCEmulator
        }
    }
    catch {
        return [ordered]@{
            Name              = $null
            DNSRoot           = $null
            DistinguishedName = $null
            DomainMode        = $null
            DomainSID         = $null
            PDCEmulator       = $null
            QueryError        = $_.Exception.Message
        }
    }
}

function New-GroupDefinition {
    param(
        [Parameter(Mandatory = $true)][string]$Key,
        [Parameter(Mandatory = $true)][string]$DisplayName,
        [Parameter(Mandatory = $true)][string]$Identity,
        [string]$Tier = "Tier0",
        [string]$ExpectedRisk = "Critical"
    )

    [pscustomobject][ordered]@{
        Key          = $Key
        DisplayName  = $DisplayName
        Identity     = $Identity
        Tier         = $Tier
        ExpectedRisk = $ExpectedRisk
        IsExtraGroup = $false
    }
}

function Get-DefaultGroupDefinitions {
    param([Parameter(Mandatory = $true)][string]$DomainSID)

    $definitions = New-Object System.Collections.Generic.List[object]
    if ($DomainSID) {
        $definitions.Add((New-GroupDefinition -Key "DomainAdmins" -DisplayName "Domain Admins" -Identity "$DomainSID-512" -ExpectedRisk "Critical")) | Out-Null
        $definitions.Add((New-GroupDefinition -Key "SchemaAdmins" -DisplayName "Schema Admins" -Identity "$DomainSID-518" -ExpectedRisk "Critical")) | Out-Null
        $definitions.Add((New-GroupDefinition -Key "EnterpriseAdmins" -DisplayName "Enterprise Admins" -Identity "$DomainSID-519" -ExpectedRisk "Critical")) | Out-Null
        $definitions.Add((New-GroupDefinition -Key "GroupPolicyCreatorOwners" -DisplayName "Group Policy Creator Owners" -Identity "$DomainSID-520" -ExpectedRisk "High")) | Out-Null
        $definitions.Add((New-GroupDefinition -Key "ProtectedUsers" -DisplayName "Protected Users" -Identity "$DomainSID-525" -ExpectedRisk "High")) | Out-Null
        $definitions.Add((New-GroupDefinition -Key "KeyAdmins" -DisplayName "Key Admins" -Identity "$DomainSID-526" -ExpectedRisk "High")) | Out-Null
        $definitions.Add((New-GroupDefinition -Key "EnterpriseKeyAdmins" -DisplayName "Enterprise Key Admins" -Identity "$DomainSID-527" -ExpectedRisk "High")) | Out-Null
    }

    $definitions.Add((New-GroupDefinition -Key "BuiltinAdministrators" -DisplayName "Builtin Administrators" -Identity "S-1-5-32-544" -ExpectedRisk "Critical")) | Out-Null
    $definitions.Add((New-GroupDefinition -Key "AccountOperators" -DisplayName "Account Operators" -Identity "S-1-5-32-548" -ExpectedRisk "High")) | Out-Null
    $definitions.Add((New-GroupDefinition -Key "ServerOperators" -DisplayName "Server Operators" -Identity "S-1-5-32-549" -ExpectedRisk "High")) | Out-Null
    $definitions.Add((New-GroupDefinition -Key "PrintOperators" -DisplayName "Print Operators" -Identity "S-1-5-32-550" -ExpectedRisk "High")) | Out-Null
    $definitions.Add((New-GroupDefinition -Key "BackupOperators" -DisplayName "Backup Operators" -Identity "S-1-5-32-551" -ExpectedRisk "High")) | Out-Null
    $definitions.Add((New-GroupDefinition -Key "DnsAdmins" -DisplayName "DnsAdmins" -Identity "DnsAdmins" -ExpectedRisk "High")) | Out-Null

    foreach ($extraGroup in @($GroupName | Where-Object { $_ })) {
        $safeKey = ($extraGroup -replace "[^A-Za-z0-9]", "")
        if (-not $safeKey) {
            $safeKey = "ExtraGroup"
        }
        $definitions.Add([pscustomobject][ordered]@{
                Key          = "Extra_$safeKey"
                DisplayName  = $extraGroup
                Identity     = $extraGroup
                Tier         = "Custom"
                ExpectedRisk = "High"
                IsExtraGroup = $true
            }) | Out-Null
    }

    return @($definitions.ToArray())
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

function Get-MemberKey {
    param([Parameter(Mandatory = $true)][object]$Member)

    $sid = Get-ObjectValue -InputObject $Member -Name "SID"
    if (-not $sid) {
        $sid = Get-ObjectValue -InputObject $Member -Name "ObjectSid"
    }
    if ($sid) {
        return "$sid"
    }

    $dn = Get-ObjectValue -InputObject $Member -Name "DistinguishedName"
    if ($dn) {
        return "$dn"
    }

    return "$(Get-ObjectValue -InputObject $Member -Name "Name")"
}

function Convert-ADMember {
    param(
        [Parameter(Mandatory = $true)][object]$Group,
        [Parameter(Mandatory = $true)][object]$Member,
        [string]$MembershipType = "Direct"
    )

    $objectClass = "$(Get-ObjectValue -InputObject $Member -Name "ObjectClass")"
    $memberKey = Get-MemberKey -Member $Member
    $name = Get-ObjectValue -InputObject $Member -Name "Name"
    $sam = Get-ObjectValue -InputObject $Member -Name "SamAccountName"
    $distinguishedName = Get-ObjectValue -InputObject $Member -Name "DistinguishedName"
    $riskFlags = New-Object System.Collections.Generic.List[string]

    if ($objectClass -eq "group") {
        $riskFlags.Add("NestedGroup") | Out-Null
    }
    if ($objectClass -eq "foreignSecurityPrincipal") {
        $riskFlags.Add("ForeignSecurityPrincipal") | Out-Null
    }
    if ($objectClass -eq "computer") {
        $riskFlags.Add("ComputerAccount") | Out-Null
    }
    if ($Group.ExpectedRisk -eq "Critical") {
        $riskFlags.Add("CriticalGroup") | Out-Null
    }

    [pscustomobject][ordered]@{
        GroupKey          = $Group.Key
        GroupName         = $Group.Name
        GroupSamAccountName = $Group.SamAccountName
        GroupSID          = $Group.SID
        GroupDN           = $Group.DistinguishedName
        GroupTier         = $Group.Tier
        GroupExpectedRisk = $Group.ExpectedRisk
        MembershipType    = $MembershipType
        MemberKey         = $memberKey
        MemberName        = $name
        MemberSamAccountName = $sam
        MemberObjectClass = $objectClass
        MemberSID         = "$(Get-ObjectValue -InputObject $Member -Name "SID")"
        MemberDN          = $distinguishedName
        RiskFlags         = @($riskFlags.ToArray())
        RiskFlagsText     = if ($riskFlags.Count -gt 0) { @($riskFlags.ToArray()) -join "; " } else { "" }
    }
}

function Resolve-GroupDefinition {
    param(
        [Parameter(Mandatory = $true)][object]$Definition,
        [Parameter(Mandatory = $true)][hashtable]$CommonParameters
    )

    try {
        $group = Get-ADGroup -Identity $Definition.Identity -Properties Description, GroupCategory, GroupScope, SID @CommonParameters -ErrorAction Stop
        return [pscustomobject][ordered]@{
            Succeeded       = $true
            Error           = ""
            Key             = $Definition.Key
            Name            = $group.Name
            SamAccountName  = $group.SamAccountName
            SID             = "$($group.SID)"
            DistinguishedName = $group.DistinguishedName
            Description     = $group.Description
            GroupCategory   = "$($group.GroupCategory)"
            GroupScope      = "$($group.GroupScope)"
            Tier            = $Definition.Tier
            ExpectedRisk    = $Definition.ExpectedRisk
            IsExtraGroup    = [bool]$Definition.IsExtraGroup
        }
    }
    catch {
        return [pscustomobject][ordered]@{
            Succeeded       = $false
            Error           = $_.Exception.Message
            Key             = $Definition.Key
            Name            = $Definition.DisplayName
            SamAccountName  = ""
            SID             = ""
            DistinguishedName = ""
            Description     = ""
            GroupCategory   = ""
            GroupScope      = ""
            Tier            = $Definition.Tier
            ExpectedRisk    = $Definition.ExpectedRisk
            IsExtraGroup    = [bool]$Definition.IsExtraGroup
        }
    }
}

function Get-GroupMembershipRows {
    param(
        [Parameter(Mandatory = $true)][object]$Group,
        [Parameter(Mandatory = $true)][hashtable]$CommonParameters
    )

    $result = [ordered]@{
        DirectMembers    = @()
        RecursiveMembers = @()
        Errors           = @()
    }

    if (-not $Group.Succeeded) {
        $result["Errors"] = @("Group was not resolved: $($Group.Error)")
        return $result
    }

    try {
        $directMembers = @(Get-ADGroupMember -Identity $Group.DistinguishedName @CommonParameters -ErrorAction Stop)
        $result["DirectMembers"] = @($directMembers | ForEach-Object { Convert-ADMember -Group $Group -Member $_ -MembershipType "Direct" })
    }
    catch {
        $result["Errors"] = @($result["Errors"]) + "Could not read direct members for $($Group.Name): $($_.Exception.Message)"
    }

    if ($IncludeRecursiveMembers) {
        try {
            $recursiveMembers = @(Get-ADGroupMember -Identity $Group.DistinguishedName -Recursive @CommonParameters -ErrorAction Stop)
            $result["RecursiveMembers"] = @($recursiveMembers | ForEach-Object { Convert-ADMember -Group $Group -Member $_ -MembershipType "Recursive" })
        }
        catch {
            $result["Errors"] = @($result["Errors"]) + "Could not read recursive members for $($Group.Name): $($_.Exception.Message)"
        }
    }

    return $result
}

function Get-ComparisonKey {
    param([Parameter(Mandatory = $true)][object]$MemberRow)

    $memberKey = Get-ObjectValue -InputObject $MemberRow -Name "MemberKey"
    $groupSid = Get-ObjectValue -InputObject $MemberRow -Name "GroupSID"
    $groupKey = Get-ObjectValue -InputObject $MemberRow -Name "GroupKey"
    if ($groupSid) {
        return "$groupSid|$memberKey"
    }
    return "$groupKey|$memberKey"
}

function Convert-BaselineMembers {
    param([AllowNull()][object]$Baseline)

    if ($null -eq $Baseline) {
        return @()
    }

    $hasDirectMembers = $false
    if ($Baseline -is [System.Collections.IDictionary]) {
        $hasDirectMembers = $Baseline.Contains("DirectMembers")
    }
    elseif ($Baseline.PSObject.Properties["DirectMembers"]) {
        $hasDirectMembers = $true
    }

    $members = Get-ObjectValue -InputObject $Baseline -Name "DirectMembers"
    if ($hasDirectMembers) {
        return @($members)
    }

    $groups = @(Get-ObjectValue -InputObject $Baseline -Name "Groups")
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($group in $groups) {
        foreach ($member in @(Get-ObjectValue -InputObject $group -Name "DirectMembers")) {
            $rows.Add($member) | Out-Null
        }
    }
    return @($rows.ToArray())
}

function Read-Baseline {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -Path $Path)) {
        return $null
    }

    try {
        return Get-Content -Path $Path -Raw | ConvertFrom-Json
    }
    catch {
        throw "Could not read baseline '$Path': $($_.Exception.Message)"
    }
}

function Write-Baseline {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Snapshot
    )

    New-ParentDirectory -Path $Path
    $Snapshot | ConvertTo-Json -Depth 8 | Out-File -FilePath $Path -Encoding utf8
}

function Get-ChangeGuidance {
    param(
        [Parameter(Mandatory = $true)][string]$ChangeType,
        [Parameter(Mandatory = $true)][object]$MemberRow
    )

    $groupRisk = Get-ObjectValue -InputObject $MemberRow -Name "GroupExpectedRisk"
    $objectClass = Get-ObjectValue -InputObject $MemberRow -Name "MemberObjectClass"
    $priority = if ($groupRisk -eq "Critical" -or $ChangeType -eq "Added") { "P1 - Review immediately" } else { "P2 - Review" }
    $severity = if ($groupRisk -eq "Critical" -or $ChangeType -eq "Added") { "Critical" } else { "High" }
    $action = if ($ChangeType -eq "Added") {
        "Confirm this addition is approved, ticketed, time-bound, and owned. Remove immediately if unauthorized."
    }
    else {
        "Confirm this removal is approved and does not break administration, service recovery, or delegated operations."
    }
    if ($objectClass -eq "group") {
        $action = "$action Nested groups should be reviewed carefully because they can hide effective privileged users."
    }

    [ordered]@{
        ActionPriority   = $priority
        Severity         = $severity
        AdminAction      = $action
        VerificationStep = "Check GPMC/ADUC group membership, change ticket, owner approval, and recent Security events 4728/4729/4732/4733/4756/4757."
    }
}

function New-ChangeRow {
    param(
        [Parameter(Mandatory = $true)][string]$ChangeType,
        [Parameter(Mandatory = $true)][object]$MemberRow
    )

    $guidance = Get-ChangeGuidance -ChangeType $ChangeType -MemberRow $MemberRow
    [pscustomobject][ordered]@{
        ChangeType       = $ChangeType
        ActionPriority   = $guidance.ActionPriority
        Severity         = $guidance.Severity
        GroupName        = Get-ObjectValue -InputObject $MemberRow -Name "GroupName"
        GroupSID         = Get-ObjectValue -InputObject $MemberRow -Name "GroupSID"
        GroupTier        = Get-ObjectValue -InputObject $MemberRow -Name "GroupTier"
        MemberName       = Get-ObjectValue -InputObject $MemberRow -Name "MemberName"
        MemberSamAccountName = Get-ObjectValue -InputObject $MemberRow -Name "MemberSamAccountName"
        MemberObjectClass = Get-ObjectValue -InputObject $MemberRow -Name "MemberObjectClass"
        MemberSID        = Get-ObjectValue -InputObject $MemberRow -Name "MemberSID"
        MemberDN         = Get-ObjectValue -InputObject $MemberRow -Name "MemberDN"
        RiskFlagsText    = Get-ObjectValue -InputObject $MemberRow -Name "RiskFlagsText"
        AdminAction      = $guidance.AdminAction
        VerificationStep = $guidance.VerificationStep
    }
}

function Add-CurrentRiskRows {
    param(
        [Parameter(Mandatory = $true)][object]$Changes,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$DirectMembers
    )

    if (-not $Changes.PSObject.Methods["Add"]) {
        throw "Change collection does not support Add()."
    }

    foreach ($member in @($DirectMembers)) {
        $objectClass = Get-ObjectValue -InputObject $member -Name "MemberObjectClass"
        $riskFlags = Get-ObjectValue -InputObject $member -Name "RiskFlagsText"
        if ($objectClass -eq "group") {
            $row = New-ChangeRow -ChangeType "NestedGroupPresent" -MemberRow $member
            $row.ActionPriority = "P2 - Nested group review"
            $row.Severity = "High"
            $row.AdminAction = "Review nested group membership and document why nested privileged access is required."
            $Changes.Add($row) | Out-Null
        }
        elseif ($objectClass -eq "foreignSecurityPrincipal") {
            $row = New-ChangeRow -ChangeType "ForeignSecurityPrincipalPresent" -MemberRow $member
            $row.ActionPriority = "P2 - External principal review"
            $row.Severity = "High"
            $row.AdminAction = "Confirm the external/foreign principal is expected and still required."
            $Changes.Add($row) | Out-Null
        }
        elseif ($objectClass -eq "computer") {
            $row = New-ChangeRow -ChangeType "ComputerAccountPresent" -MemberRow $member
            $row.ActionPriority = "P2 - Computer principal review"
            $row.Severity = "High"
            $row.AdminAction = "Confirm why a computer account has privileged group membership."
            $Changes.Add($row) | Out-Null
        }
        elseif ($riskFlags -match "CriticalGroup") {
            continue
        }
    }
}

function Compare-Membership {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$CurrentMembers,
        [AllowNull()][object[]]$BaselineMembers
    )

    $changes = New-Object System.Collections.Generic.List[object]
    if ($null -eq $BaselineMembers) {
        Add-CurrentRiskRows -Changes $changes -DirectMembers $CurrentMembers
        return @($changes.ToArray())
    }

    $baselineByKey = @{}
    foreach ($member in @($BaselineMembers)) {
        $baselineByKey[(Get-ComparisonKey -MemberRow $member)] = $member
    }

    $currentByKey = @{}
    foreach ($member in @($CurrentMembers)) {
        $currentByKey[(Get-ComparisonKey -MemberRow $member)] = $member
    }

    foreach ($key in @($currentByKey.Keys | Sort-Object)) {
        if (-not $baselineByKey.ContainsKey($key)) {
            $changes.Add((New-ChangeRow -ChangeType "Added" -MemberRow $currentByKey[$key])) | Out-Null
        }
    }

    foreach ($key in @($baselineByKey.Keys | Sort-Object)) {
        if (-not $currentByKey.ContainsKey($key)) {
            $changes.Add((New-ChangeRow -ChangeType "Removed" -MemberRow $baselineByKey[$key])) | Out-Null
        }
    }

    Add-CurrentRiskRows -Changes $changes -DirectMembers $CurrentMembers
    return @($changes.ToArray())
}

function Get-PrioritySortValue {
    param([AllowNull()][object]$Value)

    $text = "$Value"
    if ($text -match "^P(\d+)") {
        return [int]$Matches[1]
    }
    return 9
}

function Write-CsvReport {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Rows,
        [Parameter(Mandatory = $true)][string[]]$Columns
    )

    if ($Rows.Count -eq 0) {
        Set-Content -Path $Path -Value ($Columns -join ",") -Encoding UTF8
        return
    }

    $Rows | Select-Object $Columns | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
}

function Add-MarkdownChangeTable {
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

    Add-MarkdownLine -Lines $Lines -Text "| Priority | Severity | Change | Group | Member | Type | Action |"
    Add-MarkdownLine -Lines $Lines -Text "|---|---|---|---|---|---|---|"
    foreach ($row in @($Rows | Select-Object -First $Limit)) {
        Add-MarkdownLine -Lines $Lines -Text ("| {0} | {1} | {2} | {3} | {4} | {5} | {6} |" -f `
                (ConvertTo-MarkdownSafeText $row.ActionPriority),
            (ConvertTo-MarkdownSafeText $row.Severity),
            (ConvertTo-MarkdownSafeText $row.ChangeType),
            (ConvertTo-MarkdownSafeText $row.GroupName),
            (ConvertTo-MarkdownSafeText $row.MemberName),
            (ConvertTo-MarkdownSafeText $row.MemberObjectClass),
            (ConvertTo-MarkdownSafeText $row.AdminAction))
    }

    if ($Rows.Count -gt $Limit) {
        Add-MarkdownLine -Lines $Lines
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
    $changes = @($Report["Changes"])
    $groups = @($Report["Groups"])
    $lines = New-Object System.Collections.Generic.List[string]

    Add-MarkdownLine -Lines $lines -Text "# AD Privileged Group Change Review"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "Generated UTC: ``$($metadata.GeneratedAtUtc)``"
    Add-MarkdownLine -Lines $lines -Text "Computer: ``$($metadata.ComputerName)``"
    Add-MarkdownLine -Lines $lines -Text "Baseline path: ``$($metadata.BaselinePath)``"
    Add-MarkdownLine -Lines $lines -Text "Baseline status: ``$($summary.BaselineStatus)``"
    Add-MarkdownLine -Lines $lines

    Add-MarkdownLine -Lines $lines -Text "## Summary"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "| Metric | Count |"
    Add-MarkdownLine -Lines $lines -Text "|---|---:|"
    foreach ($metric in @("GroupsAudited", "GroupsResolved", "GroupsFailed", "DirectMemberCount", "RecursiveMemberCount", "TotalChanges", "AddedMembers", "RemovedMembers", "NestedGroupFindings", "ForeignPrincipalFindings", "ComputerPrincipalFindings", "CriticalChanges", "HighChanges")) {
        Add-MarkdownLine -Lines $lines -Text ("| {0} | {1} |" -f $metric, $summary.$metric)
    }
    Add-MarkdownLine -Lines $lines

    Add-MarkdownLine -Lines $lines -Text "## Admin Action Plan"
    Add-MarkdownLine -Lines $lines
    if ($summary.BaselineStatus -eq "Created") {
        Add-MarkdownLine -Lines $lines -Text "No previous baseline existed, so the current privileged group membership was saved as the initial baseline. Re-run this script later to detect changes."
    }
    elseif ($summary.TotalChanges -eq 0) {
        Add-MarkdownLine -Lines $lines -Text "No membership changes were detected against the baseline. Review any nested, foreign, or computer-principal findings if present."
    }
    else {
        Add-MarkdownLine -Lines $lines -Text "Membership differences were detected. Review Added members first, then Removed members, then nested/foreign/computer-principal findings."
    }
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "Do not approve a baseline update until every change is confirmed with an owner, ticket, expected duration, and rollback decision."
    Add-MarkdownLine -Lines $lines

    Add-MarkdownLine -Lines $lines -Text "## Critical / High Review"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownChangeTable -Lines $lines -Rows @($changes | Where-Object { $_.Severity -in @("Critical", "High") } | Sort-Object @{ Expression = { Get-PrioritySortValue -Value $_.ActionPriority } }, ChangeType, GroupName, MemberName)

    Add-MarkdownLine -Lines $lines -Text "## All Changes And Findings"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownChangeTable -Lines $lines -Rows @($changes | Sort-Object @{ Expression = { Get-PrioritySortValue -Value $_.ActionPriority } }, ChangeType, GroupName, MemberName) -Limit 100

    Add-MarkdownLine -Lines $lines -Text "## Group Summary"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "| Group | Resolved | Direct members | Recursive members | Expected risk | Error |"
    Add-MarkdownLine -Lines $lines -Text "|---|---:|---:|---:|---|---|"
    foreach ($group in @($groups | Sort-Object Name)) {
        Add-MarkdownLine -Lines $lines -Text ("| {0} | {1} | {2} | {3} | {4} | {5} |" -f `
                (ConvertTo-MarkdownSafeText $group.Name),
            (ConvertTo-MarkdownSafeText $group.Succeeded),
            $group.DirectMemberCount,
            $group.RecursiveMemberCount,
            (ConvertTo-MarkdownSafeText $group.ExpectedRisk),
            (ConvertTo-MarkdownSafeText $group.Error))
    }
    Add-MarkdownLine -Lines $lines

    Add-MarkdownLine -Lines $lines -Text "## Review Rules"
    Add-MarkdownLine -Lines $lines
    foreach ($note in @($summary.Notes)) {
        Add-MarkdownLine -Lines $lines -Text "- $note"
    }

    $lines | Out-File -FilePath $Path -Encoding utf8
}

New-Directory -Path $OutputDirectory
$resolvedOutputDirectory = (Resolve-Path -Path $OutputDirectory).Path
$resolvedBaselinePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($BaselinePath)
$jsonPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "privileged-groups.json"
$groupCsvPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "privileged-groups.csv"
$memberCsvPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "privileged-group-members.csv"
$changeCsvPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "privileged-group-changes.csv"
$markdownPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "privileged-groups-review.md"

if (-not (Import-ActiveDirectoryModule)) {
    $reason = "ActiveDirectory PowerShell module was not found. Install RSAT Active Directory tools or run this script on a domain management host."
    $failedReport = [ordered]@{
        ReportMetadata = [ordered]@{
            SchemaVersion  = "1.0"
            ReportType     = "ADPrivilegedGroupChanges"
            Status         = "Failed"
            GeneratedAtUtc = (Get-Date).ToUniversalTime().ToString("o")
            ComputerName   = $env:COMPUTERNAME
            BaselinePath   = $resolvedBaselinePath
        }
        Summary = [ordered]@{
            Status = "Failed"
            Reason = $reason
        }
        Groups  = @()
        Members = @()
        Changes = @()
    }
    $failedReport | ConvertTo-Json -Depth 6 | Out-File -FilePath $jsonPath -Encoding utf8
    throw $reason
}

$commonParameters = Get-ADCommonParameters
$domainSummary = Get-DomainSummary -CommonParameters $commonParameters
$groupDefinitions = @(Get-DefaultGroupDefinitions -DomainSID "$($domainSummary.DomainSID)")
$groupRows = New-Object System.Collections.Generic.List[object]
$directMemberRows = New-Object System.Collections.Generic.List[object]
$recursiveMemberRows = New-Object System.Collections.Generic.List[object]
$reportErrors = New-Object System.Collections.Generic.List[string]

foreach ($definition in $groupDefinitions) {
    $group = Resolve-GroupDefinition -Definition $definition -CommonParameters $commonParameters
    $membership = Get-GroupMembershipRows -Group $group -CommonParameters $commonParameters
    foreach ($errorMessage in @($membership["Errors"])) {
        $reportErrors.Add($errorMessage) | Out-Null
    }
    foreach ($member in @($membership["DirectMembers"])) {
        $directMemberRows.Add($member) | Out-Null
    }
    foreach ($member in @($membership["RecursiveMembers"])) {
        $recursiveMemberRows.Add($member) | Out-Null
    }

    $groupRows.Add([pscustomobject][ordered]@{
            Key                  = $group.Key
            Name                 = $group.Name
            SamAccountName       = $group.SamAccountName
            SID                  = $group.SID
            DistinguishedName    = $group.DistinguishedName
            Succeeded            = [bool]$group.Succeeded
            Error                = $group.Error
            Tier                 = $group.Tier
            ExpectedRisk         = $group.ExpectedRisk
            IsExtraGroup         = [bool]$group.IsExtraGroup
            GroupCategory        = $group.GroupCategory
            GroupScope           = $group.GroupScope
            DirectMemberCount    = @($membership["DirectMembers"]).Count
            RecursiveMemberCount = @($membership["RecursiveMembers"]).Count
            Description          = $group.Description
        }) | Out-Null
}

$currentSnapshot = [ordered]@{
    ReportMetadata = [ordered]@{
        SchemaVersion           = "1.0"
        ReportType              = "ADPrivilegedGroupBaseline"
        GeneratedAtUtc          = (Get-Date).ToUniversalTime().ToString("o")
        Domain                  = $domainSummary
        IncludeRecursiveMembers = [bool]$IncludeRecursiveMembers
    }
    Groups           = @($groupRows.ToArray())
    DirectMembers    = @($directMemberRows.ToArray())
    RecursiveMembers = @($recursiveMemberRows.ToArray())
}

$baseline = Read-Baseline -Path $resolvedBaselinePath
$baselineStatus = "Loaded"
$baselineMembers = $null
if ($null -eq $baseline) {
    Write-Baseline -Path $resolvedBaselinePath -Snapshot $currentSnapshot
    $baselineStatus = "Created"
}
else {
    $baselineMembers = @(Convert-BaselineMembers -Baseline $baseline)
}

$changeRows = @(Compare-Membership -CurrentMembers @($directMemberRows.ToArray()) -BaselineMembers $baselineMembers)

if ($UpdateBaseline) {
    Write-Baseline -Path $resolvedBaselinePath -Snapshot $currentSnapshot
    $baselineStatus = if ($baselineStatus -eq "Created") { "Created" } else { "Updated" }
}

$changesFinal = @($changeRows | Sort-Object @{ Expression = { Get-PrioritySortValue -Value $_.ActionPriority } }, ChangeType, GroupName, MemberName)
$groupRowsFinal = @($groupRows.ToArray() | Sort-Object Name)
$directMembersFinal = @($directMemberRows.ToArray() | Sort-Object GroupName, MemberName)
$recursiveMembersFinal = @($recursiveMemberRows.ToArray() | Sort-Object GroupName, MemberName)
$allMemberRowsFinal = @($directMembersFinal + $recursiveMembersFinal)

$summary = [ordered]@{
    GroupsAudited                 = $groupRowsFinal.Count
    GroupsResolved                = @($groupRowsFinal | Where-Object { $_.Succeeded }).Count
    GroupsFailed                  = @($groupRowsFinal | Where-Object { -not $_.Succeeded }).Count
    DirectMemberCount             = $directMembersFinal.Count
    RecursiveMemberCount          = $recursiveMembersFinal.Count
    TotalChanges                  = $changesFinal.Count
    AddedMembers                  = @($changesFinal | Where-Object { $_.ChangeType -eq "Added" }).Count
    RemovedMembers                = @($changesFinal | Where-Object { $_.ChangeType -eq "Removed" }).Count
    NestedGroupFindings           = @($changesFinal | Where-Object { $_.ChangeType -eq "NestedGroupPresent" }).Count
    ForeignPrincipalFindings      = @($changesFinal | Where-Object { $_.ChangeType -eq "ForeignSecurityPrincipalPresent" }).Count
    ComputerPrincipalFindings     = @($changesFinal | Where-Object { $_.ChangeType -eq "ComputerAccountPresent" }).Count
    CriticalChanges               = @($changesFinal | Where-Object { $_.Severity -eq "Critical" }).Count
    HighChanges                   = @($changesFinal | Where-Object { $_.Severity -eq "High" }).Count
    BaselineStatus                = $baselineStatus
    BaselinePath                  = $resolvedBaselinePath
    ReportErrors                  = @($reportErrors.ToArray())
    Notes                         = @(
        "This script is audit-only and does not add, remove, or modify group members.",
        "Direct membership is the source of truth for baseline comparison.",
        "Added members to privileged groups should be reviewed first and removed immediately if unauthorized.",
        "Nested groups in privileged groups can hide effective privileged users and should be documented or removed.",
        "Use -UpdateBaseline only after every reported change has been reviewed and accepted.",
        "Correlate changes with Security events 4728, 4729, 4732, 4733, 4756, and 4757 where available."
    )
}

$report = [ordered]@{
    ReportMetadata = [ordered]@{
        SchemaVersion           = "1.0"
        ReportType              = "ADPrivilegedGroupChanges"
        Status                  = "Completed"
        GeneratedAtUtc          = (Get-Date).ToUniversalTime().ToString("o")
        ComputerName            = $env:COMPUTERNAME
        RunBy                   = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        BaselinePath            = $resolvedBaselinePath
        OutputDirectory         = $resolvedOutputDirectory
        IncludeRecursiveMembers = [bool]$IncludeRecursiveMembers
        UpdateBaseline          = [bool]$UpdateBaseline
        JsonPath                = $jsonPath
        GroupCsvPath            = $groupCsvPath
        MemberCsvPath           = $memberCsvPath
        ChangeCsvPath           = $changeCsvPath
        MarkdownPath            = $markdownPath
    }
    Domain  = $domainSummary
    Summary = $summary
    Groups  = @($groupRowsFinal)
    Members = @($allMemberRowsFinal)
    Changes = @($changesFinal)
}

$report | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding utf8
Write-CsvReport -Path $groupCsvPath -Rows $groupRowsFinal -Columns @("Name", "SamAccountName", "SID", "DistinguishedName", "Succeeded", "Error", "Tier", "ExpectedRisk", "IsExtraGroup", "GroupCategory", "GroupScope", "DirectMemberCount", "RecursiveMemberCount", "Description")
Write-CsvReport -Path $memberCsvPath -Rows $allMemberRowsFinal -Columns @("GroupName", "GroupSID", "GroupTier", "GroupExpectedRisk", "MembershipType", "MemberName", "MemberSamAccountName", "MemberObjectClass", "MemberSID", "MemberDN", "RiskFlagsText")
Write-CsvReport -Path $changeCsvPath -Rows $changesFinal -Columns @("ChangeType", "ActionPriority", "Severity", "GroupName", "GroupSID", "GroupTier", "MemberName", "MemberSamAccountName", "MemberObjectClass", "MemberSID", "MemberDN", "RiskFlagsText", "AdminAction", "VerificationStep")
Write-MarkdownReport -Path $markdownPath -Report $report

if (-not $Quiet) {
    Write-Host "AD privileged group report written to: $jsonPath"
    Write-Host "AD privileged group review written to: $markdownPath"
    Write-Host "Baseline path: $resolvedBaselinePath"
    Write-Host "Baseline status: $baselineStatus"
    Write-Host "Groups audited: $($summary.GroupsAudited)"
    Write-Host "Changes/findings: $($summary.TotalChanges)"
    Write-Host "Added members: $($summary.AddedMembers)"
    Write-Host "Removed members: $($summary.RemovedMembers)"
}
