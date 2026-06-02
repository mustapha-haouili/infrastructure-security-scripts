<#
.SYNOPSIS
Audits Active Directory Group Policy inventory, links, and common health risks.

.DESCRIPTION
This script inventories Group Policy Objects, maps where they are linked when
possible, and flags common conditions that create operational risk:

- unlinked or stale GPOs
- disabled GPOs or disabled GPO links
- empty GPOs
- duplicate GPO names
- WMI-filtered or security-filtered GPOs
- possible setting overlap on the same target
- AD/SYSVOL version mismatch
- inheritance blocks and enforced links
- legacy keywords in GPO names, descriptions, WMI filters, or report XML

It is audit-only. It does not change Group Policy or Active Directory.

.PARAMETER OutputDirectory
Directory where gpo-health.json, gpos.csv, gpo-links.csv, gpo-findings.csv, and
gpo-review.md are written.

.PARAMETER Domain
Optional DNS domain name to query.

.PARAMETER Server
Optional domain controller to query.

.PARAMETER StaleDays
Number of days since last modification before a GPO is considered stale.
Default: 365

.PARAMETER MaxGposPerTarget
Number of direct enabled GPO links on one target before a review finding is
created. Default: 10

.PARAMETER LegacyKeyword
Keywords used to flag possible legacy policy references. Defaults include old
Windows, Internet Explorer, and old Office terms.

.PARAMETER SkipTargetInventory
Skip OU/domain target inventory through ActiveDirectory and Get-GPInheritance.
The script still reads links from GPO XML reports when available.

.PARAMETER Quiet
Suppress console summary.

.EXAMPLE
.\Get-ADGPOHealthReport.ps1

Audit GPO inventory in the current domain context.

.EXAMPLE
.\Get-ADGPOHealthReport.ps1 -Domain example.com -StaleDays 730

Audit a specific domain and treat GPOs older than 730 days as stale.

.EXAMPLE
.\Get-ADGPOHealthReport.ps1 -SkipTargetInventory -OutputDirectory .\reports\gpo

Audit GPOs without querying OU inheritance targets.
#>

[CmdletBinding()]
param(
    [string]$OutputDirectory = ".\reports\ad-gpo-health-$env:COMPUTERNAME-$(Get-Date -Format 'yyyyMMdd-HHmmss')",
    [string]$Domain = "",
    [string]$Server = "",
    [ValidateRange(30, 3650)]
    [int]$StaleDays = 365,
    [ValidateRange(1, 100)]
    [int]$MaxGposPerTarget = 10,
    [string[]]$LegacyKeyword = @(
        "Windows XP",
        "Windows Vista",
        "Windows 7",
        "Windows Server 2003",
        "Windows Server 2008",
        "Windows Server 2012",
        "Internet Explorer",
        "IE Maintenance",
        "Office 2010",
        "Office 2013",
        "Legacy"
    ),
    [switch]$SkipTargetInventory,
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

function Get-GpoCommandParameters {
    $parameters = @{}
    if ($Domain) {
        $parameters["Domain"] = $Domain
    }
    if ($Server) {
        $parameters["Server"] = $Server
    }
    return $parameters
}

function Get-GpPermissionParameters {
    $parameters = @{}
    if ($Domain) {
        $parameters["DomainName"] = $Domain
    }
    if ($Server) {
        $parameters["Server"] = $Server
    }
    return $parameters
}

function Get-ADCommandParameters {
    $parameters = @{}
    if ($Server) {
        $parameters["Server"] = $Server
    }
    elseif ($Domain) {
        $parameters["Server"] = $Domain
    }
    return $parameters
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

function Write-FailedReport {
    param(
        [Parameter(Mandatory = $true)][string]$JsonPath,
        [Parameter(Mandatory = $true)][string]$Reason
    )

    $report = [ordered]@{
        ReportMetadata = [ordered]@{
            SchemaVersion  = "1.0"
            ReportType     = "ADGPOHealth"
            Status         = "Failed"
            GeneratedAtUtc = (Get-Date).ToUniversalTime().ToString("o")
            ComputerName   = $env:COMPUTERNAME
            RunBy          = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            Domain         = if ($Domain) { $Domain } else { $null }
            Server         = if ($Server) { $Server } else { $null }
            StaleDays      = $StaleDays
        }
        Summary = [ordered]@{
            Status = "Failed"
            Reason = $Reason
        }
        GPOs     = @()
        Links    = @()
        Findings = @()
    }

    $report | ConvertTo-Json -Depth 8 | Out-File -FilePath $JsonPath -Encoding utf8
}

function Import-RequiredModule {
    param([Parameter(Mandatory = $true)][string]$Name)

    $module = Get-Module -ListAvailable -Name $Name | Select-Object -First 1
    if (-not $module) {
        return $false
    }

    Import-Module $Name -ErrorAction Stop
    return $true
}

function Test-OptionalModule {
    param([Parameter(Mandatory = $true)][string]$Name)

    $module = Get-Module -ListAvailable -Name $Name | Select-Object -First 1
    if (-not $module) {
        return $false
    }

    try {
        Import-Module $Name -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

function Get-XmlChildText {
    param(
        [AllowNull()][System.Xml.XmlNode]$Node,
        [Parameter(Mandatory = $true)][string]$ChildName
    )

    if ($null -eq $Node) {
        return $null
    }

    foreach ($child in @($Node.ChildNodes)) {
        if ($child.LocalName -eq $ChildName) {
            return $child.InnerText
        }
    }

    return $null
}

function Get-XmlElementNames {
    param(
        [AllowNull()][xml]$Xml,
        [string]$XPath,
        [string]$Fallback = ""
    )

    if ($null -eq $Xml) {
        return @()
    }

    $names = New-Object System.Collections.Generic.List[string]
    foreach ($node in @($Xml.SelectNodes($XPath))) {
        $name = Get-XmlChildText -Node $node -ChildName "Name"
        if (-not $name -and $node.Attributes["name"]) {
            $name = $node.Attributes["name"].Value
        }
        if (-not $name -and $node.Attributes["type"]) {
            $name = $node.Attributes["type"].Value
        }
        if (-not $name) {
            $name = $Fallback
        }
        if ($name -and $names -notcontains $name) {
            $names.Add($name) | Out-Null
        }
    }

    return @($names.ToArray())
}

function Get-GpoExtensionDataNames {
    param(
        [AllowNull()][xml]$Xml,
        [Parameter(Mandatory = $true)][string]$ScopeName,
        [string]$Fallback = ""
    )

    if ($null -eq $Xml) {
        return @()
    }

    $names = New-Object System.Collections.Generic.List[string]
    $extensionDataPath = "//*[local-name()='$ScopeName']//*[local-name()='ExtensionData']"
    foreach ($node in @($Xml.SelectNodes($extensionDataPath))) {
        $name = Get-XmlChildText -Node $node -ChildName "Name"
        if (-not $name) {
            $extensionNode = @($node.ChildNodes | Where-Object { $_.LocalName -eq "Extension" } | Select-Object -First 1)
            if ($extensionNode.Count -gt 0) {
                $name = Get-XmlChildText -Node $extensionNode[0] -ChildName "Name"
                if (-not $name -and $extensionNode[0].Attributes["type"]) {
                    $name = $extensionNode[0].Attributes["type"].Value
                }
            }
        }
        if (-not $name) {
            $name = $Fallback
        }
        if ($name -and $names -notcontains $name) {
            $names.Add($name) | Out-Null
        }
    }

    if ($names.Count -gt 0) {
        return @($names.ToArray())
    }

    return @(Get-XmlElementNames -Xml $Xml -XPath "//*[local-name()='$ScopeName']//*[local-name()='Extension']" -Fallback $Fallback)
}

function Get-GpoReportXml {
    param(
        [Parameter(Mandatory = $true)][object]$Gpo,
        [Parameter(Mandatory = $true)][hashtable]$GpoParameters
    )

    try {
        $xmlText = Get-GPOReport -Guid $Gpo.Id -ReportType Xml @GpoParameters -ErrorAction Stop
        return [xml]$xmlText
    }
    catch {
        return $null
    }
}

function Get-GpoLinksFromXml {
    param(
        [Parameter(Mandatory = $true)][object]$Gpo,
        [AllowNull()][xml]$Xml
    )

    if ($null -eq $Xml) {
        return @()
    }

    $links = New-Object System.Collections.Generic.List[object]
    foreach ($node in @($Xml.SelectNodes("//*[local-name()='LinksTo']"))) {
        $somName = Get-XmlChildText -Node $node -ChildName "SOMName"
        $somPath = Get-XmlChildText -Node $node -ChildName "SOMPath"
        $enabled = Get-XmlChildText -Node $node -ChildName "Enabled"
        $enforced = Get-XmlChildText -Node $node -ChildName "NoOverride"

        $links.Add([pscustomobject][ordered]@{
                GpoId       = "$($Gpo.Id)"
                DisplayName = $Gpo.DisplayName
                TargetName  = $somName
                TargetPath  = $somPath
                TargetType  = "Unknown"
                LinkType    = "Direct"
                Enabled     = if ($enabled) { "$enabled" } else { $null }
                Enforced    = if ($enforced) { "$enforced" } else { $null }
                LinkOrder   = $null
                Source      = "GPOReportXml"
            }) | Out-Null
    }

    return @($links.ToArray())
}

function Get-GpoExtensionSummary {
    param([AllowNull()][xml]$Xml)

    $computerExtensions = @(Get-GpoExtensionDataNames -Xml $Xml -ScopeName "Computer" -Fallback "ComputerExtension")
    $userExtensions = @(Get-GpoExtensionDataNames -Xml $Xml -ScopeName "User" -Fallback "UserExtension")
    $allExtensions = @($computerExtensions + $userExtensions | Sort-Object -Unique)

    [ordered]@{
        ComputerExtensions = $computerExtensions
        UserExtensions     = $userExtensions
        AllExtensions      = $allExtensions
        ExtensionCount     = $allExtensions.Count
    }
}

function Get-SideVersion {
    param(
        [AllowNull()][object]$Side,
        [string]$Name
    )

    $value = Get-ObjectValue -InputObject $Side -Name $Name
    if ($null -eq $value) {
        return $null
    }

    try {
        return [int]$value
    }
    catch {
        return $null
    }
}

function Get-WmiFilterName {
    param([AllowNull()][object]$Gpo)

    $filter = Get-ObjectValue -InputObject $Gpo -Name "WmiFilter"
    if ($null -eq $filter) {
        return $null
    }

    $name = Get-ObjectValue -InputObject $filter -Name "Name"
    if ($name) {
        return "$name"
    }

    return "$filter"
}

function Get-GpoPermissions {
    param(
        [Parameter(Mandatory = $true)][object]$Gpo,
        [Parameter(Mandatory = $true)][hashtable]$PermissionParameters
    )

    try {
        return [pscustomobject][ordered]@{
            Succeeded   = $true
            Permissions = @(Get-GPPermission -Guid $Gpo.Id -All @PermissionParameters -ErrorAction Stop)
            Error       = ""
        }
    }
    catch {
        return [pscustomobject][ordered]@{
            Succeeded   = $false
            Permissions = @()
            Error       = $_.Exception.Message
        }
    }
}

function Convert-GpoPermissions {
    param(
        [AllowEmptyCollection()]
        [object[]]$Permissions
    )

    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($permission in @($Permissions)) {
        $trustee = Get-ObjectValue -InputObject $permission -Name "Trustee"
        $trusteeName = if ($trustee) {
            $name = Get-ObjectValue -InputObject $trustee -Name "Name"
            if ($name) { "$name" } else { "$trustee" }
        } else {
            "$permission"
        }
        $permissionValue = Get-ObjectValue -InputObject $permission -Name "Permission"
        $principalType = Get-ObjectValue -InputObject $permission -Name "TrusteeType"
        $principalSid = if ($trustee) {
            $sid = Get-ObjectValue -InputObject $trustee -Name "Sid"
            if (-not $sid) {
                $sid = Get-ObjectValue -InputObject $trustee -Name "SID"
            }
            if ($sid) { "$sid" } else { "" }
        }
        else {
            ""
        }

        $rows.Add([pscustomobject][ordered]@{
            PrincipalName = $trusteeName
            PrincipalType = if ($principalType) { "$principalType" } else { "" }
            PrincipalSid  = $principalSid
            Permission    = if ($permissionValue) { "$permissionValue" } else { "" }
        }) | Out-Null
    }

    return @($rows.ToArray())
}

function Test-LegacyKeyword {
    param(
        [AllowNull()][string]$Text,
        [string[]]$Keywords
    )

    foreach ($keyword in @($Keywords)) {
        if ($Text -and $Text.IndexOf($keyword, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            return $keyword
        }
    }

    return $null
}

function Test-DefaultApplyPrincipal {
    param([object[]]$ApplyPermissions)

    foreach ($permission in @($ApplyPermissions)) {
        $principal = "$($permission.PrincipalName)"
        $sid = "$($permission.PrincipalSid)"

        if ($sid -in @("S-1-1-0", "S-1-5-11") -or $sid -match "-515$") {
            return $true
        }

        if ($principal -match "(^|\\)(Authenticated Users|Domain Computers|Everyone|Jeder|Alle|Authentifizierte Benutzer|Domänencomputer|Domaenencomputer)$") {
            return $true
        }
    }

    return $false
}

function Get-FindingGuidance {
    param(
        [Parameter(Mandatory = $true)][string]$FindingType,
        [Parameter(Mandatory = $true)][string]$Severity
    )

    $defaultPriority = switch ($Severity) {
        "Critical" { "P1 - Critical" }
        "High" { "P2 - High" }
        "Medium" { "P3 - Review" }
        "Low" { "P4 - Hygiene" }
        default { "P5 - Document" }
    }

    $guidance = [ordered]@{
        ActionPriority   = $defaultPriority
        AdminAction      = "Review the evidence, confirm owner and scope, then decide Keep, Change, Exception, or Remove."
        ChangeRisk       = "Review required"
        VerificationStep = "Use Group Policy Management Console, Group Policy Results, or gpresult to confirm effective policy before changing anything."
    }

    switch ($FindingType) {
        "AdSysvolVersionMismatch" {
            $guidance.ActionPriority = "P1 - Critical"
            $guidance.AdminAction = "Fix or investigate SYSVOL/DFSR replication before relying on this GPO."
            $guidance.ChangeRisk = "High"
            $guidance.VerificationStep = "Check DFSR/SYSVOL replication health and compare AD/SYSVOL GPO versions."
        }
        "GPOReportReadFailed" {
            $guidance.ActionPriority = "P2 - High"
            $guidance.AdminAction = "Fix report access or GPO health first; the script could not inspect this policy."
            $guidance.ChangeRisk = "Medium"
            $guidance.VerificationStep = "Open the GPO in GPMC and confirm delegation/SYSVOL access."
        }
        "GpoPermissionReadFailed" {
            $guidance.ActionPriority = "P2 - High"
            $guidance.AdminAction = "Fix permission visibility for this report account before trusting filtering results."
            $guidance.ChangeRisk = "Medium"
            $guidance.VerificationStep = "Check GPO Delegation and Security Filtering in GPMC."
        }
        "NoApplyPermission" {
            $guidance.ActionPriority = "P2 - High"
            $guidance.AdminAction = "Confirm whether the GPO is intentionally unused. If not, repair security filtering."
            $guidance.ChangeRisk = "Medium"
            $guidance.VerificationStep = "Check GPMC Scope tab and confirm an Apply Group Policy principal exists."
        }
        "UnlinkedGpo" {
            $guidance.ActionPriority = "P3 - Cleanup candidate"
            $guidance.AdminAction = "Do not delete immediately. Backup/export the GPO, confirm no owner or required future use, then remove through change control."
            $guidance.ChangeRisk = "Low to Medium"
            $guidance.VerificationStep = "Confirm there are no links in GPMC and no documented dependency."
        }
        "StaleGpo" {
            $guidance.ActionPriority = "P3 - Review"
            $guidance.AdminAction = "Review owner, target OUs, and settings. Keep if still required; otherwise plan consolidation or retirement."
            $guidance.ChangeRisk = "Medium"
            $guidance.VerificationStep = "Run Group Policy Results on affected computers/users and compare with current baseline."
        }
        "LegacyKeyword" {
            $guidance.ActionPriority = "P3 - Modernize"
            $guidance.AdminAction = "Review for old OS, browser, or Office targeting. Replace with a modern supported baseline when needed."
            $guidance.ChangeRisk = "Medium"
            $guidance.VerificationStep = "Open settings in GPMC and confirm whether they still apply to supported systems."
        }
        "PotentialSettingOverlap" {
            $guidance.ActionPriority = "P3 - Conflict review"
            $guidance.AdminAction = "Review link order and actual setting values. Consolidate or document which GPO is authoritative."
            $guidance.ChangeRisk = "Medium"
            $guidance.VerificationStep = "Use Group Policy Modeling/Results or gpresult /h on a target in this OU."
        }
        "ManyGpoLinksOnTarget" {
            $guidance.ActionPriority = "P3 - Simplify"
            $guidance.AdminAction = "Review direct links and link order. Consolidate policies where possible to reduce conflict and admin effort."
            $guidance.ChangeRisk = "Medium"
            $guidance.VerificationStep = "Check GPMC Linked Group Policy Objects order for the target."
        }
        "EmptyGpo" {
            $guidance.ActionPriority = "P4 - Cleanup candidate"
            $guidance.AdminAction = "Backup/export and remove only after confirming it is not a template or placeholder."
            $guidance.ChangeRisk = "Low"
            $guidance.VerificationStep = "Open the GPO and confirm no Computer or User settings are configured."
        }
        "DisabledGpo" {
            $guidance.ActionPriority = "P4 - Hygiene"
            $guidance.AdminAction = "Confirm whether this is a template, disabled policy, or stale object. Remove only after backup and approval."
            $guidance.ChangeRisk = "Low"
            $guidance.VerificationStep = "Check GPO Status and owner notes."
        }
        "DisabledGpoLink" {
            $guidance.ActionPriority = "P4 - Hygiene"
            $guidance.AdminAction = "Confirm whether the disabled link should be removed or re-enabled."
            $guidance.ChangeRisk = "Low"
            $guidance.VerificationStep = "Review the linked target in GPMC."
        }
        "SecurityFilteredGpo" {
            $guidance.ActionPriority = "P5 - Document"
            $guidance.AdminAction = "No immediate change. Confirm the filtered group or computer account is still owned and maintained."
            $guidance.ChangeRisk = "Low"
            $guidance.VerificationStep = "Check Security Filtering and group membership."
        }
        "WmiFilteredGpo" {
            $guidance.ActionPriority = "P5 - Document"
            $guidance.AdminAction = "No immediate change. Confirm the WMI filter still matches supported systems."
            $guidance.ChangeRisk = "Low"
            $guidance.VerificationStep = "Review the WMI filter query and test against current workstation/server versions."
        }
        "InheritanceBlocked" {
            $guidance.ActionPriority = "P5 - Document"
            $guidance.AdminAction = "Confirm baseline policies still reach this OU through direct or enforced links."
            $guidance.ChangeRisk = "Low"
            $guidance.VerificationStep = "Check effective policy on representative computers/users."
        }
        "EnforcedGpoLink" {
            $guidance.ActionPriority = "P5 - Document"
            $guidance.AdminAction = "Confirm enforcement is still required and documented."
            $guidance.ChangeRisk = "Low"
            $guidance.VerificationStep = "Review link inheritance and lower-level OU policy needs."
        }
    }

    return $guidance
}

function New-Finding {
    param(
        [Parameter(Mandatory = $true)][string]$Severity,
        [Parameter(Mandatory = $true)][string]$FindingType,
        [string]$GpoId = "",
        [string]$GpoName = "",
        [string]$TargetPath = "",
        [Parameter(Mandatory = $true)][string]$Title,
        [Parameter(Mandatory = $true)][string]$Evidence,
        [Parameter(Mandatory = $true)][string]$Recommendation
    )

    $guidance = Get-FindingGuidance -FindingType $FindingType -Severity $Severity

    [pscustomobject][ordered]@{
        Severity         = $Severity
        ActionPriority   = $guidance.ActionPriority
        FindingType      = $FindingType
        GpoId            = $GpoId
        GpoName          = $GpoName
        TargetPath       = $TargetPath
        Title            = $Title
        Evidence         = $Evidence
        AdminAction      = $guidance.AdminAction
        ChangeRisk       = $guidance.ChangeRisk
        VerificationStep = $guidance.VerificationStep
        Recommendation   = $Recommendation
    }
}

function Get-CountByField {
    param(
        [AllowEmptyCollection()]
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

function Get-GpoLinkTargetInventory {
    param(
        [Parameter(Mandatory = $true)][hashtable]$GpParameters,
        [Parameter(Mandatory = $true)][hashtable]$AdParameters,
        [bool]$HasActiveDirectoryModule
    )

    $result = [ordered]@{
        Targets = @()
        Links   = @()
        Errors  = @()
    }

    if (-not $HasActiveDirectoryModule -or $SkipTargetInventory) {
        return $result
    }

    try {
        $domainInfo = Get-ADDomain @AdParameters -ErrorAction Stop
    }
    catch {
        $result["Errors"] = @($result["Errors"]) + "Could not query AD domain: $($_.Exception.Message)"
        return $result
    }

    $targets = New-Object System.Collections.Generic.List[object]
    $targets.Add([pscustomobject][ordered]@{
            Name              = $domainInfo.DNSRoot
            DistinguishedName = $domainInfo.DistinguishedName
            TargetType        = "Domain"
        }) | Out-Null

    try {
        $ous = @(Get-ADOrganizationalUnit -Filter * -Properties gPOptions @AdParameters -ErrorAction Stop)
        foreach ($ou in $ous) {
            $targets.Add([pscustomobject][ordered]@{
                    Name              = $ou.Name
                    DistinguishedName = $ou.DistinguishedName
                    TargetType        = "OU"
                }) | Out-Null
        }
    }
    catch {
        $result["Errors"] = @($result["Errors"]) + "Could not query OUs: $($_.Exception.Message)"
    }

    $targetRows = New-Object System.Collections.Generic.List[object]
    $linkRows = New-Object System.Collections.Generic.List[object]
    foreach ($target in @($targets.ToArray())) {
        try {
            $inheritance = Get-GPInheritance -Target $target.DistinguishedName @GpParameters -ErrorAction Stop
            $blocked = [bool](Get-ObjectValue -InputObject $inheritance -Name "GpoInheritanceBlocked")
            $directLinks = @(Get-ObjectValue -InputObject $inheritance -Name "GpoLinks")
            $inheritedLinks = @(Get-ObjectValue -InputObject $inheritance -Name "InheritedGpoLinks")

            $targetRows.Add([pscustomobject][ordered]@{
                    TargetName            = $target.Name
                    TargetPath            = $target.DistinguishedName
                    TargetType            = $target.TargetType
                    InheritanceBlocked    = $blocked
                    DirectLinkCount       = $directLinks.Count
                    InheritedLinkCount    = $inheritedLinks.Count
                    TotalEffectiveGpoLinks = $directLinks.Count + $inheritedLinks.Count
                }) | Out-Null

            foreach ($link in $directLinks) {
                $linkRows.Add((Convert-GpInheritanceLink -Link $link -Target $target -LinkType "Direct")) | Out-Null
            }
            foreach ($link in $inheritedLinks) {
                $linkRows.Add((Convert-GpInheritanceLink -Link $link -Target $target -LinkType "Inherited")) | Out-Null
            }
        }
        catch {
            $result["Errors"] = @($result["Errors"]) + "Could not read GP inheritance for $($target.DistinguishedName): $($_.Exception.Message)"
        }
    }

    $result["Targets"] = @($targetRows.ToArray())
    $result["Links"] = @($linkRows.ToArray())
    return $result
}

function Convert-GpInheritanceLink {
    param(
        [Parameter(Mandatory = $true)][object]$Link,
        [Parameter(Mandatory = $true)][object]$Target,
        [Parameter(Mandatory = $true)][string]$LinkType
    )

    $gpoId = Get-ObjectValue -InputObject $Link -Name "GpoId"
    if (-not $gpoId) {
        $gpoId = Get-ObjectValue -InputObject $Link -Name "Guid"
    }
    $displayName = Get-ObjectValue -InputObject $Link -Name "DisplayName"
    $enabled = Get-ObjectValue -InputObject $Link -Name "Enabled"
    $enforced = Get-ObjectValue -InputObject $Link -Name "Enforced"
    $order = Get-ObjectValue -InputObject $Link -Name "Order"

    [pscustomobject][ordered]@{
        GpoId       = "$gpoId"
        DisplayName = "$displayName"
        TargetName  = $Target.Name
        TargetPath  = $Target.DistinguishedName
        TargetType  = $Target.TargetType
        LinkType    = $LinkType
        Enabled     = if ($null -ne $enabled) { "$enabled" } else { $null }
        Enforced    = if ($null -ne $enforced) { "$enforced" } else { $null }
        LinkOrder   = $order
        Source      = "GetGPInheritance"
    }
}

function Add-FindingRow {
    param(
        [Parameter(Mandatory = $true)][object]$Findings,
        [Parameter(Mandatory = $true)][object]$Finding
    )

    if (-not $Findings.PSObject.Methods["Add"]) {
        throw "Finding collection does not support Add()."
    }

    $Findings.Add($Finding) | Out-Null
}

function Add-MarkdownFindingTable {
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

    Add-MarkdownLine -Lines $Lines -Text "| Priority | Severity | Type | GPO | Target | Evidence | Admin action | Verification |"
    Add-MarkdownLine -Lines $Lines -Text "|---|---|---|---|---|---|---|---|"
    foreach ($row in @($Rows | Select-Object -First $Limit)) {
        Add-MarkdownLine -Lines $Lines -Text ("| {0} | {1} | {2} | {3} | {4} | {5} | {6} | {7} |" -f `
                (ConvertTo-MarkdownSafeText $row.ActionPriority),
                (ConvertTo-MarkdownSafeText $row.Severity),
            (ConvertTo-MarkdownSafeText $row.FindingType),
            (ConvertTo-MarkdownSafeText $row.GpoName),
            (ConvertTo-MarkdownSafeText $row.TargetPath),
            (ConvertTo-MarkdownSafeText $row.Evidence),
            (ConvertTo-MarkdownSafeText $row.AdminAction),
            (ConvertTo-MarkdownSafeText $row.VerificationStep))
    }

    if ($Rows.Count -gt $Limit) {
        Add-MarkdownLine -Lines $Lines
        Add-MarkdownLine -Lines $Lines -Text "Showing first $Limit of $($Rows.Count). See CSV/JSON for the full list."
    }

    Add-MarkdownLine -Lines $Lines
}

function Get-PrioritySortValue {
    param([AllowNull()][object]$Value)

    $text = "$Value"
    if ($text -match "^P(\d+)") {
        return [int]$Matches[1]
    }
    return 9
}

function Add-MarkdownAdminActionPlan {
    param(
        [Parameter(Mandatory = $true)][object]$Lines,
        [Parameter(Mandatory = $true)][object[]]$Findings,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Summary
    )

    Add-MarkdownLine -Lines $Lines -Text "## Admin Action Plan"
    Add-MarkdownLine -Lines $Lines

    if ($Summary.CriticalFindings -eq 0 -and $Summary.HighFindings -eq 0) {
        Add-MarkdownLine -Lines $Lines -Text "No Critical or High GPO health findings were detected in this run. Treat the remaining items as cleanup, modernization, and conflict-review work, not emergency changes."
    }
    else {
        Add-MarkdownLine -Lines $Lines -Text "Critical or High findings exist. Review those before cleanup work and do not make broad GPO changes until impact is confirmed."
    }
    Add-MarkdownLine -Lines $Lines
    Add-MarkdownLine -Lines $Lines -Text "Do not delete or edit a GPO only because it appears in this report. For each item, confirm owner, effective scope, business purpose, backup/export status, and rollback plan."
    Add-MarkdownLine -Lines $Lines

    $priorityGroups = @($Findings | Group-Object ActionPriority | Sort-Object @{ Expression = { Get-PrioritySortValue -Value $_.Name } }, Name)
    if ($priorityGroups.Count -gt 0) {
        Add-MarkdownLine -Lines $Lines -Text "| Priority | Count | What the admin should do |"
        Add-MarkdownLine -Lines $Lines -Text "|---|---:|---|"
        foreach ($group in $priorityGroups) {
            $sample = @($group.Group | Select-Object -First 1)[0]
            Add-MarkdownLine -Lines $Lines -Text ("| {0} | {1} | {2} |" -f `
                    (ConvertTo-MarkdownSafeText $group.Name),
                $group.Count,
                (ConvertTo-MarkdownSafeText $sample.AdminAction))
        }
        Add-MarkdownLine -Lines $Lines
    }

    $reviewRows = @($Findings | Sort-Object @{ Expression = { Get-PrioritySortValue -Value $_.ActionPriority } }, FindingType, GpoName, TargetPath | Select-Object -First 12)
    if ($reviewRows.Count -gt 0) {
        Add-MarkdownLine -Lines $Lines -Text "### First Items To Review"
        Add-MarkdownLine -Lines $Lines
        Add-MarkdownLine -Lines $Lines -Text "| Priority | Severity | Type | GPO / Target | Why | Next admin action |"
        Add-MarkdownLine -Lines $Lines -Text "|---|---|---|---|---|---|"
        foreach ($row in $reviewRows) {
            $objectName = if ($row.GpoName) { $row.GpoName } else { $row.TargetPath }
            Add-MarkdownLine -Lines $Lines -Text ("| {0} | {1} | {2} | {3} | {4} | {5} |" -f `
                    (ConvertTo-MarkdownSafeText $row.ActionPriority),
                (ConvertTo-MarkdownSafeText $row.Severity),
                (ConvertTo-MarkdownSafeText $row.FindingType),
                (ConvertTo-MarkdownSafeText $objectName),
                (ConvertTo-MarkdownSafeText $row.Evidence),
                (ConvertTo-MarkdownSafeText $row.AdminAction))
        }
        Add-MarkdownLine -Lines $Lines
    }
}

function Write-MarkdownReport {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Report
    )

    $metadata = $Report["ReportMetadata"]
    $summary = $Report["Summary"]
    $findings = @($Report["Findings"])
    $gpos = @($Report["GPOs"])
    $targets = @($Report["Targets"])
    $lines = New-Object System.Collections.Generic.List[string]

    Add-MarkdownLine -Lines $lines -Text "# AD GPO Health Review"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "Generated UTC: ``$($metadata.GeneratedAtUtc)``"
    Add-MarkdownLine -Lines $lines -Text "Computer: ``$($metadata.ComputerName)``"
    $domainText = if ($metadata.Domain) { $metadata.Domain } else { "Current logon domain" }
    Add-MarkdownLine -Lines $lines -Text "Domain: ``$domainText``"
    Add-MarkdownLine -Lines $lines

    Add-MarkdownLine -Lines $lines -Text "## Summary"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "| Metric | Count |"
    Add-MarkdownLine -Lines $lines -Text "|---|---:|"
    foreach ($metric in @("TotalGpos", "LinkedGpos", "UnlinkedGpos", "StaleGpos", "DisabledGpos", "EmptyGpos", "WmiFilteredGpos", "SecurityFilteredGpos", "VersionMismatchGpos", "TotalFindings", "CriticalFindings", "HighFindings", "MediumFindings", "LowFindings", "InfoFindings")) {
        Add-MarkdownLine -Lines $lines -Text ("| {0} | {1} |" -f $metric, $summary.$metric)
    }
    Add-MarkdownLine -Lines $lines

    Add-MarkdownAdminActionPlan -Lines $lines -Findings $findings -Summary $summary

    Add-MarkdownLine -Lines $lines -Text "## Findings"
    Add-MarkdownLine -Lines $lines
    foreach ($severity in @("Critical", "High", "Medium", "Low", "Info")) {
        $severityRows = @($findings | Where-Object { $_.Severity -eq $severity })
        Add-MarkdownLine -Lines $lines -Text "### $severity"
        Add-MarkdownLine -Lines $lines
        Add-MarkdownFindingTable -Lines $lines -Rows $severityRows -Limit 40
    }

    Add-MarkdownLine -Lines $lines -Text "## Unlinked Or Stale GPOs"
    Add-MarkdownLine -Lines $lines
    $reviewGpos = @($gpos | Where-Object { $_.DirectLinkCount -eq 0 -or $_.IsStale } | Sort-Object DirectLinkCount, ModificationTimeUtc)
    if ($reviewGpos.Count -eq 0) {
        Add-MarkdownLine -Lines $lines -Text "None."
    }
    else {
        Add-MarkdownLine -Lines $lines -Text "| GPO | Linked | Stale | Modified UTC | Status |"
        Add-MarkdownLine -Lines $lines -Text "|---|---:|---:|---|---|"
        foreach ($gpo in @($reviewGpos | Select-Object -First 50)) {
            Add-MarkdownLine -Lines $lines -Text ("| {0} | {1} | {2} | {3} | {4} |" -f `
                    (ConvertTo-MarkdownSafeText $gpo.DisplayName),
                $gpo.DirectLinkCount,
                $gpo.IsStale,
                (ConvertTo-MarkdownSafeText $gpo.ModificationTimeUtc),
                (ConvertTo-MarkdownSafeText $gpo.GpoStatus))
        }
    }
    Add-MarkdownLine -Lines $lines

    Add-MarkdownLine -Lines $lines -Text "## Targets With Many Direct GPO Links"
    Add-MarkdownLine -Lines $lines
    $busyTargets = @($targets | Where-Object { $_.DirectLinkCount -ge $MaxGposPerTarget } | Sort-Object DirectLinkCount -Descending)
    if ($busyTargets.Count -eq 0) {
        Add-MarkdownLine -Lines $lines -Text "None."
    }
    else {
        Add-MarkdownLine -Lines $lines -Text "| Target | Type | Direct links | Inherited links | Inheritance blocked |"
        Add-MarkdownLine -Lines $lines -Text "|---|---|---:|---:|---:|"
        foreach ($target in @($busyTargets | Select-Object -First 25)) {
            Add-MarkdownLine -Lines $lines -Text ("| {0} | {1} | {2} | {3} | {4} |" -f `
                    (ConvertTo-MarkdownSafeText $target.TargetPath),
                (ConvertTo-MarkdownSafeText $target.TargetType),
                $target.DirectLinkCount,
                $target.InheritedLinkCount,
                $target.InheritanceBlocked)
        }
    }
    Add-MarkdownLine -Lines $lines

    Add-MarkdownLine -Lines $lines -Text "## Review Notes"
    Add-MarkdownLine -Lines $lines
    foreach ($note in @($summary.Notes)) {
        Add-MarkdownLine -Lines $lines -Text "- $note"
    }

    $lines | Out-File -FilePath $Path -Encoding utf8
}

New-Directory -Path $OutputDirectory
$resolvedOutputDirectory = (Resolve-Path -Path $OutputDirectory).Path
$jsonPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "gpo-health.json"
$gpoCsvPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "gpos.csv"
$linksCsvPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "gpo-links.csv"
$findingsCsvPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "gpo-findings.csv"
$markdownPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "gpo-review.md"

if (-not (Import-RequiredModule -Name "GroupPolicy")) {
    $reason = "GroupPolicy PowerShell module was not found. Install RSAT Group Policy Management tools or run from a domain management host."
    Write-FailedReport -JsonPath $jsonPath -Reason $reason
    throw $reason
}

$hasActiveDirectoryModule = Test-OptionalModule -Name "ActiveDirectory"
$gpoParameters = Get-GpoCommandParameters
$permissionParameters = Get-GpPermissionParameters
$adParameters = Get-ADCommandParameters
$generatedAtUtc = (Get-Date).ToUniversalTime().ToString("o")
$now = Get-Date
$staleCutoff = $now.AddDays(-1 * $StaleDays)

try {
    $rawGpos = @(Get-GPO -All @gpoParameters -ErrorAction Stop)
}
catch {
    $reason = "GPO query failed: $($_.Exception.Message)"
    Write-FailedReport -JsonPath $jsonPath -Reason $reason
    throw $reason
}

$targetInventory = Get-GpoLinkTargetInventory -GpParameters $gpoParameters -AdParameters $adParameters -HasActiveDirectoryModule $hasActiveDirectoryModule
$links = New-Object System.Collections.Generic.List[object]
foreach ($link in @($targetInventory["Links"])) {
    $links.Add($link) | Out-Null
}

$gpoRows = New-Object System.Collections.Generic.List[object]
$findings = New-Object System.Collections.Generic.List[object]
$xmlLinkRows = New-Object System.Collections.Generic.List[object]
$reportErrors = New-Object System.Collections.Generic.List[string]
foreach ($errorMessage in @($targetInventory["Errors"])) {
    $reportErrors.Add($errorMessage) | Out-Null
}

$duplicateNameGroups = @($rawGpos | Group-Object DisplayName | Where-Object { $_.Count -gt 1 })
$duplicateNameSet = @{}
foreach ($group in $duplicateNameGroups) {
    $duplicateNameSet[$group.Name] = $group.Count
}

foreach ($gpo in $rawGpos) {
    $xml = Get-GpoReportXml -Gpo $gpo -GpoParameters $gpoParameters
    if ($null -eq $xml) {
        Add-FindingRow -Findings $findings -Finding (New-Finding -Severity "High" -FindingType "GPOReportReadFailed" -GpoId "$($gpo.Id)" -GpoName $gpo.DisplayName -Title "Could not read GPO XML report" -Evidence "Get-GPOReport failed for this GPO." -Recommendation "Confirm GPMC permissions and SYSVOL/GPO health.")
    }

    $xmlLinks = @(Get-GpoLinksFromXml -Gpo $gpo -Xml $xml)
    foreach ($link in $xmlLinks) {
        $xmlLinkRows.Add($link) | Out-Null
    }

    $extensionSummary = Get-GpoExtensionSummary -Xml $xml
    $extensionNames = @($extensionSummary["AllExtensions"])
    $extensionText = if ($extensionNames.Count -gt 0) { $extensionNames -join "; " } else { "" }
    $permissionResult = Get-GpoPermissions -Gpo $gpo -PermissionParameters $permissionParameters
    $permissions = @(Convert-GpoPermissions -Permissions $permissionResult.Permissions)
    $applyPermissions = @($permissions | Where-Object { $_.Permission -match "Apply|GpoApply" })
    $applyPrincipals = @($applyPermissions | ForEach-Object { $_.PrincipalName } | Where-Object { $_ } | Sort-Object -Unique)
    $applyPrincipalSids = @($applyPermissions | ForEach-Object { $_.PrincipalSid } | Where-Object { $_ } | Sort-Object -Unique)
    $hasDefaultApplyPrincipal = Test-DefaultApplyPrincipal -ApplyPermissions $applyPermissions
    $isSecurityFiltered = $applyPrincipals.Count -gt 0 -and -not $hasDefaultApplyPrincipal

    $userSide = Get-ObjectValue -InputObject $gpo -Name "User"
    $computerSide = Get-ObjectValue -InputObject $gpo -Name "Computer"
    $userAdVersion = Get-SideVersion -Side $userSide -Name "DSVersion"
    $userSysvolVersion = Get-SideVersion -Side $userSide -Name "SysvolVersion"
    $computerAdVersion = Get-SideVersion -Side $computerSide -Name "DSVersion"
    $computerSysvolVersion = Get-SideVersion -Side $computerSide -Name "SysvolVersion"
    $versionMismatch = ($null -ne $userAdVersion -and $null -ne $userSysvolVersion -and $userAdVersion -ne $userSysvolVersion) -or
    ($null -ne $computerAdVersion -and $null -ne $computerSysvolVersion -and $computerAdVersion -ne $computerSysvolVersion)

    $directLinksForGpo = @($targetInventory["Links"] | Where-Object { "$($_.GpoId)" -eq "$($gpo.Id)" -and $_.LinkType -eq "Direct" })
    if ($directLinksForGpo.Count -eq 0) {
        $directLinksForGpo = @($xmlLinks)
    }

    foreach ($link in $xmlLinks) {
        if (@($links | Where-Object { $_.GpoId -eq $link.GpoId -and $_.TargetPath -eq $link.TargetPath -and $_.LinkType -eq $link.LinkType }).Count -eq 0) {
            $links.Add($link) | Out-Null
        }
    }

    $wmiFilterName = Get-WmiFilterName -Gpo $gpo
    $gpoDescription = Get-ObjectValue -InputObject $gpo -Name "Description"
    $gpoReportText = if ($xml) { $xml.OuterXml } else { "" }
    $legacyScanText = @($gpo.DisplayName, $gpoDescription, $wmiFilterName, $gpoReportText) -join " "
    $legacyKeywordHit = Test-LegacyKeyword -Text $legacyScanText -Keywords $LegacyKeyword
    $gpoStatus = "$($gpo.GpoStatus)"
    $isDisabled = $gpoStatus -eq "AllSettingsDisabled"
    $isEmpty = $extensionNames.Count -eq 0
    $isStale = ([datetime]$gpo.ModificationTime -le $staleCutoff)
    $isDuplicateName = $duplicateNameSet.ContainsKey($gpo.DisplayName)

    $gpoRow = [pscustomobject][ordered]@{
        DisplayName           = $gpo.DisplayName
        GpoId                 = "$($gpo.Id)"
        DomainName            = $gpo.DomainName
        Owner                 = $gpo.Owner
        GpoStatus             = $gpoStatus
        CreationTimeUtc       = Format-DateTimeUtc -Value $gpo.CreationTime
        ModificationTimeUtc   = Format-DateTimeUtc -Value $gpo.ModificationTime
        AgeDaysSinceModified  = [int](New-TimeSpan -Start ([datetime]$gpo.ModificationTime) -End $now).TotalDays
        IsStale               = [bool]$isStale
        IsDisabled            = [bool]$isDisabled
        IsEmpty               = [bool]$isEmpty
        IsDuplicateName       = [bool]$isDuplicateName
        WmiFilterName         = $wmiFilterName
        HasWmiFilter          = [bool]$wmiFilterName
        DirectLinkCount       = $directLinksForGpo.Count
        PermissionReadSucceeded = [bool]$permissionResult.Succeeded
        PermissionReadError   = $permissionResult.Error
        ApplyPrincipalCount   = $applyPrincipals.Count
        ApplyPrincipals       = @($applyPrincipals)
        ApplyPrincipalsText   = if ($applyPrincipals.Count -gt 0) { $applyPrincipals -join "; " } else { "" }
        ApplyPrincipalSids    = @($applyPrincipalSids)
        ApplyPrincipalSidsText = if ($applyPrincipalSids.Count -gt 0) { $applyPrincipalSids -join "; " } else { "" }
        IsSecurityFiltered    = [bool]$isSecurityFiltered
        ExtensionCount        = $extensionNames.Count
        Extensions            = @($extensionNames)
        ExtensionsText        = $extensionText
        UserAdVersion         = $userAdVersion
        UserSysvolVersion     = $userSysvolVersion
        ComputerAdVersion     = $computerAdVersion
        ComputerSysvolVersion = $computerSysvolVersion
        VersionMismatch       = [bool]$versionMismatch
        LegacyKeywordHit      = $legacyKeywordHit
        Description           = $gpoDescription
    }
    $gpoRows.Add($gpoRow) | Out-Null

    if ($isDuplicateName) {
        Add-FindingRow -Findings $findings -Finding (New-Finding -Severity "Medium" -FindingType "DuplicateGpoName" -GpoId "$($gpo.Id)" -GpoName $gpo.DisplayName -Title "Duplicate GPO display name" -Evidence "There are $($duplicateNameSet[$gpo.DisplayName]) GPOs named '$($gpo.DisplayName)'." -Recommendation "Rename or document duplicates so admins know which policy is authoritative.")
    }
    if ($directLinksForGpo.Count -eq 0) {
        Add-FindingRow -Findings $findings -Finding (New-Finding -Severity "Medium" -FindingType "UnlinkedGpo" -GpoId "$($gpo.Id)" -GpoName $gpo.DisplayName -Title "GPO has no direct links" -Evidence "No direct links were found through inheritance inventory or GPO report XML." -Recommendation "Confirm whether this is a legacy policy. Backup/export, document owner, then remove only through change control.")
    }
    if ($isStale) {
        Add-FindingRow -Findings $findings -Finding (New-Finding -Severity "Medium" -FindingType "StaleGpo" -GpoId "$($gpo.Id)" -GpoName $gpo.DisplayName -Title "GPO has not changed recently" -Evidence "Last modified $($gpoRow.AgeDaysSinceModified) days ago. Threshold is $StaleDays days." -Recommendation "Review owner, linked targets, and whether settings still match the supported OS/server baseline.")
    }
    if ($isDisabled) {
        Add-FindingRow -Findings $findings -Finding (New-Finding -Severity "Low" -FindingType "DisabledGpo" -GpoId "$($gpo.Id)" -GpoName $gpo.DisplayName -Title "All GPO settings are disabled" -Evidence "GpoStatus is AllSettingsDisabled." -Recommendation "Confirm whether this GPO should be removed, retained as a template, or re-enabled through change control.")
    }
    if ($isEmpty) {
        Add-FindingRow -Findings $findings -Finding (New-Finding -Severity "Low" -FindingType "EmptyGpo" -GpoId "$($gpo.Id)" -GpoName $gpo.DisplayName -Title "No configured policy extensions detected" -Evidence "No User or Computer policy extensions were found in the XML report." -Recommendation "Confirm whether this is a placeholder/template. Remove stale empty policies after backup and approval.")
    }
    if ($wmiFilterName) {
        Add-FindingRow -Findings $findings -Finding (New-Finding -Severity "Info" -FindingType "WmiFilteredGpo" -GpoId "$($gpo.Id)" -GpoName $gpo.DisplayName -Title "GPO uses a WMI filter" -Evidence "WMI filter: $wmiFilterName" -Recommendation "Confirm the WMI query still matches supported workstation/server versions and does not exclude intended devices.")
    }
    if (-not $permissionResult.Succeeded) {
        Add-FindingRow -Findings $findings -Finding (New-Finding -Severity "High" -FindingType "GpoPermissionReadFailed" -GpoId "$($gpo.Id)" -GpoName $gpo.DisplayName -Title "Could not read GPO permissions" -Evidence $permissionResult.Error -Recommendation "Confirm the account running the report has permission to read GPO delegation and security filtering.")
    }
    elseif ($applyPrincipals.Count -eq 0) {
        Add-FindingRow -Findings $findings -Finding (New-Finding -Severity "High" -FindingType "NoApplyPermission" -GpoId "$($gpo.Id)" -GpoName $gpo.DisplayName -Title "No Apply Group Policy permission detected" -Evidence "Get-GPPermission did not return an Apply/GpoApply principal." -Recommendation "Confirm security filtering. A GPO with no apply principal may not apply to any device or user.")
    }
    elseif ($isSecurityFiltered) {
        Add-FindingRow -Findings $findings -Finding (New-Finding -Severity "Info" -FindingType "SecurityFilteredGpo" -GpoId "$($gpo.Id)" -GpoName $gpo.DisplayName -Title "GPO is security-filtered" -Evidence "Apply principals: $($applyPrincipals -join ', ')" -Recommendation "Confirm the filtered group is still maintained and includes the intended computers/users.")
    }
    if ($versionMismatch) {
        Add-FindingRow -Findings $findings -Finding (New-Finding -Severity "High" -FindingType "AdSysvolVersionMismatch" -GpoId "$($gpo.Id)" -GpoName $gpo.DisplayName -Title "AD and SYSVOL GPO versions differ" -Evidence "User AD/SYSVOL=$userAdVersion/$userSysvolVersion; Computer AD/SYSVOL=$computerAdVersion/$computerSysvolVersion." -Recommendation "Check DFSR/SYSVOL replication and GPO consistency before relying on this policy.")
    }
    if ($legacyKeywordHit) {
        Add-FindingRow -Findings $findings -Finding (New-Finding -Severity "Medium" -FindingType "LegacyKeyword" -GpoId "$($gpo.Id)" -GpoName $gpo.DisplayName -Title "Possible legacy GPO reference" -Evidence "Matched legacy keyword '$legacyKeywordHit'." -Recommendation "Review whether this GPO still applies to supported OS/server versions. Replace legacy settings with a modern baseline where possible.")
    }
}

$linkRows = @($links.ToArray())
$targetRows = @($targetInventory["Targets"])

foreach ($link in @($linkRows | Where-Object { $_.LinkType -eq "Direct" })) {
    if ("$($link.Enabled)" -match "False|No|0") {
        Add-FindingRow -Findings $findings -Finding (New-Finding -Severity "Low" -FindingType "DisabledGpoLink" -GpoId "$($link.GpoId)" -GpoName $link.DisplayName -TargetPath $link.TargetPath -Title "GPO link is disabled" -Evidence "Link to $($link.TargetPath) is disabled." -Recommendation "Confirm whether the link should be removed or re-enabled through change control.")
    }
    if ("$($link.Enforced)" -match "True|Yes|1") {
        Add-FindingRow -Findings $findings -Finding (New-Finding -Severity "Info" -FindingType "EnforcedGpoLink" -GpoId "$($link.GpoId)" -GpoName $link.DisplayName -TargetPath $link.TargetPath -Title "GPO link is enforced" -Evidence "Link to $($link.TargetPath) is enforced." -Recommendation "Confirm enforcement is still required because it can override lower-level OU policy decisions.")
    }
}

foreach ($target in @($targetRows)) {
    if ($target.InheritanceBlocked) {
        Add-FindingRow -Findings $findings -Finding (New-Finding -Severity "Info" -FindingType "InheritanceBlocked" -TargetPath $target.TargetPath -Title "GPO inheritance is blocked" -Evidence "$($target.TargetPath) blocks GPO inheritance." -Recommendation "Confirm security baseline GPOs still reach this OU through enforced links or direct links.")
    }
    if ($target.DirectLinkCount -ge $MaxGposPerTarget) {
        Add-FindingRow -Findings $findings -Finding (New-Finding -Severity "Medium" -FindingType "ManyGpoLinksOnTarget" -TargetPath $target.TargetPath -Title "Target has many direct GPO links" -Evidence "$($target.DirectLinkCount) direct GPO links on this target. Threshold is $MaxGposPerTarget." -Recommendation "Review link order and consolidate policies where possible.")
    }
}

$gpoRowsById = @{}
foreach ($gpoRow in @($gpoRows.ToArray())) {
    $gpoRowsById[$gpoRow.GpoId] = $gpoRow
}

$overlapCounter = 0
$overlapLinkRows = if ($targetRows.Count -gt 0) {
    @($linkRows | Where-Object { $_.Source -eq "GetGPInheritance" })
}
else {
    @($linkRows)
}
foreach ($targetGroup in @($overlapLinkRows | Where-Object { $_.LinkType -eq "Direct" -and "$($_.Enabled)" -notmatch "False|No|0" } | Group-Object TargetPath)) {
    $linkedGpos = @($targetGroup.Group | ForEach-Object {
            if ($gpoRowsById.ContainsKey($_.GpoId)) {
                $gpoRowsById[$_.GpoId]
            }
        })
    foreach ($extensionGroup in @($linkedGpos | ForEach-Object {
                $row = $_
                foreach ($extension in @($row.Extensions)) {
                    [pscustomobject]@{ Extension = $extension; GpoName = $row.DisplayName; GpoId = $row.GpoId }
                }
            } | Group-Object Extension | Where-Object { $_.Count -gt 1 })) {
        $overlapCounter++
        if ($overlapCounter -le 100) {
            $names = @($extensionGroup.Group | ForEach-Object { $_.GpoName } | Sort-Object -Unique)
            Add-FindingRow -Findings $findings -Finding (New-Finding -Severity "Medium" -FindingType "PotentialSettingOverlap" -TargetPath $targetGroup.Name -Title "Multiple GPOs configure the same policy area on one target" -Evidence "Policy area '$($extensionGroup.Name)' appears in: $($names -join ', ')." -Recommendation "Review link order and setting values. Consolidate or document authoritative GPO ownership.")
        }
    }
}

$gpoRowsFinal = @($gpoRows.ToArray() | Sort-Object DisplayName)
$linkRowsFinal = @($linkRows | Sort-Object TargetPath, LinkType, LinkOrder, DisplayName)
$findingRowsFinal = @($findings.ToArray() | Sort-Object @{ Expression = { Get-PrioritySortValue -Value $_.ActionPriority } }, @{ Expression = {
            switch ($_.Severity) {
                "Critical" { 0 }
                "High" { 1 }
                "Medium" { 2 }
                "Low" { 3 }
                "Info" { 4 }
                default { 5 }
            }
        } }, FindingType, GpoName)

$summary = [ordered]@{
    TotalGpos             = $gpoRowsFinal.Count
    LinkedGpos            = @($gpoRowsFinal | Where-Object { $_.DirectLinkCount -gt 0 }).Count
    UnlinkedGpos          = @($gpoRowsFinal | Where-Object { $_.DirectLinkCount -eq 0 }).Count
    StaleGpos             = @($gpoRowsFinal | Where-Object { $_.IsStale }).Count
    DisabledGpos          = @($gpoRowsFinal | Where-Object { $_.IsDisabled }).Count
    EmptyGpos             = @($gpoRowsFinal | Where-Object { $_.IsEmpty }).Count
    WmiFilteredGpos       = @($gpoRowsFinal | Where-Object { $_.HasWmiFilter }).Count
    SecurityFilteredGpos  = @($gpoRowsFinal | Where-Object { $_.IsSecurityFiltered }).Count
    VersionMismatchGpos   = @($gpoRowsFinal | Where-Object { $_.VersionMismatch }).Count
    TargetCount           = $targetRows.Count
    LinkCount             = $linkRowsFinal.Count
    TotalFindings         = $findingRowsFinal.Count
    CriticalFindings      = @($findingRowsFinal | Where-Object { $_.Severity -eq "Critical" }).Count
    HighFindings          = @($findingRowsFinal | Where-Object { $_.Severity -eq "High" }).Count
    MediumFindings        = @($findingRowsFinal | Where-Object { $_.Severity -eq "Medium" }).Count
    LowFindings           = @($findingRowsFinal | Where-Object { $_.Severity -eq "Low" }).Count
    InfoFindings          = @($findingRowsFinal | Where-Object { $_.Severity -eq "Info" }).Count
    ActionPriorityCounts  = Get-CountByField -Rows $findingRowsFinal -FieldName "ActionPriority"
    FindingSeverityCounts = Get-CountByField -Rows $findingRowsFinal -FieldName "Severity"
    FindingTypeCounts     = Get-CountByField -Rows $findingRowsFinal -FieldName "FindingType"
    ReportErrors          = @($reportErrors.ToArray())
    Notes                 = @(
        "This script is audit-only and does not change GPOs, links, permissions, WMI filters, or AD objects.",
        "PotentialSettingOverlap means multiple GPOs touch the same policy extension on the same target. It is a review signal, not proof of a conflict.",
        "Unlinked or stale GPOs should be exported/backed up and owner-reviewed before removal.",
        "Security-filtered and WMI-filtered GPOs can be valid, but they should have documented ownership and intended scope.",
        "AD/SYSVOL version mismatch may indicate replication or GPO consistency problems and should be reviewed before trusting the policy."
    )
}

$report = [ordered]@{
    ReportMetadata = [ordered]@{
        SchemaVersion       = "1.0"
        ReportType          = "ADGPOHealth"
        Status              = "Completed"
        GeneratedAtUtc      = $generatedAtUtc
        ComputerName        = $env:COMPUTERNAME
        RunBy               = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        Domain              = if ($Domain) { $Domain } else { $null }
        Server              = if ($Server) { $Server } else { $null }
        StaleDays           = $StaleDays
        MaxGposPerTarget    = $MaxGposPerTarget
        SkipTargetInventory = [bool]$SkipTargetInventory
        HasActiveDirectoryModule = [bool]$hasActiveDirectoryModule
        JsonPath            = $jsonPath
        GpoCsvPath          = $gpoCsvPath
        LinksCsvPath        = $linksCsvPath
        FindingsCsvPath     = $findingsCsvPath
        MarkdownPath        = $markdownPath
    }
    Summary  = $summary
    GPOs     = @($gpoRowsFinal)
    Targets  = @($targetRows)
    Links    = @($linkRowsFinal)
    Findings = @($findingRowsFinal)
}

$report | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding utf8
Write-CsvReport -Path $gpoCsvPath -Rows $gpoRowsFinal -Columns @("DisplayName", "GpoId", "DomainName", "Owner", "GpoStatus", "CreationTimeUtc", "ModificationTimeUtc", "AgeDaysSinceModified", "IsStale", "IsDisabled", "IsEmpty", "IsDuplicateName", "WmiFilterName", "HasWmiFilter", "DirectLinkCount", "PermissionReadSucceeded", "PermissionReadError", "ApplyPrincipalCount", "ApplyPrincipalsText", "ApplyPrincipalSidsText", "IsSecurityFiltered", "ExtensionCount", "ExtensionsText", "VersionMismatch", "LegacyKeywordHit", "Description")
Write-CsvReport -Path $linksCsvPath -Rows $linkRowsFinal -Columns @("GpoId", "DisplayName", "TargetName", "TargetPath", "TargetType", "LinkType", "Enabled", "Enforced", "LinkOrder", "Source")
Write-CsvReport -Path $findingsCsvPath -Rows $findingRowsFinal -Columns @("ActionPriority", "Severity", "FindingType", "GpoId", "GpoName", "TargetPath", "Title", "Evidence", "AdminAction", "ChangeRisk", "VerificationStep", "Recommendation")
Write-MarkdownReport -Path $markdownPath -Report $report

if (-not $Quiet) {
    Write-Host "AD GPO health report written to: $jsonPath"
    Write-Host "GPO inventory CSV written to: $gpoCsvPath"
    Write-Host "GPO links CSV written to: $linksCsvPath"
    Write-Host "GPO findings CSV written to: $findingsCsvPath"
    Write-Host "GPO review markdown written to: $markdownPath"
    Write-Host "GPOs: $($summary.TotalGpos)"
    Write-Host "Findings: $($summary.TotalFindings)"
    Write-Host "Unlinked GPOs: $($summary.UnlinkedGpos)"
    Write-Host "Stale GPOs: $($summary.StaleGpos)"
    if ($reportErrors.Count -gt 0) {
        Write-Host "Warnings: $($reportErrors.Count). See Summary.ReportErrors in the JSON report." -ForegroundColor Yellow
    }
}
