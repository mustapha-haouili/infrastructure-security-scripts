<#
.SYNOPSIS
Audits user accounts with Service Principal Names for Kerberos exposure risk.

.DESCRIPTION
This script reports Active Directory user accounts that have SPN values and
highlights exposure indicators such as privileged membership,
PasswordNeverExpires, old passwords, delegation, pre-authentication disabled,
and weak or unknown Kerberos encryption settings.

It is audit-only. It does not request Kerberos tickets, crack passwords, or
change Active Directory.

.PARAMETER SearchBase
Optional distinguished name for the OU or domain path to search.

.PARAMETER Server
Optional domain controller or AD LDS instance to query.

.PARAMETER Credential
Optional credential for the AD query.

.PARAMETER IncludeDisabled
Include disabled SPN-bearing user accounts.

.PARAMETER MaxPasswordAgeDays
Password age threshold used for exposure review. Default: 180.

.PARAMETER OutputDirectory
Directory where spn-exposure.json, spn-exposure.csv, and
spn-exposure-review.md are written.

.PARAMETER Quiet
Suppress console summary.

.EXAMPLE
.\Get-ADSPNExposureAudit.ps1

.EXAMPLE
.\Get-ADSPNExposureAudit.ps1 -IncludeDisabled -MaxPasswordAgeDays 365
#>

[CmdletBinding()]
param(
    [string]$SearchBase = "",
    [string]$Server = "",
    [System.Management.Automation.PSCredential]$Credential,
    [switch]$IncludeDisabled,
    [ValidateRange(1, 3650)]
    [int]$MaxPasswordAgeDays = 180,
    [string]$OutputDirectory = ".\reports\ad-spn-exposure-$env:COMPUTERNAME-$(Get-Date -Format 'yyyyMMdd-HHmmss')",
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
        if ($fileTime -le 0 -or $fileTime -ge 9223372036854775807) {
            return $null
        }
        return [datetime]::FromFileTimeUtc($fileTime).ToString("o")
    }
    catch {
        return $null
    }
}

function Get-AgeDays {
    param(
        [AllowNull()][object]$Value,
        [Parameter(Mandatory = $true)][datetime]$Now
    )

    if ($null -eq $Value) {
        return $null
    }

    try {
        return [int](New-TimeSpan -Start ([datetime]$Value) -End $Now).TotalDays
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
    if ($PSBoundParameters.ContainsKey("Credential")) {
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

function Get-CnFromDistinguishedName {
    param([AllowNull()][string]$DistinguishedName)

    if (-not $DistinguishedName) {
        return ""
    }

    if ($DistinguishedName -match '^CN=([^,]+)') {
        return ($Matches[1] -replace '\\,', ',')
    }

    return $DistinguishedName
}

function Convert-DistinguishedNamesToNames {
    param([AllowNull()][object[]]$DistinguishedNames)

    return @($DistinguishedNames | Where-Object { $_ } | ForEach-Object { Get-CnFromDistinguishedName -DistinguishedName "$_" })
}

function Get-PrivilegedGroupNames {
    param([AllowNull()][object[]]$GroupDistinguishedNames)

    $privilegedGroupPattern = '(?i)^(Domain Admins|Enterprise Admins|Schema Admins|Administrators|Account Operators|Server Operators|Backup Operators|Print Operators|DnsAdmins|Group Policy Creator Owners|Protected Users|Key Admins|Enterprise Key Admins)$'
    return @(Convert-DistinguishedNamesToNames -DistinguishedNames $GroupDistinguishedNames | Where-Object { $_ -match $privilegedGroupPattern })
}

function Get-EncryptionAssessment {
    param([AllowNull()][object]$SupportedEncryptionTypes)

    if ($null -eq $SupportedEncryptionTypes -or "$SupportedEncryptionTypes" -eq "") {
        return [ordered]@{
            EncryptionRisk = "UnknownOrDefault"
            HasAES         = $false
            HasRC4         = $false
            Text           = "msDS-SupportedEncryptionTypes is empty; effective Kerberos encryption depends on domain and account defaults."
        }
    }

    try {
        $value = [int]$SupportedEncryptionTypes
        $hasRc4 = [bool]($value -band 0x4)
        $hasAes = [bool]($value -band 0x18)
        $risk = if ($hasRc4 -and -not $hasAes) { "RC4OnlyOrLegacy" } elseif ($hasRc4) { "RC4Allowed" } elseif ($hasAes) { "AESConfigured" } else { "NoModernEncryptionFlag" }
        return [ordered]@{
            EncryptionRisk = $risk
            HasAES         = $hasAes
            HasRC4         = $hasRc4
            Text           = "msDS-SupportedEncryptionTypes=$value; AES=$hasAes; RC4=$hasRc4."
        }
    }
    catch {
        return [ordered]@{
            EncryptionRisk = "Unknown"
            HasAES         = $false
            HasRC4         = $false
            Text           = "Could not parse msDS-SupportedEncryptionTypes."
        }
    }
}

function Get-ExposureAssessment {
    param(
        [bool]$Enabled,
        [bool]$PasswordNeverExpires,
        [AllowNull()][object]$PasswordAgeDays,
        [bool]$AdminCount,
        [int]$PrivilegedGroupCount,
        [bool]$DoesNotRequirePreAuth,
        [bool]$TrustedForDelegation,
        [bool]$TrustedToAuthForDelegation,
        [string]$EncryptionRisk
    )

    $flags = New-Object System.Collections.Generic.List[string]
    $reasons = New-Object System.Collections.Generic.List[string]

    if ($Enabled) {
        $flags.Add("Enabled") | Out-Null
    }
    else {
        $flags.Add("Disabled") | Out-Null
    }
    $flags.Add("HasSPN") | Out-Null
    if ($PasswordNeverExpires) {
        $flags.Add("PasswordNeverExpires") | Out-Null
        $reasons.Add("SPN-bearing account has PasswordNeverExpires set.") | Out-Null
    }
    if ($PasswordAgeDays -ne $null -and [int]$PasswordAgeDays -gt $MaxPasswordAgeDays) {
        $flags.Add("OldPassword") | Out-Null
        $reasons.Add("Password age exceeds the configured review threshold.") | Out-Null
    }
    if ($AdminCount -or $PrivilegedGroupCount -gt 0) {
        $flags.Add("PrivilegedAccess") | Out-Null
        $reasons.Add("Privileged group membership or AdminCount=1 increases SPN account impact.") | Out-Null
    }
    if ($DoesNotRequirePreAuth) {
        $flags.Add("DoesNotRequirePreAuth") | Out-Null
        $reasons.Add("Kerberos pre-authentication is disabled.") | Out-Null
    }
    if ($TrustedForDelegation) {
        $flags.Add("UnconstrainedDelegation") | Out-Null
        $reasons.Add("Unconstrained delegation is enabled.") | Out-Null
    }
    if ($TrustedToAuthForDelegation) {
        $flags.Add("ConstrainedDelegation") | Out-Null
        $reasons.Add("Protocol-transition delegation is enabled.") | Out-Null
    }
    if ($EncryptionRisk -in @("RC4OnlyOrLegacy", "RC4Allowed", "NoModernEncryptionFlag", "UnknownOrDefault", "Unknown")) {
        $flags.Add("EncryptionReview") | Out-Null
        $reasons.Add("Kerberos encryption settings require review: $EncryptionRisk.") | Out-Null
    }

    $priority = "Medium"
    if (-not $Enabled) {
        $priority = "Low"
    }
    elseif ($DoesNotRequirePreAuth -or $TrustedForDelegation -or (($AdminCount -or $PrivilegedGroupCount -gt 0) -and ($PasswordNeverExpires -or ($PasswordAgeDays -ne $null -and [int]$PasswordAgeDays -gt $MaxPasswordAgeDays)))) {
        $priority = "Critical"
    }
    elseif ($PasswordNeverExpires -or ($PasswordAgeDays -ne $null -and [int]$PasswordAgeDays -gt $MaxPasswordAgeDays) -or $TrustedToAuthForDelegation -or $EncryptionRisk -in @("RC4OnlyOrLegacy", "RC4Allowed", "UnknownOrDefault")) {
        $priority = "High"
    }

    $recommendedAction = switch ($priority) {
        "Critical" { "Review immediately. Remove privilege/delegation where possible, rotate password, and consider gMSA migration." }
        "High" { "Validate SPN owner, rotate password, configure AES where supported, and document any exception." }
        "Medium" { "Confirm SPN is still required and include the account in recurring service account review." }
        "Low" { "Confirm disabled SPN account has no dependency, then remove SPNs or retire through change control." }
        default { "Review manually." }
    }

    $nextStep = switch ($priority) {
        "Critical" { "Open urgent identity/security review and verify recent account changes." }
        "High" { "Assign owner and create rotation/encryption cleanup plan." }
        "Medium" { "Document owner and required SPNs." }
        "Low" { "Confirm retirement path for disabled SPN account." }
        default { "Review manually." }
    }

    [ordered]@{
        ExposurePriority = $priority
        RiskFlags        = @($flags.ToArray())
        ReviewReasons    = @($reasons.ToArray())
        RecommendedAction = $recommendedAction
        NextReviewStep   = $nextStep
    }
}

function ConvertTo-SPNExposureRow {
    param(
        [Parameter(Mandatory = $true)][object]$User,
        [Parameter(Mandatory = $true)][datetime]$Now
    )

    $spns = @(Get-ObjectValue -InputObject $User -Name "ServicePrincipalName" | Where-Object { $_ })
    $memberOf = @(Get-ObjectValue -InputObject $User -Name "memberOf" | Where-Object { $_ })
    $directGroupNames = @(Convert-DistinguishedNamesToNames -DistinguishedNames $memberOf)
    $privilegedGroupNames = @(Get-PrivilegedGroupNames -GroupDistinguishedNames $memberOf)
    $passwordLastSet = Get-ObjectValue -InputObject $User -Name "PasswordLastSet"
    $passwordAgeDays = Get-AgeDays -Value $passwordLastSet -Now $Now
    $lastLogonDate = Get-ObjectValue -InputObject $User -Name "LastLogonDate"
    $encryption = Get-EncryptionAssessment -SupportedEncryptionTypes (Get-ObjectValue -InputObject $User -Name "msDS-SupportedEncryptionTypes")
    $enabled = [bool](Get-ObjectValue -InputObject $User -Name "Enabled")
    $passwordNeverExpires = [bool](Get-ObjectValue -InputObject $User -Name "PasswordNeverExpires")
    $adminCount = [bool]((Get-ObjectValue -InputObject $User -Name "AdminCount") -eq 1)
    $doesNotRequirePreAuth = [bool](Get-ObjectValue -InputObject $User -Name "DoesNotRequirePreAuth")
    $trustedForDelegation = [bool](Get-ObjectValue -InputObject $User -Name "TrustedForDelegation")
    $trustedToAuthForDelegation = [bool](Get-ObjectValue -InputObject $User -Name "TrustedToAuthForDelegation")
    $assessment = Get-ExposureAssessment -Enabled $enabled -PasswordNeverExpires $passwordNeverExpires -PasswordAgeDays $passwordAgeDays -AdminCount $adminCount -PrivilegedGroupCount $privilegedGroupNames.Count -DoesNotRequirePreAuth $doesNotRequirePreAuth -TrustedForDelegation $trustedForDelegation -TrustedToAuthForDelegation $trustedToAuthForDelegation -EncryptionRisk $encryption.EncryptionRisk

    [pscustomobject][ordered]@{
        ExposurePriority          = $assessment.ExposurePriority
        ActionPriority            = Get-ActionPriority -ReviewPriority $assessment.ExposurePriority
        SamAccountName            = Get-ObjectValue -InputObject $User -Name "SamAccountName"
        Name                      = Get-ObjectValue -InputObject $User -Name "Name"
        UserPrincipalName         = Get-ObjectValue -InputObject $User -Name "UserPrincipalName"
        SID                       = "$(Get-ObjectValue -InputObject $User -Name "SID")"
        Enabled                   = $enabled
        SPNCount                  = $spns.Count
        ServicePrincipalNames     = @($spns)
        ServicePrincipalNamesText = if ($spns.Count -gt 0) { $spns -join "; " } else { "" }
        PasswordNeverExpires      = $passwordNeverExpires
        PasswordLastSetUtc        = Format-DateTimeUtc -Value $passwordLastSet
        PasswordAgeDays           = $passwordAgeDays
        LastLogonDateUtc          = Format-DateTimeUtc -Value $lastLogonDate
        LastLogonTimestampUtc     = Convert-ADFileTimeToUtc -Value (Get-ObjectValue -InputObject $User -Name "lastLogonTimestamp")
        InactiveDays              = Get-AgeDays -Value $lastLogonDate -Now $Now
        AdminCount                = if ($adminCount) { 1 } else { Get-ObjectValue -InputObject $User -Name "AdminCount" }
        PrivilegedGroupCount      = $privilegedGroupNames.Count
        PrivilegedGroups          = @($privilegedGroupNames)
        PrivilegedGroupsText      = if ($privilegedGroupNames.Count -gt 0) { $privilegedGroupNames -join "; " } else { "" }
        DirectGroupCount          = $directGroupNames.Count
        DoesNotRequirePreAuth     = $doesNotRequirePreAuth
        TrustedForDelegation      = $trustedForDelegation
        TrustedToAuthForDelegation = $trustedToAuthForDelegation
        AccountNotDelegated       = [bool](Get-ObjectValue -InputObject $User -Name "AccountNotDelegated")
        SupportedEncryptionTypes  = Get-ObjectValue -InputObject $User -Name "msDS-SupportedEncryptionTypes"
        EncryptionRisk            = $encryption.EncryptionRisk
        EncryptionEvidence        = $encryption.Text
        HasAES                    = [bool]$encryption.HasAES
        HasRC4                    = [bool]$encryption.HasRC4
        ManagedBy                 = Get-ObjectValue -InputObject $User -Name "ManagedBy"
        Description               = Get-ObjectValue -InputObject $User -Name "Description"
        RiskFlags                 = @($assessment.RiskFlags)
        RiskFlagsText             = if ($assessment.RiskFlags.Count -gt 0) { $assessment.RiskFlags -join "; " } else { "" }
        ReviewReasons             = @($assessment.ReviewReasons)
        ReviewReasonsText         = if ($assessment.ReviewReasons.Count -gt 0) { $assessment.ReviewReasons -join " " } else { "" }
        RecommendedAction         = $assessment.RecommendedAction
        NextReviewStep            = $assessment.NextReviewStep
        DistinguishedName         = Get-ObjectValue -InputObject $User -Name "DistinguishedName"
    }
}

function Get-ActionPriority {
    param([string]$ReviewPriority)

    switch ($ReviewPriority) {
        "Critical" { return "P1 - Immediate SPN review" }
        "High" { return "P2 - Kerberos exposure review" }
        "Medium" { return "P3 - Document and monitor" }
        "Low" { return "P4 - Retirement validation" }
        default { return "P5 - Manual review" }
    }
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
        [object[]]$Rows
    )

    $columns = @(
        "ExposurePriority",
        "ActionPriority",
        "SamAccountName",
        "Name",
        "UserPrincipalName",
        "SID",
        "Enabled",
        "SPNCount",
        "ServicePrincipalNamesText",
        "PasswordNeverExpires",
        "PasswordLastSetUtc",
        "PasswordAgeDays",
        "LastLogonDateUtc",
        "InactiveDays",
        "AdminCount",
        "PrivilegedGroupCount",
        "PrivilegedGroupsText",
        "DoesNotRequirePreAuth",
        "TrustedForDelegation",
        "TrustedToAuthForDelegation",
        "AccountNotDelegated",
        "SupportedEncryptionTypes",
        "EncryptionRisk",
        "EncryptionEvidence",
        "HasAES",
        "HasRC4",
        "ManagedBy",
        "RiskFlagsText",
        "ReviewReasonsText",
        "RecommendedAction",
        "NextReviewStep",
        "Description",
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
            SchemaVersion  = "1.0"
            ReportType     = "ADSPNExposureAudit"
            Status         = "Failed"
            GeneratedAtUtc = (Get-Date).ToUniversalTime().ToString("o")
            ComputerName   = $env:COMPUTERNAME
            SearchBase     = if ($SearchBase) { $SearchBase } else { $null }
            Server         = if ($Server) { $Server } else { $null }
        }
        Summary = [ordered]@{
            Status = "Failed"
            Reason = $Reason
        }
        SPNAccounts = @()
    }

    $report | ConvertTo-Json -Depth 6 | Out-File -FilePath $JsonPath -Encoding utf8
}

function Add-MarkdownSPNTable {
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

    Add-MarkdownLine -Lines $Lines -Text "| Priority | Account | SPNs | Password age | Encryption | Risk flags | Next step |"
    Add-MarkdownLine -Lines $Lines -Text "|---|---|---:|---:|---|---|---|"
    foreach ($row in @($Rows | Select-Object -First $Limit)) {
        Add-MarkdownLine -Lines $Lines -Text ("| {0} | {1} | {2} | {3} | {4} | {5} | {6} |" -f `
                (ConvertTo-MarkdownSafeText $row.ActionPriority),
            (ConvertTo-MarkdownSafeText $row.SamAccountName),
            (ConvertTo-MarkdownSafeText $row.SPNCount),
            (ConvertTo-MarkdownSafeText $row.PasswordAgeDays),
            (ConvertTo-MarkdownSafeText $row.EncryptionRisk),
            (ConvertTo-MarkdownSafeText $row.RiskFlagsText),
            (ConvertTo-MarkdownSafeText $row.NextReviewStep))
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
    $rows = @($Report["SPNAccounts"])
    $lines = New-Object System.Collections.Generic.List[string]

    Add-MarkdownLine -Lines $lines -Text "# AD SPN Exposure Review"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "Generated UTC: ``$($metadata.GeneratedAtUtc)``"
    Add-MarkdownLine -Lines $lines -Text "Computer: ``$($metadata.ComputerName)``"
    Add-MarkdownLine -Lines $lines -Text "Search base: ``$(if ($metadata.SearchBase) { $metadata.SearchBase } else { 'Domain default' })``"
    Add-MarkdownLine -Lines $lines

    Add-MarkdownLine -Lines $lines -Text "## Summary"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "| Metric | Count |"
    Add-MarkdownLine -Lines $lines -Text "|---|---:|"
    foreach ($metric in @("TotalSPNAccounts", "CriticalAccounts", "HighAccounts", "PasswordNeverExpiresAccounts", "OldPasswordAccounts", "PrivilegedAccounts", "DelegationAccounts", "PreAuthDisabledAccounts", "EncryptionReviewAccounts")) {
        Add-MarkdownLine -Lines $lines -Text ("| {0} | {1} |" -f $metric, $summary.$metric)
    }
    Add-MarkdownLine -Lines $lines

    Add-MarkdownLine -Lines $lines -Text "## Admin Action Plan"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "This report is defensive inventory only. It does not request tickets or test passwords."
    if ($summary.CriticalAccounts -gt 0) {
        Add-MarkdownLine -Lines $lines -Text "Critical SPN accounts exist. Review privileged, delegation, and pre-authentication findings first."
    }
    elseif ($summary.HighAccounts -gt 0) {
        Add-MarkdownLine -Lines $lines -Text "High SPN exposure findings exist. Prioritize password rotation, AES support, and ownership review."
    }
    else {
        Add-MarkdownLine -Lines $lines -Text "No Critical or High SPN exposure findings were detected. Continue with ownership and recurring service account review."
    }
    Add-MarkdownLine -Lines $lines

    Add-MarkdownLine -Lines $lines -Text "## Critical"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownSPNTable -Lines $lines -Rows @($rows | Where-Object { $_.ExposurePriority -eq "Critical" } | Sort-Object SamAccountName)

    Add-MarkdownLine -Lines $lines -Text "## High"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownSPNTable -Lines $lines -Rows @($rows | Where-Object { $_.ExposurePriority -eq "High" } | Sort-Object SamAccountName)

    Add-MarkdownLine -Lines $lines -Text "## All SPN Accounts"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownSPNTable -Lines $lines -Rows @($rows | Sort-Object @{ Expression = { Get-PrioritySortValue -Value $_.ActionPriority } }, SamAccountName) -Limit 100

    Add-MarkdownLine -Lines $lines -Text "## Review Rules"
    Add-MarkdownLine -Lines $lines
    foreach ($note in @($summary.Notes)) {
        Add-MarkdownLine -Lines $lines -Text "- $note"
    }

    $lines | Out-File -FilePath $Path -Encoding utf8
}

New-Directory -Path $OutputDirectory
$resolvedOutputDirectory = (Resolve-Path -Path $OutputDirectory).Path
$jsonPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "spn-exposure.json"
$csvPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "spn-exposure.csv"
$markdownPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "spn-exposure-review.md"

if (-not (Import-ActiveDirectoryModule)) {
    $reason = "ActiveDirectory PowerShell module was not found. Install RSAT Active Directory tools or run this script on a domain management host."
    Write-FailedReport -JsonPath $jsonPath -Reason $reason
    throw $reason
}

$now = Get-Date
$commonParameters = Get-ADCommonParameters
$domainSummary = Get-DomainSummary -CommonParameters $commonParameters
$enabledClause = if ($IncludeDisabled) { "" } else { "(!(userAccountControl:1.2.840.113556.1.4.803:=2))" }
$spnFilter = "(&(objectCategory=person)(objectClass=user)$enabledClause(servicePrincipalName=*))"

$userParameters = @{
    LDAPFilter  = $spnFilter
    Properties  = @(
        "AccountNotDelegated",
        "AdminCount",
        "Description",
        "DoesNotRequirePreAuth",
        "Enabled",
        "KerberosEncryptionType",
        "LastLogonDate",
        "lastLogonTimestamp",
        "ManagedBy",
        "memberOf",
        "msDS-SupportedEncryptionTypes",
        "PasswordLastSet",
        "PasswordNeverExpires",
        "ServicePrincipalName",
        "SID",
        "TrustedForDelegation",
        "TrustedToAuthForDelegation",
        "UserPrincipalName",
        "whenChanged",
        "WhenCreated"
    )
    ErrorAction = "Stop"
}
foreach ($key in $commonParameters.Keys) {
    $userParameters[$key] = $commonParameters[$key]
}
if ($SearchBase) {
    $userParameters["SearchBase"] = $SearchBase
}

try {
    $users = @(Get-ADUser @userParameters)
}
catch {
    $reason = "Active Directory SPN account query failed: $($_.Exception.Message)"
    Write-FailedReport -JsonPath $jsonPath -Reason $reason
    throw $reason
}

$spnAccounts = @($users | ForEach-Object { ConvertTo-SPNExposureRow -User $_ -Now $now } | Sort-Object @{ Expression = { Get-PrioritySortValue -Value $_.ActionPriority } }, SamAccountName)

$summary = [ordered]@{
    TotalSPNAccounts              = $spnAccounts.Count
    CriticalAccounts              = @($spnAccounts | Where-Object { $_.ExposurePriority -eq "Critical" }).Count
    HighAccounts                  = @($spnAccounts | Where-Object { $_.ExposurePriority -eq "High" }).Count
    MediumAccounts                = @($spnAccounts | Where-Object { $_.ExposurePriority -eq "Medium" }).Count
    LowAccounts                   = @($spnAccounts | Where-Object { $_.ExposurePriority -eq "Low" }).Count
    PasswordNeverExpiresAccounts  = @($spnAccounts | Where-Object { $_.PasswordNeverExpires }).Count
    OldPasswordAccounts           = @($spnAccounts | Where-Object { $_.PasswordAgeDays -ne $null -and $_.PasswordAgeDays -gt $MaxPasswordAgeDays }).Count
    PrivilegedAccounts            = @($spnAccounts | Where-Object { $_.PrivilegedGroupCount -gt 0 -or $_.AdminCount -eq 1 }).Count
    DelegationAccounts            = @($spnAccounts | Where-Object { $_.TrustedForDelegation -or $_.TrustedToAuthForDelegation }).Count
    PreAuthDisabledAccounts       = @($spnAccounts | Where-Object { $_.DoesNotRequirePreAuth }).Count
    EncryptionReviewAccounts      = @($spnAccounts | Where-Object { $_.EncryptionRisk -in @("RC4OnlyOrLegacy", "RC4Allowed", "NoModernEncryptionFlag", "UnknownOrDefault", "Unknown") }).Count
    Notes                         = @(
        "This script is audit-only and does not request Kerberos tickets or test credentials.",
        "SPN-bearing user accounts can be sensitive even when they are not Domain Admins.",
        "Prioritize SPN accounts with privilege, delegation, PasswordNeverExpires, old passwords, or weak/unknown encryption.",
        "Prefer gMSA migration where supported, then remove unneeded SPNs and rotate passwords through change control.",
        "Empty msDS-SupportedEncryptionTypes is treated as review-needed, not proof of RC4-only behavior."
    )
}

$report = [ordered]@{
    ReportMetadata = [ordered]@{
        SchemaVersion      = "1.0"
        ReportType         = "ADSPNExposureAudit"
        Status             = "Completed"
        GeneratedAtUtc     = (Get-Date).ToUniversalTime().ToString("o")
        ComputerName       = $env:COMPUTERNAME
        RunBy              = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        SearchBase         = if ($SearchBase) { $SearchBase } else { $null }
        Server             = if ($Server) { $Server } else { $null }
        IncludeDisabled    = [bool]$IncludeDisabled
        MaxPasswordAgeDays = $MaxPasswordAgeDays
        OutputDirectory    = $resolvedOutputDirectory
        JsonPath           = $jsonPath
        CsvPath            = $csvPath
        MarkdownPath       = $markdownPath
    }
    Domain      = $domainSummary
    Summary     = $summary
    SPNAccounts = @($spnAccounts)
}

$report | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding utf8
Write-CsvReport -Path $csvPath -Rows $spnAccounts
Write-MarkdownReport -Path $markdownPath -Report $report

if (-not $Quiet) {
    Write-Host "AD SPN exposure report written to: $jsonPath"
    Write-Host "AD SPN exposure review written to: $markdownPath"
    Write-Host "SPN accounts: $($summary.TotalSPNAccounts)"
    Write-Host "Critical: $($summary.CriticalAccounts)"
    Write-Host "High: $($summary.HighAccounts)"
}
