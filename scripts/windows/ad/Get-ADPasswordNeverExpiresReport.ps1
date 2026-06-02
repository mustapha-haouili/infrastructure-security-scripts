<#
.SYNOPSIS
Reports Active Directory user accounts with PasswordNeverExpires.

.DESCRIPTION
This script audits Active Directory user accounts where PasswordNeverExpires is
set. It classifies privileged accounts, service/SPN accounts, normal user
exceptions, disabled accounts, and system-managed Exchange health mailboxes.

It is audit-only. It does not change Active Directory.

.PARAMETER SearchBase
Optional distinguished name for the OU or domain path to search.

.PARAMETER Server
Optional domain controller or AD LDS instance to query.

.PARAMETER Credential
Optional credential for the AD query.

.PARAMETER IncludeDisabled
Include disabled accounts. By default, only enabled accounts are scanned.

.PARAMETER MaxPasswordAgeDays
Password age threshold used for review guidance. Default: 180.

.PARAMETER OutputDirectory
Directory where password-never-expires.json, password-never-expires.csv, and
password-never-expires-review.md are written.

.PARAMETER Quiet
Suppress console summary.

.EXAMPLE
.\Get-ADPasswordNeverExpiresReport.ps1

.EXAMPLE
.\Get-ADPasswordNeverExpiresReport.ps1 -IncludeDisabled -SearchBase "OU=Users,DC=example,DC=com"
#>

[CmdletBinding()]
param(
    [string]$SearchBase = "",
    [string]$Server = "",
    [System.Management.Automation.PSCredential]$Credential,
    [switch]$IncludeDisabled,
    [ValidateRange(1, 3650)]
    [int]$MaxPasswordAgeDays = 180,
    [string]$OutputDirectory = ".\reports\ad-password-never-expires-$env:COMPUTERNAME-$(Get-Date -Format 'yyyyMMdd-HHmmss')",
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

function Test-ServiceAccountCandidate {
    param(
        [AllowNull()][string]$SamAccountName,
        [AllowNull()][string]$Name,
        [AllowNull()][string]$Description,
        [AllowNull()][string]$DistinguishedName,
        [bool]$HasSPN
    )

    if ($HasSPN) {
        return $true
    }

    $haystack = @($SamAccountName, $Name, $Description, $DistinguishedName) -join " "
    return [bool]($haystack -match "(?i)(^|[^a-z])(svc|service|srv|app|sql|iis|backup|bkp|task|job|api|ldap|monitor|sync|agent|daemon|robot)([^a-z]|$)")
}

function Test-ExchangeHealthMailbox {
    param(
        [AllowNull()][string]$SamAccountName,
        [AllowNull()][string]$Name,
        [AllowNull()][string]$DistinguishedName
    )

    if ($SamAccountName -like "HealthMailbox*" -or $Name -like "HealthMailbox*") {
        return $true
    }

    if ($DistinguishedName -and $DistinguishedName -match "(?i)CN=Monitoring Mailboxes,CN=Microsoft Exchange System Objects") {
        return $true
    }

    return $false
}

function Get-AccountCategory {
    param(
        [Parameter(Mandatory = $true)][object]$User,
        [bool]$IsExchangeHealthMailbox,
        [bool]$IsServiceAccount,
        [bool]$HasSPN,
        [int]$PrivilegedGroupCount
    )

    if ($IsExchangeHealthMailbox) {
        return "ExchangeHealthMailbox"
    }
    if ((Get-ObjectValue -InputObject $User -Name "SamAccountName") -eq "Administrator" -or "$(Get-ObjectValue -InputObject $User -Name "SID")" -match "-500$") {
        return "BuiltInAdministrator"
    }
    if ((Get-ObjectValue -InputObject $User -Name "AdminCount") -eq 1 -or $PrivilegedGroupCount -gt 0) {
        return "PrivilegedAccount"
    }
    if ($HasSPN) {
        return "SPNServiceAccount"
    }
    if ($IsServiceAccount) {
        return "ServiceAccountCandidate"
    }
    return "UserPasswordException"
}

function Get-PasswordExceptionAssessment {
    param(
        [string]$AccountCategory,
        [bool]$Enabled,
        [AllowNull()][object]$PasswordAgeDays,
        [bool]$MissingOwner,
        [bool]$DoesNotRequirePreAuth,
        [bool]$TrustedForDelegation
    )

    $flags = New-Object System.Collections.Generic.List[string]
    $reasons = New-Object System.Collections.Generic.List[string]

    $flags.Add("PasswordNeverExpires") | Out-Null
    if ($Enabled) {
        $flags.Add("Enabled") | Out-Null
    }
    else {
        $flags.Add("Disabled") | Out-Null
    }
    if ($AccountCategory -eq "ExchangeHealthMailbox") {
        $flags.Add("SystemManagedAccount") | Out-Null
        $reasons.Add("Exchange health mailbox detected; treat as system-managed hold.") | Out-Null
    }
    if ($AccountCategory -in @("BuiltInAdministrator", "PrivilegedAccount")) {
        $flags.Add("PrivilegedAccess") | Out-Null
        $reasons.Add("PasswordNeverExpires is set on a privileged or protected account.") | Out-Null
    }
    if ($AccountCategory -in @("SPNServiceAccount", "ServiceAccountCandidate")) {
        $flags.Add("ServiceAccount") | Out-Null
        $reasons.Add("Account appears to be a service account; validate owner and rotation plan.") | Out-Null
    }
    if ($PasswordAgeDays -ne $null -and [int]$PasswordAgeDays -gt $MaxPasswordAgeDays) {
        $flags.Add("OldPassword") | Out-Null
        $reasons.Add("Password age exceeds the configured review threshold.") | Out-Null
    }
    if ($MissingOwner) {
        $flags.Add("MissingOwner") | Out-Null
        $reasons.Add("No owner evidence found in ManagedBy/Description/Info.") | Out-Null
    }
    if ($DoesNotRequirePreAuth) {
        $flags.Add("DoesNotRequirePreAuth") | Out-Null
        $reasons.Add("Kerberos pre-authentication is disabled.") | Out-Null
    }
    if ($TrustedForDelegation) {
        $flags.Add("UnconstrainedDelegation") | Out-Null
        $reasons.Add("Unconstrained delegation is enabled.") | Out-Null
    }

    $priority = "Medium"
    if ($AccountCategory -eq "ExchangeHealthMailbox") {
        $priority = "Hold"
    }
    elseif (-not $Enabled) {
        $priority = "Low"
    }
    elseif ($AccountCategory -in @("BuiltInAdministrator", "PrivilegedAccount") -or $DoesNotRequirePreAuth -or $TrustedForDelegation) {
        $priority = "Critical"
    }
    elseif ($AccountCategory -in @("SPNServiceAccount", "ServiceAccountCandidate") -or $MissingOwner -or ($PasswordAgeDays -ne $null -and [int]$PasswordAgeDays -gt $MaxPasswordAgeDays)) {
        $priority = "High"
    }

    $readiness = switch ($priority) {
        "Critical" { "UrgentExceptionRemovalOrRotationReview" }
        "High" { "NeedsOwnerRotationOrDocumentedException" }
        "Medium" { "NeedsBusinessJustification" }
        "Low" { "DisabledRetentionCleanupCandidate" }
        "Hold" { "HoldSystemManagedDoNotChangeFromThisReport" }
        default { "ManualReview" }
    }

    $recommendedAction = switch ($priority) {
        "Critical" { "Review immediately and remove PasswordNeverExpires or rotate under approved change control." }
        "High" { "Confirm owner and dependency, then create rotation plan or time-bound exception." }
        "Medium" { "Document business justification and review expiration of the exception." }
        "Low" { "Confirm disabled account has no dependency before cleanup." }
        "Hold" { "Keep on hold as system-managed unless product documentation says otherwise." }
        default { "Review manually." }
    }

    $nextStep = switch ($priority) {
        "Critical" { "Open urgent identity/security review and validate privileged access." }
        "High" { "Assign owner and create rotation or exception record." }
        "Medium" { "Document justification and next review date." }
        "Low" { "Validate disabled account retirement path." }
        "Hold" { "Verify product ownership and exclude from normal cleanup." }
        default { "Review manually." }
    }

    [ordered]@{
        ReviewPriority     = $priority
        RotationReadiness  = $readiness
        RiskFlags          = @($flags.ToArray())
        ReviewReasons      = @($reasons.ToArray())
        RecommendedAction  = $recommendedAction
        NextReviewStep     = $nextStep
    }
}

function ConvertTo-PasswordNeverExpiresRow {
    param(
        [Parameter(Mandatory = $true)][object]$User,
        [Parameter(Mandatory = $true)][datetime]$Now
    )

    $spns = @(Get-ObjectValue -InputObject $User -Name "ServicePrincipalName" | Where-Object { $_ })
    $memberOf = @(Get-ObjectValue -InputObject $User -Name "memberOf" | Where-Object { $_ })
    $directGroupNames = @(Convert-DistinguishedNamesToNames -DistinguishedNames $memberOf)
    $privilegedGroupNames = @(Get-PrivilegedGroupNames -GroupDistinguishedNames $memberOf)
    $sam = Get-ObjectValue -InputObject $User -Name "SamAccountName"
    $name = Get-ObjectValue -InputObject $User -Name "Name"
    $description = Get-ObjectValue -InputObject $User -Name "Description"
    $info = Get-ObjectValue -InputObject $User -Name "info"
    $dn = Get-ObjectValue -InputObject $User -Name "DistinguishedName"
    $managedBy = Get-ObjectValue -InputObject $User -Name "ManagedBy"
    $passwordLastSet = Get-ObjectValue -InputObject $User -Name "PasswordLastSet"
    $lastLogonDate = Get-ObjectValue -InputObject $User -Name "LastLogonDate"
    $passwordAgeDays = Get-AgeDays -Value $passwordLastSet -Now $Now
    $isServiceAccount = Test-ServiceAccountCandidate -SamAccountName $sam -Name $name -Description $description -DistinguishedName $dn -HasSPN ($spns.Count -gt 0)
    $isExchangeHealthMailbox = Test-ExchangeHealthMailbox -SamAccountName $sam -Name $name -DistinguishedName $dn
    $accountCategory = Get-AccountCategory -User $User -IsExchangeHealthMailbox $isExchangeHealthMailbox -IsServiceAccount $isServiceAccount -HasSPN ($spns.Count -gt 0) -PrivilegedGroupCount $privilegedGroupNames.Count
    $enabled = [bool](Get-ObjectValue -InputObject $User -Name "Enabled")
    $missingOwner = -not ($managedBy -or $description -or $info)
    $doesNotRequirePreAuth = [bool](Get-ObjectValue -InputObject $User -Name "DoesNotRequirePreAuth")
    $trustedForDelegation = [bool](Get-ObjectValue -InputObject $User -Name "TrustedForDelegation")
    $assessment = Get-PasswordExceptionAssessment -AccountCategory $accountCategory -Enabled $enabled -PasswordAgeDays $passwordAgeDays -MissingOwner $missingOwner -DoesNotRequirePreAuth $doesNotRequirePreAuth -TrustedForDelegation $trustedForDelegation

    [pscustomobject][ordered]@{
        ReviewPriority          = $assessment.ReviewPriority
        ActionPriority          = Get-ActionPriority -ReviewPriority $assessment.ReviewPriority
        AccountCategory         = $accountCategory
        RotationReadiness       = $assessment.RotationReadiness
        SamAccountName          = $sam
        Name                    = $name
        UserPrincipalName       = Get-ObjectValue -InputObject $User -Name "UserPrincipalName"
        SID                     = "$(Get-ObjectValue -InputObject $User -Name "SID")"
        Enabled                 = $enabled
        PasswordNeverExpires    = [bool](Get-ObjectValue -InputObject $User -Name "PasswordNeverExpires")
        PasswordLastSetUtc      = Format-DateTimeUtc -Value $passwordLastSet
        PasswordAgeDays         = $passwordAgeDays
        LastLogonDateUtc        = Format-DateTimeUtc -Value $lastLogonDate
        LastLogonTimestampUtc   = Convert-ADFileTimeToUtc -Value (Get-ObjectValue -InputObject $User -Name "lastLogonTimestamp")
        InactiveDays            = Get-AgeDays -Value $lastLogonDate -Now $Now
        NeverLoggedOn           = [bool]($null -eq $lastLogonDate)
        WhenCreatedUtc          = Format-DateTimeUtc -Value (Get-ObjectValue -InputObject $User -Name "WhenCreated")
        WhenChangedUtc          = Format-DateTimeUtc -Value (Get-ObjectValue -InputObject $User -Name "whenChanged")
        HasSPN                  = [bool]($spns.Count -gt 0)
        SPNCount                = $spns.Count
        ServicePrincipalNames   = @($spns)
        ServicePrincipalNamesText = if ($spns.Count -gt 0) { $spns -join "; " } else { "" }
        AdminCount              = Get-ObjectValue -InputObject $User -Name "AdminCount"
        PrivilegedGroupCount    = $privilegedGroupNames.Count
        PrivilegedGroups        = @($privilegedGroupNames)
        PrivilegedGroupsText    = if ($privilegedGroupNames.Count -gt 0) { $privilegedGroupNames -join "; " } else { "" }
        DirectGroupCount        = $directGroupNames.Count
        DirectGroupsText        = if ($directGroupNames.Count -gt 0) { $directGroupNames -join "; " } else { "" }
        DoesNotRequirePreAuth   = $doesNotRequirePreAuth
        TrustedForDelegation    = $trustedForDelegation
        TrustedToAuthForDelegation = [bool](Get-ObjectValue -InputObject $User -Name "TrustedToAuthForDelegation")
        ManagedBy               = $managedBy
        OwnerEvidenceMissing    = [bool]$missingOwner
        ExceptionRequired       = $assessment.ReviewPriority -notin @("Low", "Hold")
        RiskFlags               = @($assessment.RiskFlags)
        RiskFlagsText           = if ($assessment.RiskFlags.Count -gt 0) { $assessment.RiskFlags -join "; " } else { "" }
        ReviewReasons           = @($assessment.ReviewReasons)
        ReviewReasonsText       = if ($assessment.ReviewReasons.Count -gt 0) { $assessment.ReviewReasons -join " " } else { "" }
        RecommendedAction       = $assessment.RecommendedAction
        NextReviewStep          = $assessment.NextReviewStep
        Description             = $description
        DistinguishedName       = $dn
    }
}

function Get-ActionPriority {
    param([string]$ReviewPriority)

    switch ($ReviewPriority) {
        "Critical" { return "P1 - Remove or approve exception" }
        "High" { return "P2 - Rotation or exception review" }
        "Medium" { return "P3 - Justification review" }
        "Low" { return "P4 - Disabled cleanup validation" }
        "Hold" { return "Hold - System managed" }
        default { return "P5 - Manual review" }
    }
}

function Get-PrioritySortValue {
    param([AllowNull()][object]$Value)

    $text = "$Value"
    if ($text -match "^P(\d+)") {
        return [int]$Matches[1]
    }
    if ($text -match "^Hold") {
        return 8
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
        "ReviewPriority",
        "ActionPriority",
        "AccountCategory",
        "RotationReadiness",
        "SamAccountName",
        "Name",
        "UserPrincipalName",
        "SID",
        "Enabled",
        "PasswordNeverExpires",
        "PasswordLastSetUtc",
        "PasswordAgeDays",
        "LastLogonDateUtc",
        "InactiveDays",
        "HasSPN",
        "SPNCount",
        "ServicePrincipalNamesText",
        "AdminCount",
        "PrivilegedGroupCount",
        "PrivilegedGroupsText",
        "DoesNotRequirePreAuth",
        "TrustedForDelegation",
        "TrustedToAuthForDelegation",
        "ManagedBy",
        "OwnerEvidenceMissing",
        "ExceptionRequired",
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
            ReportType     = "ADPasswordNeverExpires"
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
        PasswordNeverExpiresAccounts = @()
    }

    $report | ConvertTo-Json -Depth 6 | Out-File -FilePath $JsonPath -Encoding utf8
}

function Add-MarkdownPasswordAccountTable {
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

    Add-MarkdownLine -Lines $Lines -Text "| Priority | Account | Category | Enabled | Password age | Exception | Risk flags | Next step |"
    Add-MarkdownLine -Lines $Lines -Text "|---|---|---|---:|---:|---:|---|---|"
    foreach ($row in @($Rows | Select-Object -First $Limit)) {
        Add-MarkdownLine -Lines $Lines -Text ("| {0} | {1} | {2} | {3} | {4} | {5} | {6} | {7} |" -f `
                (ConvertTo-MarkdownSafeText $row.ActionPriority),
            (ConvertTo-MarkdownSafeText $row.SamAccountName),
            (ConvertTo-MarkdownSafeText $row.AccountCategory),
            (ConvertTo-MarkdownSafeText $row.Enabled),
            (ConvertTo-MarkdownSafeText $row.PasswordAgeDays),
            (ConvertTo-MarkdownSafeText $row.ExceptionRequired),
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
    $rows = @($Report["PasswordNeverExpiresAccounts"])
    $lines = New-Object System.Collections.Generic.List[string]

    Add-MarkdownLine -Lines $lines -Text "# AD Password Never Expires Review"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "Generated UTC: ``$($metadata.GeneratedAtUtc)``"
    Add-MarkdownLine -Lines $lines -Text "Computer: ``$($metadata.ComputerName)``"
    Add-MarkdownLine -Lines $lines -Text "Search base: ``$(if ($metadata.SearchBase) { $metadata.SearchBase } else { 'Domain default' })``"
    Add-MarkdownLine -Lines $lines

    Add-MarkdownLine -Lines $lines -Text "## Summary"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "| Metric | Count |"
    Add-MarkdownLine -Lines $lines -Text "|---|---:|"
    foreach ($metric in @("TotalAccounts", "CriticalAccounts", "HighAccounts", "PrivilegedAccounts", "ServiceAccountCandidates", "SPNAccounts", "MissingOwnerAccounts", "OldPasswordAccounts", "DisabledAccounts", "ExceptionRequiredAccounts")) {
        Add-MarkdownLine -Lines $lines -Text ("| {0} | {1} |" -f $metric, $summary.$metric)
    }
    Add-MarkdownLine -Lines $lines

    Add-MarkdownLine -Lines $lines -Text "## Admin Action Plan"
    Add-MarkdownLine -Lines $lines
    if ($summary.CriticalAccounts -gt 0) {
        Add-MarkdownLine -Lines $lines -Text "Critical PasswordNeverExpires accounts exist. Start with privileged accounts, built-in Administrator, delegation, or pre-authentication disabled."
    }
    elseif ($summary.HighAccounts -gt 0) {
        Add-MarkdownLine -Lines $lines -Text "High review accounts exist. Prioritize service accounts, SPN accounts, old passwords, and missing owners."
    }
    else {
        Add-MarkdownLine -Lines $lines -Text "No Critical or High PasswordNeverExpires accounts were detected in this run."
    }
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "Do not remove PasswordNeverExpires blindly. Confirm owner, service dependency, maintenance window, rollback, and exception status first."
    Add-MarkdownLine -Lines $lines

    Add-MarkdownLine -Lines $lines -Text "## Critical"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownPasswordAccountTable -Lines $lines -Rows @($rows | Where-Object { $_.ReviewPriority -eq "Critical" } | Sort-Object SamAccountName)

    Add-MarkdownLine -Lines $lines -Text "## High"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownPasswordAccountTable -Lines $lines -Rows @($rows | Where-Object { $_.ReviewPriority -eq "High" } | Sort-Object SamAccountName)

    Add-MarkdownLine -Lines $lines -Text "## All PasswordNeverExpires Accounts"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownPasswordAccountTable -Lines $lines -Rows @($rows | Sort-Object @{ Expression = { Get-PrioritySortValue -Value $_.ActionPriority } }, SamAccountName) -Limit 100

    Add-MarkdownLine -Lines $lines -Text "## Review Rules"
    Add-MarkdownLine -Lines $lines
    foreach ($note in @($summary.Notes)) {
        Add-MarkdownLine -Lines $lines -Text "- $note"
    }

    $lines | Out-File -FilePath $Path -Encoding utf8
}

New-Directory -Path $OutputDirectory
$resolvedOutputDirectory = (Resolve-Path -Path $OutputDirectory).Path
$jsonPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "password-never-expires.json"
$csvPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "password-never-expires.csv"
$markdownPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "password-never-expires-review.md"

if (-not (Import-ActiveDirectoryModule)) {
    $reason = "ActiveDirectory PowerShell module was not found. Install RSAT Active Directory tools or run this script on a domain management host."
    Write-FailedReport -JsonPath $jsonPath -Reason $reason
    throw $reason
}

$now = Get-Date
$commonParameters = Get-ADCommonParameters
$domainSummary = Get-DomainSummary -CommonParameters $commonParameters
$enabledClause = if ($IncludeDisabled) { "" } else { "(!(userAccountControl:1.2.840.113556.1.4.803:=2))" }
$pneFilter = "(&(objectCategory=person)(objectClass=user)$enabledClause(userAccountControl:1.2.840.113556.1.4.803:=65536))"

$userParameters = @{
    LDAPFilter  = $pneFilter
    Properties  = @(
        "AdminCount",
        "Description",
        "DoesNotRequirePreAuth",
        "Enabled",
        "info",
        "LastLogonDate",
        "lastLogonTimestamp",
        "ManagedBy",
        "memberOf",
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
    $reason = "Active Directory PasswordNeverExpires query failed: $($_.Exception.Message)"
    Write-FailedReport -JsonPath $jsonPath -Reason $reason
    throw $reason
}

$passwordRows = @($users | ForEach-Object { ConvertTo-PasswordNeverExpiresRow -User $_ -Now $now } | Sort-Object @{ Expression = { Get-PrioritySortValue -Value $_.ActionPriority } }, SamAccountName)

$summary = [ordered]@{
    TotalAccounts              = $passwordRows.Count
    CriticalAccounts           = @($passwordRows | Where-Object { $_.ReviewPriority -eq "Critical" }).Count
    HighAccounts               = @($passwordRows | Where-Object { $_.ReviewPriority -eq "High" }).Count
    MediumAccounts             = @($passwordRows | Where-Object { $_.ReviewPriority -eq "Medium" }).Count
    LowAccounts                = @($passwordRows | Where-Object { $_.ReviewPriority -eq "Low" }).Count
    HoldAccounts               = @($passwordRows | Where-Object { $_.ReviewPriority -eq "Hold" }).Count
    PrivilegedAccounts         = @($passwordRows | Where-Object { $_.AccountCategory -in @("BuiltInAdministrator", "PrivilegedAccount") }).Count
    ServiceAccountCandidates   = @($passwordRows | Where-Object { $_.AccountCategory -in @("SPNServiceAccount", "ServiceAccountCandidate") }).Count
    SPNAccounts                = @($passwordRows | Where-Object { $_.HasSPN }).Count
    MissingOwnerAccounts       = @($passwordRows | Where-Object { $_.OwnerEvidenceMissing }).Count
    OldPasswordAccounts        = @($passwordRows | Where-Object { $_.PasswordAgeDays -ne $null -and $_.PasswordAgeDays -gt $MaxPasswordAgeDays }).Count
    DisabledAccounts           = @($passwordRows | Where-Object { -not $_.Enabled }).Count
    ExceptionRequiredAccounts  = @($passwordRows | Where-Object { $_.ExceptionRequired }).Count
    Notes                      = @(
        "This script is audit-only and does not change password policy or account attributes.",
        "PasswordNeverExpires is not always wrong for a service account, but it must have owner, dependency, rotation, and exception evidence.",
        "Privileged accounts with PasswordNeverExpires should be reviewed first.",
        "SPN-bearing accounts should also be reviewed with the SPN exposure report.",
        "Disabled accounts are cleanup candidates only after dependency validation and approved change control.",
        "Exchange HealthMailbox accounts are marked Hold and should not be treated like normal users."
    )
}

$report = [ordered]@{
    ReportMetadata = [ordered]@{
        SchemaVersion      = "1.0"
        ReportType         = "ADPasswordNeverExpires"
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
    Domain                       = $domainSummary
    Summary                      = $summary
    PasswordNeverExpiresAccounts = @($passwordRows)
}

$report | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding utf8
Write-CsvReport -Path $csvPath -Rows $passwordRows
Write-MarkdownReport -Path $markdownPath -Report $report

if (-not $Quiet) {
    Write-Host "AD PasswordNeverExpires report written to: $jsonPath"
    Write-Host "AD PasswordNeverExpires review written to: $markdownPath"
    Write-Host "Accounts: $($summary.TotalAccounts)"
    Write-Host "Critical: $($summary.CriticalAccounts)"
    Write-Host "High: $($summary.HighAccounts)"
}
