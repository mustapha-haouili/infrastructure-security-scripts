<#
.SYNOPSIS
Reports inactive Active Directory user accounts with last logon evidence.

.DESCRIPTION
This script audits Active Directory users and writes JSON plus CSV reports for
accounts that have not logged on within the selected threshold.

It does not change Active Directory.

The report uses LastLogonDate, which is based on the replicated
lastLogonTimestamp attribute. That value is suitable for cleanup reporting, but
it can lag behind real logon activity. Use a conservative threshold such as 90
days or more before operational action.

Each account is classified with ReviewPriority, AccountCategory, and
DeletionReadiness. Enabled accounts are never marked safe for immediate
deletion. System-managed Exchange HealthMailbox accounts are placed on hold so
they are not treated like normal inactive users.

.PARAMETER DaysInactive
Number of days since last logon before an account is reported as inactive.
Default: 90

.PARAMETER SearchBase
Optional distinguished name for the OU or domain path to search.

.PARAMETER Server
Optional domain controller or AD LDS instance to query.

.PARAMETER Credential
Optional credential for the AD query.

.PARAMETER IncludeDisabled
Include disabled user accounts in the report. By default, only enabled users
are scanned.

.PARAMETER ExcludeNeverLoggedOn
Exclude accounts that have never logged on. By default, never-logged-on
accounts older than the inactivity threshold are included.

.PARAMETER OutputDirectory
Directory where inactive-users.json, inactive-users.csv, and
inactive-users-review.md are written.
Default: .\reports\ad-inactive-users-COMPUTER-TIMESTAMP

.PARAMETER Quiet
Suppress console summary. Useful for scheduled reporting.

.EXAMPLE
.\Get-ADInactiveUserReport.ps1

Report enabled users inactive for 90 days or more.

.EXAMPLE
.\Get-ADInactiveUserReport.ps1 -DaysInactive 180 -SearchBase "OU=Users,DC=example,DC=com"

Report enabled users in a specific OU inactive for 180 days or more.

.EXAMPLE
.\Get-ADInactiveUserReport.ps1 -IncludeDisabled -OutputDirectory .\reports\ad-users

Include disabled accounts and write reports to a known directory.
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
    [string]$OutputDirectory = ".\reports\ad-inactive-users-$env:COMPUTERNAME-$(Get-Date -Format 'yyyyMMdd-HHmmss')",
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
    if ($PSBoundParameters.ContainsKey("Credential")) {
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
        "AccountCategory",
        "LifecycleStage",
        "DeletionReadiness",
        "CanDeleteNow",
        "PotentialDeletionCandidate",
        "NextReviewStep",
        "SamAccountName",
        "Name",
        "UserPrincipalName",
        "SID",
        "Enabled",
        "InactiveDays",
        "DaysSinceCreated",
        "NeverLoggedOn",
        "LastLogonDateUtc",
        "WhenCreatedUtc",
        "WhenChangedUtc",
        "AccountExpirationDateUtc",
        "PasswordLastSetUtc",
        "PasswordNeverExpires",
        "AdminCount",
        "HasSPN",
        "SPNCount",
        "HasMailAttributes",
        "Mail",
        "ProxyAddressCount",
        "DirectGroupCount",
        "PrivilegedGroupCount",
        "PrivilegedGroupsText",
        "DependencySignalsText",
        "RiskFlagsText",
        "ReviewReasonsText",
        "ActivityEvidenceSource",
        "ActivityEvidenceConfidence",
        "ActivityValidationRequired",
        "Classification",
        "ClassificationReason",
        "ServiceAccountConfidence",
        "AccountReviewReason",
        "RecommendedAction",
        "DeletionGuidance",
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
            ReportType           = "ADInactiveUsers"
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
        InactiveUsers = @()
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

function Add-MarkdownUserTable {
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

    Add-MarkdownLine -Lines $Lines -Text "| Priority | Account | Category | Enabled | Inactive | Dependencies | Next step |"
    Add-MarkdownLine -Lines $Lines -Text "|---|---|---|---:|---:|---|---|"
    foreach ($row in @($Rows | Select-Object -First $Limit)) {
        $inactive = if ($null -ne $row.InactiveDays) { $row.InactiveDays } elseif ($row.NeverLoggedOn) { "Never" } else { "" }
        Add-MarkdownLine -Lines $Lines -Text ("| {0} | {1} | {2} | {3} | {4} | {5} | {6} |" -f `
                (ConvertTo-MarkdownSafeText $row.ReviewPriority),
            (ConvertTo-MarkdownSafeText $row.SamAccountName),
            (ConvertTo-MarkdownSafeText $row.AccountCategory),
            (ConvertTo-MarkdownSafeText $row.Enabled),
            (ConvertTo-MarkdownSafeText $inactive),
            (ConvertTo-MarkdownSafeText $row.DependencySignalsText),
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
    $rows = @($Report["InactiveUsers"])
    $lines = New-Object System.Collections.Generic.List[string]

    Add-MarkdownLine -Lines $lines -Text "# AD Inactive User Review"
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
    foreach ($metric in @("TotalUsersScanned", "InactiveUsers", "EnabledInactiveUsers", "DisabledInactiveUsers", "CriticalPriorityUsers", "HighPriorityReviewUsers", "HoldSystemManagedUsers", "PotentialDeletionCandidates", "CanDeleteNowUsers")) {
        Add-MarkdownLine -Lines $lines -Text ("| {0} | {1} |" -f $metric, $summary.$metric)
    }
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "> CanDeleteNow is always false. Use disable, quarantine, dependency review, and owner approval before deletion."
    Add-MarkdownLine -Lines $lines

    Add-MarkdownLine -Lines $lines -Text "## Critical"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownUserTable -Lines $lines -Rows @($rows | Where-Object { $_.ReviewPriority -eq "Critical" })

    Add-MarkdownLine -Lines $lines -Text "## High"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownUserTable -Lines $lines -Rows @($rows | Where-Object { $_.ReviewPriority -eq "High" })

    Add-MarkdownLine -Lines $lines -Text "## Hold / System Managed"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownUserTable -Lines $lines -Rows @($rows | Where-Object { $_.ReviewPriority -eq "Hold" })

    Add-MarkdownLine -Lines $lines -Text "## Potential Deletion Candidates"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "These are still not approved for deletion. They are only candidates after owner approval, quarantine, dependency checks, and rollback planning."
    Add-MarkdownLine -Lines $lines
    Add-MarkdownUserTable -Lines $lines -Rows @($rows | Where-Object { $_.PotentialDeletionCandidate })

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

function Get-RiskFlags {
    param(
        [Parameter(Mandatory = $true)][object]$User,
        [bool]$NeverLoggedOn,
        [bool]$HasSPN,
        [bool]$IsSystemManagedAccount,
        [bool]$IsServiceAccountCandidate,
        [bool]$HasMailAttributes,
        [int]$PrivilegedGroupCount
    )

    $flags = New-Object System.Collections.Generic.List[string]

    if ($IsSystemManagedAccount) {
        $flags.Add("SystemManagedAccount") | Out-Null
    }
    if ($User.Enabled) {
        $flags.Add("Enabled") | Out-Null
    }
    if ($NeverLoggedOn) {
        $flags.Add("NeverLoggedOn") | Out-Null
    }
    if ($User.PasswordNeverExpires) {
        $flags.Add("PasswordNeverExpires") | Out-Null
    }
    if ($User.AdminCount -eq 1) {
        $flags.Add("AdminCount1") | Out-Null
    }
    if ($HasSPN) {
        $flags.Add("HasSPN") | Out-Null
    }
    if ($HasMailAttributes) {
        $flags.Add("MailEnabled") | Out-Null
    }
    if ($PrivilegedGroupCount -gt 0) {
        $flags.Add("PrivilegedGroupMember") | Out-Null
    }
    if ($IsServiceAccountCandidate) {
        $flags.Add("ServiceAccountCandidate") | Out-Null
    }
    if ($User.LockedOut) {
        $flags.Add("LockedOut") | Out-Null
    }

    return @($flags.ToArray())
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

    $privilegedGroupPattern = '(?i)^(Domain Admins|Enterprise Admins|Schema Admins|Administrators|Account Operators|Server Operators|Backup Operators|Print Operators|DnsAdmins|Group Policy Creator Owners|Protected Users)$'
    return @(Convert-DistinguishedNamesToNames -DistinguishedNames $GroupDistinguishedNames | Where-Object { $_ -match $privilegedGroupPattern })
}

function Test-MailEnabledAccount {
    param(
        [AllowNull()][string]$Mail,
        [AllowNull()][object[]]$ProxyAddresses
    )

    return [bool]($Mail -or @($ProxyAddresses | Where-Object { $_ }).Count -gt 0)
}

function Get-DependencySignals {
    param(
        [bool]$HasSPN,
        [bool]$HasMailAttributes,
        [int]$DirectGroupCount,
        [int]$PrivilegedGroupCount,
        [bool]$IsServiceAccountCandidate,
        [bool]$IsExchangeHealthMailbox
    )

    $signals = New-Object System.Collections.Generic.List[string]

    if ($IsExchangeHealthMailbox) {
        $signals.Add("ExchangeHealthMailbox") | Out-Null
    }
    if ($HasSPN) {
        $signals.Add("SPN") | Out-Null
    }
    if ($HasMailAttributes) {
        $signals.Add("MailAttributes") | Out-Null
    }
    if ($PrivilegedGroupCount -gt 0) {
        $signals.Add("PrivilegedGroups:$PrivilegedGroupCount") | Out-Null
    }
    if ($DirectGroupCount -gt 0) {
        $signals.Add("DirectGroups:$DirectGroupCount") | Out-Null
    }
    if ($IsServiceAccountCandidate) {
        $signals.Add("ServiceNamePattern") | Out-Null
    }

    return @($signals.ToArray())
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
    return [bool]($haystack -match "(?i)(^|[^a-z])(svc|service|srv|app|sql|iis|iusr|iwam|backup|bkp|cron|task|job|vpn|syslog|docker|svn|api|ldap)([^a-z]|$)")
}

function Get-AccountCategory {
    param(
        [Parameter(Mandatory = $true)][object]$User,
        [bool]$IsExchangeHealthMailbox,
        [bool]$IsServiceAccountCandidate,
        [bool]$HasSPN,
        [int]$PrivilegedGroupCount
    )

    if ($IsExchangeHealthMailbox) {
        return "ExchangeHealthMailbox"
    }

    if ($User.SamAccountName -eq "Administrator" -or "$($User.SID)" -match "-500$") {
        return "BuiltInAdministrator"
    }

    if ($User.AdminCount -eq 1 -or $PrivilegedGroupCount -gt 0) {
        return "PrivilegedAccount"
    }

    if ($HasSPN) {
        return "SPNServiceAccount"
    }

    if ($IsServiceAccountCandidate) {
        return "ServiceAccountCandidate"
    }

    return "StandardUser"
}

function Get-ReviewReasons {
    param(
        [Parameter(Mandatory = $true)][object]$User,
        [string]$AccountCategory,
        [bool]$NeverLoggedOn,
        [bool]$HasSPN,
        [bool]$IsServiceAccountCandidate,
        [bool]$HasMailAttributes,
        [int]$PrivilegedGroupCount
    )

    $reasons = New-Object System.Collections.Generic.List[string]

    switch ($AccountCategory) {
        "ExchangeHealthMailbox" {
            $reasons.Add("Exchange monitoring mailbox under Microsoft Exchange System Objects; do not clean up like a normal user.") | Out-Null
        }
        "BuiltInAdministrator" {
            $reasons.Add("Built-in Administrator account is enabled and inactive.") | Out-Null
        }
        "PrivilegedAccount" {
            $reasons.Add("AdminCount=1 indicates privileged or formerly protected account.") | Out-Null
        }
        "SPNServiceAccount" {
            $reasons.Add("Account has SPN values and may be used by a service.") | Out-Null
        }
    }

    if ($User.Enabled) {
        $reasons.Add("Account is still enabled; deletion is not safe.") | Out-Null
    }
    if ($NeverLoggedOn) {
        $reasons.Add("Account has never logged on and is older than the inactivity threshold.") | Out-Null
    }
    if ($User.PasswordNeverExpires) {
        $reasons.Add("PasswordNeverExpires is set.") | Out-Null
    }
    if ($HasSPN) {
        $reasons.Add("SPN present; check service dependency and Kerberoasting exposure.") | Out-Null
    }
    if ($HasMailAttributes) {
        $reasons.Add("Mail attributes present; check mailbox or mail-enabled object ownership.") | Out-Null
    }
    if ($PrivilegedGroupCount -gt 0) {
        $reasons.Add("Direct privileged group membership found.") | Out-Null
    }
    if ($IsServiceAccountCandidate -and $AccountCategory -ne "ExchangeHealthMailbox" -and $AccountCategory -ne "SPNServiceAccount") {
        $reasons.Add("Name, description, or OU suggests a service/shared account.") | Out-Null
    }

    return @($reasons.ToArray())
}

function Get-ReviewPriority {
    param(
        [Parameter(Mandatory = $true)][object]$User,
        [string]$AccountCategory,
        [bool]$HasSPN,
        [bool]$IsServiceAccountCandidate
    )

    if ($AccountCategory -eq "ExchangeHealthMailbox") {
        return "Hold"
    }

    if ($User.Enabled -and ($AccountCategory -in @("BuiltInAdministrator", "PrivilegedAccount"))) {
        return "Critical"
    }

    if ($User.Enabled -and $HasSPN) {
        return "Critical"
    }

    if (-not $User.Enabled) {
        if ($AccountCategory -in @("BuiltInAdministrator", "PrivilegedAccount", "SPNServiceAccount", "ServiceAccountCandidate")) {
            return "Medium"
        }
        return "Low"
    }

    if ($User.PasswordNeverExpires -or $IsServiceAccountCandidate) {
        return "High"
    }

    return "Medium"
}

function Get-LifecycleStage {
    param(
        [Parameter(Mandatory = $true)][object]$User,
        [string]$ReviewPriority
    )

    if ($ReviewPriority -eq "Hold") {
        return "HoldSystemManaged"
    }

    if ($User.Enabled -and $ReviewPriority -eq "Critical") {
        return "UrgentOwnerReview"
    }

    if ($User.Enabled) {
        return "OwnerReviewBeforeDisable"
    }

    return "DisabledRetentionReview"
}

function Get-NextReviewStep {
    param(
        [string]$ReviewPriority,
        [string]$DeletionReadiness
    )

    if ($ReviewPriority -eq "Critical") {
        return "Urgent owner/security review before any disable action."
    }

    if ($ReviewPriority -eq "Hold") {
        return "Hold out of normal cleanup; validate with owning platform team."
    }

    switch ($DeletionReadiness) {
        "NotReadyEnabledAccount" {
            return "Confirm owner and business need, then disable/quarantine if approved."
        }
        "NotReadyEnabledPrivilegedOrSPN" {
            return "Remove privilege/SPN dependency first, then disable only after approval."
        }
        "DisabledButPrivilegedOrSPNReviewRequired" {
            return "Confirm privilege/SPN dependency is removed before deletion review."
        }
        "DisabledServiceOrSharedAccountReviewRequired" {
            return "Check service/shared dependencies before deletion review."
        }
        "DeletionCandidateAfterQuarantineAndOwnerApproval" {
            return "Candidate for deletion review after quarantine and owner approval."
        }
        default {
            return "Manual review required."
        }
    }
}

function Get-DeletionReadiness {
    param(
        [Parameter(Mandatory = $true)][object]$User,
        [string]$AccountCategory,
        [bool]$HasSPN,
        [bool]$IsServiceAccountCandidate
    )

    if ($AccountCategory -eq "ExchangeHealthMailbox") {
        return "DoNotDeleteSystemManaged"
    }

    if ($AccountCategory -eq "BuiltInAdministrator") {
        return "DoNotDeleteBuiltInAccount"
    }

    if ($User.Enabled -and ($AccountCategory -in @("BuiltInAdministrator", "PrivilegedAccount") -or $HasSPN)) {
        return "NotReadyEnabledPrivilegedOrSPN"
    }

    if ($User.Enabled) {
        return "NotReadyEnabledAccount"
    }

    if ($AccountCategory -in @("PrivilegedAccount", "SPNServiceAccount") -or $HasSPN) {
        return "DisabledButPrivilegedOrSPNReviewRequired"
    }

    if ($IsServiceAccountCandidate -or $User.PasswordNeverExpires) {
        return "DisabledServiceOrSharedAccountReviewRequired"
    }

    return "DeletionCandidateAfterQuarantineAndOwnerApproval"
}

function Get-Recommendation {
    param(
        [Parameter(Mandatory = $true)][object]$User,
        [string]$AccountCategory,
        [string]$ReviewPriority,
        [string]$DeletionReadiness,
        [bool]$NeverLoggedOn
    )

    if ($AccountCategory -eq "ExchangeHealthMailbox") {
        return "Hold. Do not disable or delete as normal AD cleanup. Validate Exchange health and remove only through an Exchange-supported decommission or cleanup process."
    }

    if ($AccountCategory -eq "BuiltInAdministrator") {
        return "Do not delete the built-in Administrator account. Keep it disabled or tightly controlled according to the domain break-glass policy."
    }

    if (-not $User.Enabled) {
        if ($DeletionReadiness -eq "DeletionCandidateAfterQuarantineAndOwnerApproval") {
            return "Possible deletion candidate only after confirming owner approval, disabled quarantine period, no mailbox, no service dependency, and backup/restore requirements."
        }
        return "Already disabled, but still requires dependency review before deletion."
    }

    if ($ReviewPriority -eq "Critical") {
        return "Critical. Do not delete. Review urgently, remove unnecessary privilege/SPN, then disable only through an approved change."
    }

    if ($AccountCategory -eq "ServiceAccountCandidate" -or $AccountCategory -eq "SPNServiceAccount") {
        return "Do not delete directly. Confirm service, scheduled task, IIS app pool, backup, VPN, or LDAP bind dependency before disable/quarantine."
    }

    if ($NeverLoggedOn) {
        return "Confirm account purpose and owner. If unused, disable and quarantine before considering deletion."
    }

    return "Confirm ownership and business need, then disable through the approved access lifecycle process."
}

function Get-DeletionGuidance {
    param(
        [string]$DeletionReadiness
    )

    switch ($DeletionReadiness) {
        "DoNotDeleteSystemManaged" {
            return "Do not delete from AD as a normal inactive-user cleanup item. Manage through the owning product process."
        }
        "DoNotDeleteBuiltInAccount" {
            return "Do not delete built-in AD accounts. Disable or protect them through domain policy and break-glass procedures."
        }
        "NotReadyEnabledPrivilegedOrSPN" {
            return "Not delete-ready. Enabled privileged/SPN accounts must be reviewed, remediated, disabled, and monitored before any deletion discussion."
        }
        "NotReadyEnabledAccount" {
            return "Not delete-ready. Enabled accounts must first pass owner review, then be disabled and quarantined."
        }
        "DisabledButPrivilegedOrSPNReviewRequired" {
            return "Disabled but still sensitive. Confirm no privilege, SPN, mailbox, service, or application dependency remains."
        }
        "DisabledServiceOrSharedAccountReviewRequired" {
            return "Disabled but service/shared signals remain. Confirm no service, task, IIS, backup, VPN, or LDAP dependency remains."
        }
        "DeletionCandidateAfterQuarantineAndOwnerApproval" {
            return "Potential deletion candidate after documented owner approval, quarantine period, and backup/restore confirmation."
        }
        default {
            return "Manual review required before deletion."
        }
    }
}

function Get-PrioritySortOrder {
    param([AllowNull()][string]$ReviewPriority)

    switch ($ReviewPriority) {
        "Critical" { return 0 }
        "High" { return 1 }
        "Medium" { return 2 }
        "Low" { return 3 }
        "Hold" { return 4 }
        default { return 5 }
    }
}

New-Directory -Path $OutputDirectory
$resolvedOutputDirectory = (Resolve-Path -Path $OutputDirectory).Path
$jsonPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "inactive-users.json"
$csvPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "inactive-users.csv"
$markdownPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "inactive-users-review.md"

if (-not (Import-ActiveDirectoryModule)) {
    $reason = "ActiveDirectory PowerShell module was not found. Install RSAT Active Directory tools or run this script on a domain management host."
    Write-FailedReport -JsonPath $jsonPath -Reason $reason
    throw $reason
}

$now = Get-Date
$cutoff = $now.AddDays(-1 * $DaysInactive)
$commonParameters = Get-ADCommonParameters
$domainSummary = Get-DomainSummary -CommonParameters $commonParameters

$userParameters = @{
    Filter      = if ($IncludeDisabled) { "*" } else { "Enabled -eq `$true" }
    Properties  = @(
        "AdminCount",
        "AccountExpirationDate",
        "Department",
        "Description",
        "Enabled",
        "LastLogonDate",
        "lastLogonTimestamp",
        "LockedOut",
        "mail",
        "Manager",
        "memberOf",
        "PasswordExpired",
        "PasswordLastSet",
        "PasswordNeverExpires",
        "proxyAddresses",
        "ServicePrincipalName",
        "SID",
        "Title",
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
    $reason = "Active Directory user query failed: $($_.Exception.Message)"
    Write-FailedReport -JsonPath $jsonPath -Reason $reason
    throw $reason
}

$inactiveUsers = New-Object System.Collections.Generic.List[object]

foreach ($user in $users) {
    $lastLogonDate = $user.LastLogonDate
    $whenCreated = $user.WhenCreated
    $neverLoggedOn = $null -eq $lastLogonDate
    $createdBeforeCutoff = $whenCreated -and ([datetime]$whenCreated -le $cutoff)

    $isInactive = $false
    if ($lastLogonDate -and ([datetime]$lastLogonDate -le $cutoff)) {
        $isInactive = $true
    }
    elseif ($neverLoggedOn -and -not $ExcludeNeverLoggedOn -and $createdBeforeCutoff) {
        $isInactive = $true
    }

    if (-not $isInactive) {
        continue
    }

    $spns = @($user.ServicePrincipalName | Where-Object { $_ })
    $hasSpn = $spns.Count -gt 0
    $proxyAddresses = @($user.proxyAddresses | Where-Object { $_ })
    $memberOf = @($user.memberOf | Where-Object { $_ })
    $directGroupNames = @(Convert-DistinguishedNamesToNames -DistinguishedNames $memberOf)
    $privilegedGroupNames = @(Get-PrivilegedGroupNames -GroupDistinguishedNames $memberOf)
    $hasMailAttributes = Test-MailEnabledAccount -Mail $user.mail -ProxyAddresses $proxyAddresses
    $inactiveDays = if ($lastLogonDate) { [int](New-TimeSpan -Start ([datetime]$lastLogonDate) -End $now).TotalDays } else { $null }
    $daysSinceCreated = if ($whenCreated) { [int](New-TimeSpan -Start ([datetime]$whenCreated) -End $now).TotalDays } else { $null }
    $isExchangeHealthMailbox = Test-ExchangeHealthMailbox -SamAccountName $user.SamAccountName -Name $user.Name -DistinguishedName $user.DistinguishedName
    $isServiceAccountCandidate = Test-ServiceAccountCandidate -SamAccountName $user.SamAccountName -Name $user.Name -Description $user.Description -DistinguishedName $user.DistinguishedName -HasSPN $hasSpn
    $dependencySignals = @(Get-DependencySignals -HasSPN $hasSpn -HasMailAttributes $hasMailAttributes -DirectGroupCount $directGroupNames.Count -PrivilegedGroupCount $privilegedGroupNames.Count -IsServiceAccountCandidate $isServiceAccountCandidate -IsExchangeHealthMailbox $isExchangeHealthMailbox)
    $accountCategory = Get-AccountCategory -User $user -IsExchangeHealthMailbox $isExchangeHealthMailbox -IsServiceAccountCandidate $isServiceAccountCandidate -HasSPN $hasSpn -PrivilegedGroupCount $privilegedGroupNames.Count
    $reviewPriority = Get-ReviewPriority -User $user -AccountCategory $accountCategory -HasSPN $hasSpn -IsServiceAccountCandidate $isServiceAccountCandidate
    $lifecycleStage = Get-LifecycleStage -User $user -ReviewPriority $reviewPriority
    $deletionReadiness = Get-DeletionReadiness -User $user -AccountCategory $accountCategory -HasSPN $hasSpn -IsServiceAccountCandidate $isServiceAccountCandidate
    $riskFlags = @(Get-RiskFlags -User $user -NeverLoggedOn $neverLoggedOn -HasSPN $hasSpn -IsSystemManagedAccount $isExchangeHealthMailbox -IsServiceAccountCandidate $isServiceAccountCandidate -HasMailAttributes $hasMailAttributes -PrivilegedGroupCount $privilegedGroupNames.Count)
    $reviewReasons = @(Get-ReviewReasons -User $user -AccountCategory $accountCategory -NeverLoggedOn $neverLoggedOn -HasSPN $hasSpn -IsServiceAccountCandidate $isServiceAccountCandidate -HasMailAttributes $hasMailAttributes -PrivilegedGroupCount $privilegedGroupNames.Count)
    $canDeleteNow = $false
    $potentialDeletionCandidate = $deletionReadiness -eq "DeletionCandidateAfterQuarantineAndOwnerApproval"
    $nextReviewStep = Get-NextReviewStep -ReviewPriority $reviewPriority -DeletionReadiness $deletionReadiness

    $inactiveUsers.Add([pscustomobject][ordered]@{
            ReviewPriority          = $reviewPriority
            AccountCategory         = $accountCategory
            LifecycleStage          = $lifecycleStage
            DeletionReadiness       = $deletionReadiness
            CanDeleteNow            = $canDeleteNow
            PotentialDeletionCandidate = $potentialDeletionCandidate
            NextReviewStep          = $nextReviewStep
            SamAccountName          = $user.SamAccountName
            Name                    = $user.Name
            UserPrincipalName       = $user.UserPrincipalName
            SID                     = "$($user.SID)"
            Enabled                 = [bool]$user.Enabled
            InactiveDays            = $inactiveDays
            DaysSinceCreated        = $daysSinceCreated
            NeverLoggedOn           = [bool]$neverLoggedOn
            LastLogonDateUtc        = Format-DateTimeUtc -Value $lastLogonDate
            LastLogonTimestampUtc   = Convert-ADFileTimeToUtc -Value $user.lastLogonTimestamp
            LastLogonEvidence       = if ($neverLoggedOn) { "No LastLogonDate/lastLogonTimestamp present." } else { "LastLogonDate from replicated lastLogonTimestamp." }
            WhenCreatedUtc          = Format-DateTimeUtc -Value $whenCreated
            WhenChangedUtc          = Format-DateTimeUtc -Value $user.whenChanged
            AccountExpirationDateUtc = Format-DateTimeUtc -Value $user.AccountExpirationDate
            PasswordLastSetUtc      = Format-DateTimeUtc -Value $user.PasswordLastSet
            PasswordNeverExpires    = [bool]$user.PasswordNeverExpires
            PasswordExpired         = [bool]$user.PasswordExpired
            LockedOut               = [bool]$user.LockedOut
            AdminCount              = if ($null -ne $user.AdminCount) { [int]$user.AdminCount } else { $null }
            HasSPN                  = [bool]$hasSpn
            SPNCount                = $spns.Count
            ServicePrincipalNames   = @($spns)
            HasMailAttributes       = [bool]$hasMailAttributes
            Mail                    = $user.mail
            ProxyAddressCount       = $proxyAddresses.Count
            ProxyAddresses          = @($proxyAddresses)
            DirectGroupCount        = $directGroupNames.Count
            DirectGroups            = @($directGroupNames)
            DirectGroupsText        = if ($directGroupNames.Count -gt 0) { $directGroupNames -join "; " } else { "" }
            PrivilegedGroupCount    = $privilegedGroupNames.Count
            PrivilegedGroups        = @($privilegedGroupNames)
            PrivilegedGroupsText    = if ($privilegedGroupNames.Count -gt 0) { $privilegedGroupNames -join "; " } else { "" }
            DependencySignals       = @($dependencySignals)
            DependencySignalsText   = if ($dependencySignals.Count -gt 0) { $dependencySignals -join "; " } else { "" }
            IsExchangeHealthMailbox = [bool]$isExchangeHealthMailbox
            IsServiceAccountCandidate = [bool]$isServiceAccountCandidate
            Department              = $user.Department
            Title                   = $user.Title
            Manager                 = $user.Manager
            Description             = $user.Description
            RiskFlags               = @($riskFlags)
            RiskFlagsText           = if ($riskFlags.Count -gt 0) { $riskFlags -join "; " } else { "" }
            ReviewReasons           = @($reviewReasons)
            ReviewReasonsText       = if ($reviewReasons.Count -gt 0) { $reviewReasons -join " " } else { "" }
            ActivityEvidenceSource  = if ($neverLoggedOn) { "No LastLogonDate/lastLogonTimestamp present." } else { "LastLogonDate from replicated lastLogonTimestamp." }
            ActivityEvidenceConfidence = "Medium"
            ActivityValidationRequired = $true
            Classification          = $accountCategory
            ClassificationReason    = if ($reviewReasons.Count -gt 0) { $reviewReasons[0] } else { "Account category assigned by inactive-user audit evidence." }
            ServiceAccountConfidence = if ($hasSpn) { "High" } elseif ($isServiceAccountCandidate) { "Medium" } else { "Low" }
            AccountReviewReason     = "Validate owner, usage evidence, exception status, and change approval before lifecycle action."
            RecommendedAction       = Get-Recommendation -User $user -AccountCategory $accountCategory -ReviewPriority $reviewPriority -DeletionReadiness $deletionReadiness -NeverLoggedOn $neverLoggedOn
            DeletionGuidance        = Get-DeletionGuidance -DeletionReadiness $deletionReadiness
            DistinguishedName       = $user.DistinguishedName
        }) | Out-Null
}

$inactiveRows = @($inactiveUsers.ToArray() | Sort-Object @{ Expression = {
            Get-PrioritySortOrder -ReviewPriority $_.ReviewPriority
        } }, SamAccountName)
$enabledInactive = @($inactiveRows | Where-Object { $_.Enabled }).Count
$disabledInactive = @($inactiveRows | Where-Object { -not $_.Enabled }).Count
$neverLoggedOnCount = @($inactiveRows | Where-Object { $_.NeverLoggedOn }).Count
$privilegedCount = @($inactiveRows | Where-Object { $_.AdminCount -eq 1 }).Count
$passwordNeverExpiresCount = @($inactiveRows | Where-Object { $_.PasswordNeverExpires }).Count
$spnCount = @($inactiveRows | Where-Object { $_.HasSPN }).Count
$mailEnabledCount = @($inactiveRows | Where-Object { $_.HasMailAttributes }).Count
$privilegedGroupMemberCount = @($inactiveRows | Where-Object { $_.PrivilegedGroupCount -gt 0 }).Count
$criticalPriorityCount = @($inactiveRows | Where-Object { $_.ReviewPriority -eq "Critical" }).Count
$highPriorityCount = @($inactiveRows | Where-Object { $_.ReviewPriority -eq "High" }).Count
$mediumPriorityCount = @($inactiveRows | Where-Object { $_.ReviewPriority -eq "Medium" }).Count
$lowPriorityCount = @($inactiveRows | Where-Object { $_.ReviewPriority -eq "Low" }).Count
$holdPriorityCount = @($inactiveRows | Where-Object { $_.ReviewPriority -eq "Hold" }).Count
$exchangeHealthMailboxCount = @($inactiveRows | Where-Object { $_.AccountCategory -eq "ExchangeHealthMailbox" }).Count
$serviceCandidateCount = @($inactiveRows | Where-Object { $_.IsServiceAccountCandidate }).Count
$notReadyDeletionCount = @($inactiveRows | Where-Object { -not $_.PotentialDeletionCandidate }).Count
$potentialDeletionCandidateCount = @($inactiveRows | Where-Object { $_.PotentialDeletionCandidate }).Count
$priorityCounts = [ordered]@{
    Critical = $criticalPriorityCount
    High     = $highPriorityCount
    Medium   = $mediumPriorityCount
    Low      = $lowPriorityCount
    Hold     = $holdPriorityCount
}

$report = [ordered]@{
    ReportMetadata = [ordered]@{
        SchemaVersion        = "1.0"
        ReportType           = "ADInactiveUsers"
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
        TotalUsersScanned          = $users.Count
        InactiveUsers              = $inactiveRows.Count
        EnabledInactiveUsers       = $enabledInactive
        DisabledInactiveUsers      = $disabledInactive
        NeverLoggedOnUsers         = $neverLoggedOnCount
        PrivilegedInactiveUsers    = $privilegedCount
        PasswordNeverExpiresUsers  = $passwordNeverExpiresCount
        SPNInactiveUsers           = $spnCount
        MailEnabledInactiveUsers   = $mailEnabledCount
        PrivilegedGroupMembers     = $privilegedGroupMemberCount
        ExchangeHealthMailboxUsers = $exchangeHealthMailboxCount
        ServiceAccountCandidates   = $serviceCandidateCount
        PriorityCounts             = $priorityCounts
        CriticalPriorityUsers      = $criticalPriorityCount
        HighPriorityReviewUsers    = $highPriorityCount
        HoldSystemManagedUsers     = $holdPriorityCount
        NotReadyForDeletionUsers   = $notReadyDeletionCount
        PotentialDeletionCandidates = $potentialDeletionCandidateCount
        CanDeleteNowUsers          = 0
        RecommendedFirstReview     = "Review Critical accounts first, then High service/shared accounts. Hold system-managed accounts such as Exchange HealthMailbox separately. No enabled account is safe to delete directly."
        Notes                      = @(
            "This script is audit-only and does not disable, delete, or modify accounts.",
            "LastLogonDate is based on replicated lastLogonTimestamp and can lag behind actual logon activity.",
            "Never-logged-on users are included only when the account was created before the inactivity cutoff.",
            "CanDeleteNow is always false because AD deletion needs owner approval, quarantine, dependency checks, and rollback planning.",
            "PotentialDeletionCandidate means disabled, non-system, non-privileged, non-SPN, and no service/shared-account signals were found; it is still not a delete-now approval.",
            "Exchange HealthMailbox accounts are system-managed and should be handled through Exchange processes, not normal inactive-user cleanup.",
            "Review ownership, mailbox, SPN, service, scheduled task, IIS app pool, VPN, backup, and LDAP bind dependencies before disabling any account."
        )
    }
    InactiveUsers = @($inactiveRows)
}

$report | ConvertTo-Json -Depth 8 | Out-File -FilePath $jsonPath -Encoding utf8
Write-CsvReport -Path $csvPath -Rows $inactiveRows
Write-MarkdownReport -Path $markdownPath -Report $report

if (-not $Quiet) {
    Write-Host "AD inactive user report written to: $jsonPath"
    Write-Host "AD inactive user CSV written to: $csvPath"
    Write-Host "AD inactive user review written to: $markdownPath"
    Write-Host "Users scanned: $($users.Count)"
    Write-Host "Inactive users: $($inactiveRows.Count)"
    Write-Host "Enabled inactive users: $enabledInactive"
    Write-Host "Critical priority users: $criticalPriorityCount"
    Write-Host "High priority review users: $highPriorityCount"
    Write-Host "Hold/system managed users: $holdPriorityCount"
}
