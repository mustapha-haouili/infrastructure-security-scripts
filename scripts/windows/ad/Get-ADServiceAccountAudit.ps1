<#
.SYNOPSIS
Audits Active Directory service account candidates.

.DESCRIPTION
This script reports user-based service accounts, SPN-bearing accounts, and
managed service accounts. It highlights risky properties such as privileged
membership, stale logon activity, password-never-expires, old passwords,
delegation, missing owner evidence, and pre-authentication disabled.

It is audit-only. It does not change Active Directory.

.PARAMETER SearchBase
Optional distinguished name for the OU or domain path to search.

.PARAMETER Server
Optional domain controller or AD LDS instance to query.

.PARAMETER Credential
Optional credential for the AD query.

.PARAMETER IncludeDisabled
Include disabled user accounts. By default, disabled user accounts are not
returned. Managed service accounts are always inventoried when available.

.PARAMETER StaleDays
Days since last logon before an enabled service account is considered stale.
Default: 90.

.PARAMETER MaxPasswordAgeDays
Password age threshold used for service account review. Default: 180.

.PARAMETER OutputDirectory
Directory where service-accounts.json, service-accounts.csv, and
service-accounts-review.md are written.

.PARAMETER Quiet
Suppress console summary.

.EXAMPLE
.\Get-ADServiceAccountAudit.ps1

.EXAMPLE
.\Get-ADServiceAccountAudit.ps1 -SearchBase "OU=Service Accounts,DC=example,DC=com"

.EXAMPLE
.\Get-ADServiceAccountAudit.ps1 -IncludeDisabled -StaleDays 180
#>

[CmdletBinding()]
param(
    [string]$SearchBase = "",
    [string]$Server = "",
    [System.Management.Automation.PSCredential]$Credential,
    [switch]$IncludeDisabled,
    [ValidateRange(1, 3650)]
    [int]$StaleDays = 90,
    [ValidateRange(1, 3650)]
    [int]$MaxPasswordAgeDays = 180,
    [string]$OutputDirectory = ".\reports\ad-service-accounts-$env:COMPUTERNAME-$(Get-Date -Format 'yyyyMMdd-HHmmss')",
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

function Test-ServiceNamePattern {
    param(
        [AllowNull()][string]$SamAccountName,
        [AllowNull()][string]$Name,
        [AllowNull()][string]$Description,
        [AllowNull()][string]$DistinguishedName
    )

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

function Test-ADObjectClass {
    param(
        [AllowNull()][object]$ObjectClass,
        [Parameter(Mandatory = $true)][string]$Expected
    )

    return [bool](@($ObjectClass) | Where-Object { "$_" -eq $Expected })
}

function Get-AccountType {
    param(
        [Parameter(Mandatory = $true)][object]$Account,
        [bool]$HasSPN,
        [bool]$NamePattern
    )

    $objectClass = Get-ObjectValue -InputObject $Account -Name "ObjectClass"
    if (Test-ADObjectClass -ObjectClass $objectClass -Expected "msDS-GroupManagedServiceAccount") {
        return "GroupManagedServiceAccount"
    }
    if (Test-ADObjectClass -ObjectClass $objectClass -Expected "msDS-ManagedServiceAccount") {
        return "StandaloneManagedServiceAccount"
    }
    if ($HasSPN) {
        return "UserSPNServiceAccount"
    }
    if ($NamePattern) {
        return "UserServiceAccountCandidate"
    }
    return "UserReviewCandidate"
}

function Get-RiskAssessment {
    param(
        [string]$AccountType,
        [bool]$Enabled,
        [bool]$HasSPN,
        [bool]$PasswordNeverExpires,
        [AllowNull()][object]$PasswordAgeDays,
        [bool]$AdminCount,
        [int]$PrivilegedGroupCount,
        [bool]$DoesNotRequirePreAuth,
        [bool]$TrustedForDelegation,
        [bool]$TrustedToAuthForDelegation,
        [bool]$MissingOwner,
        [AllowNull()][object]$InactiveDays,
        [bool]$IsSystemManaged
    )

    $flags = New-Object System.Collections.Generic.List[string]
    $reasons = New-Object System.Collections.Generic.List[string]

    if ($IsSystemManaged) {
        $flags.Add("SystemManagedAccount") | Out-Null
        $reasons.Add("System-managed account detected; do not treat as a normal cleanup candidate.") | Out-Null
    }
    if ($AccountType -in @("GroupManagedServiceAccount", "StandaloneManagedServiceAccount")) {
        $flags.Add("ManagedServiceAccount") | Out-Null
        $reasons.Add("Managed service account; password rotation is handled by AD.") | Out-Null
    }
    if ($Enabled) {
        $flags.Add("Enabled") | Out-Null
    }
    else {
        $flags.Add("Disabled") | Out-Null
    }
    if ($HasSPN) {
        $flags.Add("HasSPN") | Out-Null
        $reasons.Add("SPN is present; review service dependency and Kerberos exposure.") | Out-Null
    }
    if ($PasswordNeverExpires) {
        $flags.Add("PasswordNeverExpires") | Out-Null
        $reasons.Add("PasswordNeverExpires is set.") | Out-Null
    }
    if ($PasswordAgeDays -ne $null -and [int]$PasswordAgeDays -gt $MaxPasswordAgeDays) {
        $flags.Add("OldPassword") | Out-Null
        $reasons.Add("Password age exceeds the configured review threshold.") | Out-Null
    }
    if ($AdminCount -or $PrivilegedGroupCount -gt 0) {
        $flags.Add("PrivilegedAccess") | Out-Null
        $reasons.Add("Privileged group membership or AdminCount=1 was found.") | Out-Null
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
    if ($MissingOwner) {
        $flags.Add("MissingOwner") | Out-Null
        $reasons.Add("No owner evidence found in ManagedBy/Description/Info.") | Out-Null
    }
    if ($Enabled -and $InactiveDays -ne $null -and [int]$InactiveDays -gt $StaleDays) {
        $flags.Add("StaleEnabledAccount") | Out-Null
        $reasons.Add("Enabled service account has stale logon evidence.") | Out-Null
    }

    $priority = "Medium"
    if ($IsSystemManaged) {
        $priority = "Hold"
    }
    elseif ($Enabled -and ($DoesNotRequirePreAuth -or $TrustedForDelegation -or $AdminCount -or $PrivilegedGroupCount -gt 0)) {
        $priority = "Critical"
    }
    elseif ($Enabled -and ($PasswordNeverExpires -or ($PasswordAgeDays -ne $null -and [int]$PasswordAgeDays -gt $MaxPasswordAgeDays) -or $TrustedToAuthForDelegation -or $MissingOwner)) {
        $priority = "High"
    }
    elseif (-not $Enabled) {
        $priority = "Low"
    }

    $recommendedAction = switch ($priority) {
        "Critical" { "Review immediately with identity/security owner. Remove privilege/delegation or rotate/replace the account through change control." }
        "High" { "Confirm owner and service dependency, then plan password rotation, gMSA migration, SPN cleanup, or documented exception." }
        "Medium" { "Document owner, validate service dependency, and schedule routine review." }
        "Low" { "Confirm disabled account is no longer required before retention cleanup." }
        "Hold" { "Keep on hold as system-managed unless the owning product documentation says cleanup is safe." }
        default { "Review manually." }
    }

    $nextStep = switch ($priority) {
        "Critical" { "Open urgent owner/security review; check recent changes and privileged group membership." }
        "High" { "Assign owner, validate service dependency, and create a rotation or exception plan." }
        "Medium" { "Add to periodic service account review." }
        "Low" { "Confirm no dependency, then retire through approved cleanup." }
        "Hold" { "Verify product ownership and exclude from normal cleanup." }
        default { "Review manually." }
    }

    [ordered]@{
        ReviewPriority  = $priority
        RiskFlags       = @($flags.ToArray())
        ReviewReasons   = @($reasons.ToArray())
        RecommendedAction = $recommendedAction
        NextReviewStep  = $nextStep
    }
}

function ConvertTo-ServiceAccountRow {
    param(
        [Parameter(Mandatory = $true)][object]$Account,
        [Parameter(Mandatory = $true)][datetime]$Now
    )

    $spns = @(Get-ObjectValue -InputObject $Account -Name "ServicePrincipalName" | Where-Object { $_ })
    $memberOf = @(Get-ObjectValue -InputObject $Account -Name "memberOf" | Where-Object { $_ })
    $directGroupNames = @(Convert-DistinguishedNamesToNames -DistinguishedNames $memberOf)
    $privilegedGroupNames = @(Get-PrivilegedGroupNames -GroupDistinguishedNames $memberOf)
    $sam = Get-ObjectValue -InputObject $Account -Name "SamAccountName"
    if (-not $sam) {
        $sam = Get-ObjectValue -InputObject $Account -Name "sAMAccountName"
    }
    $name = Get-ObjectValue -InputObject $Account -Name "Name"
    $description = Get-ObjectValue -InputObject $Account -Name "Description"
    $info = Get-ObjectValue -InputObject $Account -Name "info"
    $dn = Get-ObjectValue -InputObject $Account -Name "DistinguishedName"
    $managedBy = Get-ObjectValue -InputObject $Account -Name "ManagedBy"
    $lastLogonDate = Get-ObjectValue -InputObject $Account -Name "LastLogonDate"
    $passwordLastSet = Get-ObjectValue -InputObject $Account -Name "PasswordLastSet"
    $passwordAgeDays = Get-AgeDays -Value $passwordLastSet -Now $Now
    $inactiveDays = Get-AgeDays -Value $lastLogonDate -Now $Now
    $hasSpn = $spns.Count -gt 0
    $namePattern = Test-ServiceNamePattern -SamAccountName $sam -Name $name -Description $description -DistinguishedName $dn
    $isSystemManaged = Test-ExchangeHealthMailbox -SamAccountName $sam -Name $name -DistinguishedName $dn
    $accountType = Get-AccountType -Account $Account -HasSPN $hasSpn -NamePattern $namePattern
    $objectClass = @(Get-ObjectValue -InputObject $Account -Name "ObjectClass" | Where-Object { $_ }) -join "; "
    $enabledValue = Get-ObjectValue -InputObject $Account -Name "Enabled"
    $enabled = if ($accountType -in @("GroupManagedServiceAccount", "StandaloneManagedServiceAccount") -and $null -eq $enabledValue) { $true } else { [bool]$enabledValue }
    $passwordNeverExpires = [bool](Get-ObjectValue -InputObject $Account -Name "PasswordNeverExpires")
    $adminCount = [bool]((Get-ObjectValue -InputObject $Account -Name "AdminCount") -eq 1)
    $doesNotRequirePreAuth = [bool](Get-ObjectValue -InputObject $Account -Name "DoesNotRequirePreAuth")
    $trustedForDelegation = [bool](Get-ObjectValue -InputObject $Account -Name "TrustedForDelegation")
    $trustedToAuthForDelegation = [bool](Get-ObjectValue -InputObject $Account -Name "TrustedToAuthForDelegation")
    $missingOwner = -not ($managedBy -or $description -or $info)
    $assessment = Get-RiskAssessment -AccountType $accountType -Enabled $enabled -HasSPN $hasSpn -PasswordNeverExpires $passwordNeverExpires -PasswordAgeDays $passwordAgeDays -AdminCount $adminCount -PrivilegedGroupCount $privilegedGroupNames.Count -DoesNotRequirePreAuth $doesNotRequirePreAuth -TrustedForDelegation $trustedForDelegation -TrustedToAuthForDelegation $trustedToAuthForDelegation -MissingOwner $missingOwner -InactiveDays $inactiveDays -IsSystemManaged $isSystemManaged

    [pscustomobject][ordered]@{
        ReviewPriority          = $assessment.ReviewPriority
        ActionPriority          = Get-ActionPriority -ReviewPriority $assessment.ReviewPriority
        AccountType             = $accountType
        SamAccountName          = $sam
        Name                    = $name
        UserPrincipalName       = Get-ObjectValue -InputObject $Account -Name "UserPrincipalName"
        ObjectClass             = $objectClass
        SID                     = "$(Get-ObjectValue -InputObject $Account -Name "SID")"
        Enabled                 = $enabled
        HasSPN                  = [bool]$hasSpn
        SPNCount                = $spns.Count
        ServicePrincipalNames   = @($spns)
        ServicePrincipalNamesText = if ($spns.Count -gt 0) { $spns -join "; " } else { "" }
        PasswordNeverExpires    = $passwordNeverExpires
        PasswordLastSetUtc      = Format-DateTimeUtc -Value $passwordLastSet
        PasswordAgeDays         = $passwordAgeDays
        LastLogonDateUtc        = Format-DateTimeUtc -Value $lastLogonDate
        LastLogonTimestampUtc   = Convert-ADFileTimeToUtc -Value (Get-ObjectValue -InputObject $Account -Name "lastLogonTimestamp")
        InactiveDays            = $inactiveDays
        NeverLoggedOn           = [bool]($null -eq $lastLogonDate)
        WhenCreatedUtc          = Format-DateTimeUtc -Value (Get-ObjectValue -InputObject $Account -Name "WhenCreated")
        WhenChangedUtc          = Format-DateTimeUtc -Value (Get-ObjectValue -InputObject $Account -Name "whenChanged")
        AdminCount              = if ($adminCount) { 1 } else { Get-ObjectValue -InputObject $Account -Name "AdminCount" }
        PrivilegedGroupCount    = $privilegedGroupNames.Count
        PrivilegedGroups        = @($privilegedGroupNames)
        PrivilegedGroupsText    = if ($privilegedGroupNames.Count -gt 0) { $privilegedGroupNames -join "; " } else { "" }
        DirectGroupCount        = $directGroupNames.Count
        DirectGroupsText        = if ($directGroupNames.Count -gt 0) { $directGroupNames -join "; " } else { "" }
        DoesNotRequirePreAuth   = $doesNotRequirePreAuth
        TrustedForDelegation    = $trustedForDelegation
        TrustedToAuthForDelegation = $trustedToAuthForDelegation
        AccountNotDelegated     = [bool](Get-ObjectValue -InputObject $Account -Name "AccountNotDelegated")
        KerberosEncryptionType  = @(Get-ObjectValue -InputObject $Account -Name "KerberosEncryptionType" | Where-Object { $_ }) -join "; "
        SupportedEncryptionTypes = Get-ObjectValue -InputObject $Account -Name "msDS-SupportedEncryptionTypes"
        ManagedPasswordInterval = Get-ObjectValue -InputObject $Account -Name "msDS-ManagedPasswordInterval"
        ManagedBy               = $managedBy
        OwnerEvidenceMissing    = [bool]$missingOwner
        Description             = $description
        Info                    = $info
        RiskFlags               = @($assessment.RiskFlags)
        RiskFlagsText           = if ($assessment.RiskFlags.Count -gt 0) { $assessment.RiskFlags -join "; " } else { "" }
        ReviewReasons           = @($assessment.ReviewReasons)
        ReviewReasonsText       = if ($assessment.ReviewReasons.Count -gt 0) { $assessment.ReviewReasons -join " " } else { "" }
        RecommendedAction       = $assessment.RecommendedAction
        NextReviewStep          = $assessment.NextReviewStep
        DistinguishedName       = $dn
    }
}

function Get-ActionPriority {
    param([string]$ReviewPriority)

    switch ($ReviewPriority) {
        "Critical" { return "P1 - Immediate review" }
        "High" { return "P2 - Owner and rotation review" }
        "Medium" { return "P3 - Scheduled review" }
        "Low" { return "P4 - Cleanup validation" }
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
        "AccountType",
        "SamAccountName",
        "Name",
        "UserPrincipalName",
        "ObjectClass",
        "SID",
        "Enabled",
        "HasSPN",
        "SPNCount",
        "ServicePrincipalNamesText",
        "PasswordNeverExpires",
        "PasswordLastSetUtc",
        "PasswordAgeDays",
        "LastLogonDateUtc",
        "InactiveDays",
        "NeverLoggedOn",
        "AdminCount",
        "PrivilegedGroupCount",
        "PrivilegedGroupsText",
        "DoesNotRequirePreAuth",
        "TrustedForDelegation",
        "TrustedToAuthForDelegation",
        "AccountNotDelegated",
        "KerberosEncryptionType",
        "SupportedEncryptionTypes",
        "ManagedPasswordInterval",
        "ManagedBy",
        "OwnerEvidenceMissing",
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
            ReportType     = "ADServiceAccountAudit"
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
        ServiceAccounts = @()
    }

    $report | ConvertTo-Json -Depth 6 | Out-File -FilePath $JsonPath -Encoding utf8
}

function Add-MarkdownServiceAccountTable {
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

    Add-MarkdownLine -Lines $Lines -Text "| Priority | Account | Type | Enabled | SPNs | Password age | Risk flags | Next step |"
    Add-MarkdownLine -Lines $Lines -Text "|---|---|---|---:|---:|---:|---|---|"
    foreach ($row in @($Rows | Select-Object -First $Limit)) {
        Add-MarkdownLine -Lines $Lines -Text ("| {0} | {1} | {2} | {3} | {4} | {5} | {6} | {7} |" -f `
                (ConvertTo-MarkdownSafeText $row.ActionPriority),
            (ConvertTo-MarkdownSafeText $row.SamAccountName),
            (ConvertTo-MarkdownSafeText $row.AccountType),
            (ConvertTo-MarkdownSafeText $row.Enabled),
            (ConvertTo-MarkdownSafeText $row.SPNCount),
            (ConvertTo-MarkdownSafeText $row.PasswordAgeDays),
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
    $rows = @($Report["ServiceAccounts"])
    $lines = New-Object System.Collections.Generic.List[string]

    Add-MarkdownLine -Lines $lines -Text "# AD Service Account Review"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "Generated UTC: ``$($metadata.GeneratedAtUtc)``"
    Add-MarkdownLine -Lines $lines -Text "Computer: ``$($metadata.ComputerName)``"
    Add-MarkdownLine -Lines $lines -Text "Search base: ``$(if ($metadata.SearchBase) { $metadata.SearchBase } else { 'Domain default' })``"
    Add-MarkdownLine -Lines $lines

    Add-MarkdownLine -Lines $lines -Text "## Summary"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "| Metric | Count |"
    Add-MarkdownLine -Lines $lines -Text "|---|---:|"
    foreach ($metric in @("TotalServiceAccounts", "CriticalAccounts", "HighAccounts", "ManagedServiceAccounts", "UserServiceAccounts", "SPNAccounts", "PasswordNeverExpiresAccounts", "PrivilegedAccounts", "MissingOwnerAccounts", "StaleEnabledAccounts")) {
        Add-MarkdownLine -Lines $lines -Text ("| {0} | {1} |" -f $metric, $summary.$metric)
    }
    Add-MarkdownLine -Lines $lines

    Add-MarkdownLine -Lines $lines -Text "## Admin Action Plan"
    Add-MarkdownLine -Lines $lines
    if ($summary.CriticalAccounts -gt 0) {
        Add-MarkdownLine -Lines $lines -Text "Critical service accounts exist. Start with privileged access, unconstrained delegation, or pre-authentication disabled."
    }
    elseif ($summary.HighAccounts -gt 0) {
        Add-MarkdownLine -Lines $lines -Text "High review service accounts exist. Start with password-never-expires, old passwords, missing owners, or constrained delegation."
    }
    else {
        Add-MarkdownLine -Lines $lines -Text "No Critical or High service account findings were detected. Continue with ownership documentation and periodic review."
    }
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "Prefer gMSA where applications support it. Do not rotate or disable a service account until the owner, dependency, maintenance window, and rollback are confirmed."
    Add-MarkdownLine -Lines $lines

    Add-MarkdownLine -Lines $lines -Text "## Critical"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownServiceAccountTable -Lines $lines -Rows @($rows | Where-Object { $_.ReviewPriority -eq "Critical" } | Sort-Object @{ Expression = { Get-PrioritySortValue -Value $_.ActionPriority } }, SamAccountName)

    Add-MarkdownLine -Lines $lines -Text "## High"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownServiceAccountTable -Lines $lines -Rows @($rows | Where-Object { $_.ReviewPriority -eq "High" } | Sort-Object SamAccountName)

    Add-MarkdownLine -Lines $lines -Text "## Managed Service Accounts"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownServiceAccountTable -Lines $lines -Rows @($rows | Where-Object { $_.AccountType -in @("GroupManagedServiceAccount", "StandaloneManagedServiceAccount") } | Sort-Object SamAccountName)

    Add-MarkdownLine -Lines $lines -Text "## All Service Account Candidates"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownServiceAccountTable -Lines $lines -Rows @($rows | Sort-Object @{ Expression = { Get-PrioritySortValue -Value $_.ActionPriority } }, SamAccountName) -Limit 100

    Add-MarkdownLine -Lines $lines -Text "## Review Rules"
    Add-MarkdownLine -Lines $lines
    foreach ($note in @($summary.Notes)) {
        Add-MarkdownLine -Lines $lines -Text "- $note"
    }

    $lines | Out-File -FilePath $Path -Encoding utf8
}

New-Directory -Path $OutputDirectory
$resolvedOutputDirectory = (Resolve-Path -Path $OutputDirectory).Path
$jsonPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "service-accounts.json"
$csvPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "service-accounts.csv"
$markdownPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "service-accounts-review.md"

if (-not (Import-ActiveDirectoryModule)) {
    $reason = "ActiveDirectory PowerShell module was not found. Install RSAT Active Directory tools or run this script on a domain management host."
    Write-FailedReport -JsonPath $jsonPath -Reason $reason
    throw $reason
}

$now = Get-Date
$commonParameters = Get-ADCommonParameters
$domainSummary = Get-DomainSummary -CommonParameters $commonParameters
$reportErrors = New-Object System.Collections.Generic.List[string]

$enabledClause = if ($IncludeDisabled) { "" } else { "(!(userAccountControl:1.2.840.113556.1.4.803:=2))" }
$serviceCandidateFilter = "(&(objectCategory=person)(objectClass=user)$enabledClause(|(servicePrincipalName=*)(sAMAccountName=svc*)(sAMAccountName=svc-*)(sAMAccountName=svc_*)(sAMAccountName=*svc*)(name=*service*)(description=*service*)(description=*Service*)(adminCount=1)(userAccountControl:1.2.840.113556.1.4.803:=65536)))"

$userParameters = @{
    LDAPFilter  = $serviceCandidateFilter
    Properties  = @(
        "AccountNotDelegated",
        "AdminCount",
        "Description",
        "DoesNotRequirePreAuth",
        "Enabled",
        "info",
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
    $userAccounts = @(Get-ADUser @userParameters)
}
catch {
    $reason = "Active Directory service-account user query failed: $($_.Exception.Message)"
    Write-FailedReport -JsonPath $jsonPath -Reason $reason
    throw $reason
}

$managedServiceAccounts = @()
$objectParameters = @{
    LDAPFilter  = "(|(objectClass=msDS-GroupManagedServiceAccount)(objectClass=msDS-ManagedServiceAccount))"
    Properties  = @(
        "Description",
        "info",
        "ManagedBy",
        "memberOf",
        "msDS-GroupMSAMembership",
        "msDS-ManagedPasswordInterval",
        "msDS-SupportedEncryptionTypes",
        "ObjectClass",
        "PasswordLastSet",
        "ServicePrincipalName",
        "SID",
        "sAMAccountName",
        "whenChanged",
        "WhenCreated"
    )
    ErrorAction = "Stop"
}
foreach ($key in $commonParameters.Keys) {
    $objectParameters[$key] = $commonParameters[$key]
}
if ($SearchBase) {
    $objectParameters["SearchBase"] = $SearchBase
}

try {
    $managedServiceAccounts = @(Get-ADObject @objectParameters)
}
catch {
    $reportErrors.Add("Managed service account query failed: $($_.Exception.Message)") | Out-Null
}

$rowsByKey = @{}
foreach ($account in @($userAccounts + $managedServiceAccounts)) {
    $row = ConvertTo-ServiceAccountRow -Account $account -Now $now
    $key = if ($row.SID) { $row.SID } elseif ($row.DistinguishedName) { $row.DistinguishedName } else { $row.SamAccountName }
    $rowsByKey[$key] = $row
}

$serviceAccounts = @($rowsByKey.Values | Sort-Object @{ Expression = { Get-PrioritySortValue -Value $_.ActionPriority } }, SamAccountName)

$summary = [ordered]@{
    TotalServiceAccounts          = $serviceAccounts.Count
    CriticalAccounts              = @($serviceAccounts | Where-Object { $_.ReviewPriority -eq "Critical" }).Count
    HighAccounts                  = @($serviceAccounts | Where-Object { $_.ReviewPriority -eq "High" }).Count
    MediumAccounts                = @($serviceAccounts | Where-Object { $_.ReviewPriority -eq "Medium" }).Count
    LowAccounts                   = @($serviceAccounts | Where-Object { $_.ReviewPriority -eq "Low" }).Count
    HoldAccounts                  = @($serviceAccounts | Where-Object { $_.ReviewPriority -eq "Hold" }).Count
    ManagedServiceAccounts        = @($serviceAccounts | Where-Object { $_.AccountType -in @("GroupManagedServiceAccount", "StandaloneManagedServiceAccount") }).Count
    UserServiceAccounts           = @($serviceAccounts | Where-Object { $_.AccountType -notin @("GroupManagedServiceAccount", "StandaloneManagedServiceAccount") }).Count
    SPNAccounts                   = @($serviceAccounts | Where-Object { $_.HasSPN }).Count
    PasswordNeverExpiresAccounts  = @($serviceAccounts | Where-Object { $_.PasswordNeverExpires }).Count
    PrivilegedAccounts            = @($serviceAccounts | Where-Object { $_.PrivilegedGroupCount -gt 0 -or $_.AdminCount -eq 1 }).Count
    MissingOwnerAccounts          = @($serviceAccounts | Where-Object { $_.OwnerEvidenceMissing }).Count
    StaleEnabledAccounts          = @($serviceAccounts | Where-Object { $_.Enabled -and $_.InactiveDays -ne $null -and $_.InactiveDays -gt $StaleDays }).Count
    ReportErrors                  = @($reportErrors.ToArray())
    Notes                         = @(
        "This script is audit-only and does not rotate, disable, or modify accounts.",
        "SPN-bearing user accounts should be reviewed with Kerberos exposure in mind.",
        "Prefer group managed service accounts where the application supports them.",
        "Password rotation requires owner, dependency, maintenance window, and rollback validation.",
        "Managed service accounts are included for inventory; their password rotation is handled by AD.",
        "Missing owner evidence means ManagedBy, Description, and Info did not identify ownership."
    )
}

$report = [ordered]@{
    ReportMetadata = [ordered]@{
        SchemaVersion      = "1.0"
        ReportType         = "ADServiceAccountAudit"
        Status             = "Completed"
        GeneratedAtUtc     = (Get-Date).ToUniversalTime().ToString("o")
        ComputerName       = $env:COMPUTERNAME
        RunBy              = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        SearchBase         = if ($SearchBase) { $SearchBase } else { $null }
        Server             = if ($Server) { $Server } else { $null }
        IncludeDisabled    = [bool]$IncludeDisabled
        StaleDays          = $StaleDays
        MaxPasswordAgeDays = $MaxPasswordAgeDays
        OutputDirectory    = $resolvedOutputDirectory
        JsonPath           = $jsonPath
        CsvPath            = $csvPath
        MarkdownPath       = $markdownPath
    }
    Domain          = $domainSummary
    Summary         = $summary
    ServiceAccounts = @($serviceAccounts)
}

$report | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding utf8
Write-CsvReport -Path $csvPath -Rows $serviceAccounts
Write-MarkdownReport -Path $markdownPath -Report $report

if (-not $Quiet) {
    Write-Host "AD service account report written to: $jsonPath"
    Write-Host "AD service account review written to: $markdownPath"
    Write-Host "Service accounts: $($summary.TotalServiceAccounts)"
    Write-Host "Critical: $($summary.CriticalAccounts)"
    Write-Host "High: $($summary.HighAccounts)"
}
