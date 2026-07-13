<#
.SYNOPSIS
Audits on-prem Active Directory privileged identities for protection gaps.

.DESCRIPTION
This script inventories effective user members of privileged Active Directory
groups and reports protection gaps such as PasswordNeverExpires, old passwords,
SPNs, delegation, pre-authentication disabled, smartcard not required, not being
in Protected Users, stale activity, disabled privileged memberships, and missing
owner evidence.

This version is on-prem AD only. It does not verify Entra ID MFA or Conditional
Access. It is audit-only and does not change Active Directory.

.PARAMETER GroupName
Optional extra AD group identities to audit in addition to the built-in
privileged group set.

.PARAMETER Server
Optional domain controller or AD LDS instance to query.

.PARAMETER Credential
Optional credential for the AD query.

.PARAMETER StaleDays
Days since last logon before an enabled privileged identity is considered
stale. Default: 90.

.PARAMETER MaxCredentialAgeDays
Credential age threshold used for privileged account review. Default: 180.

.PARAMETER OutputDirectory
Directory where privileged-identity-protection.json,
privileged-identities.csv, privileged-group-memberships.csv,
privileged-identity-findings.csv, and
privileged-identity-protection-review.md are written.

.PARAMETER Quiet
Suppress console summary.

.EXAMPLE
.\Get-PrivilegedIdentityProtectionAudit.ps1

.EXAMPLE
.\Get-PrivilegedIdentityProtectionAudit.ps1 -GroupName "Tier 0 Admins"
#>

[CmdletBinding()]
param(
    [string[]]$GroupName = @(),
    [string]$Server = "",
    [System.Management.Automation.PSCredential]$Credential,
    [ValidateRange(1, 3650)]
    [int]$StaleDays = 90,
    [ValidateRange(1, 3650)]
    [int]$MaxCredentialAgeDays = 180,
    [string]$OutputDirectory = ".\reports\ad-privileged-identity-protection-$env:COMPUTERNAME-$(Get-Date -Format 'yyyyMMdd-HHmmss')",
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

function New-GroupDefinition {
    param(
        [Parameter(Mandatory = $true)][string]$Key,
        [Parameter(Mandatory = $true)][string]$DisplayName,
        [Parameter(Mandatory = $true)][string]$Identity,
        [string]$Tier = "Tier0",
        [string]$ExpectedRisk = "Critical",
        [switch]$ProtectionGroup
    )

    [pscustomobject][ordered]@{
        Key               = $Key
        DisplayName       = $DisplayName
        Identity          = $Identity
        Tier              = $Tier
        ExpectedRisk      = $ExpectedRisk
        IsProtectionGroup = [bool]$ProtectionGroup
        IsExtraGroup      = $false
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
        $definitions.Add((New-GroupDefinition -Key "ProtectedUsers" -DisplayName "Protected Users" -Identity "$DomainSID-525" -ExpectedRisk "Info" -ProtectionGroup)) | Out-Null
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
                Key               = "Extra_$safeKey"
                DisplayName       = $extraGroup
                Identity          = $extraGroup
                Tier              = "Custom"
                ExpectedRisk      = "High"
                IsProtectionGroup = $false
                IsExtraGroup      = $true
            }) | Out-Null
    }

    return @($definitions.ToArray())
}

function Resolve-GroupDefinition {
    param(
        [Parameter(Mandatory = $true)][object]$Definition,
        [Parameter(Mandatory = $true)][hashtable]$CommonParameters
    )

    try {
        $parameters = @{
            Identity    = $Definition.Identity
            Properties  = @("Description", "GroupCategory", "GroupScope", "SID")
            ErrorAction = "Stop"
        }
        foreach ($key in $CommonParameters.Keys) {
            $parameters[$key] = $CommonParameters[$key]
        }
        $group = Get-ADGroup @parameters
        return [pscustomobject][ordered]@{
            Succeeded         = $true
            Error             = ""
            Key               = $Definition.Key
            Name              = $group.Name
            SamAccountName    = $group.SamAccountName
            SID               = "$($group.SID)"
            DistinguishedName = $group.DistinguishedName
            Description       = $group.Description
            GroupCategory     = "$($group.GroupCategory)"
            GroupScope        = "$($group.GroupScope)"
            Tier              = $Definition.Tier
            ExpectedRisk      = $Definition.ExpectedRisk
            IsProtectionGroup = [bool]$Definition.IsProtectionGroup
            IsExtraGroup      = [bool]$Definition.IsExtraGroup
        }
    }
    catch {
        return [pscustomobject][ordered]@{
            Succeeded         = $false
            Error             = $_.Exception.Message
            Key               = $Definition.Key
            Name              = $Definition.DisplayName
            SamAccountName    = ""
            SID               = ""
            DistinguishedName = ""
            Description       = ""
            GroupCategory     = ""
            GroupScope        = ""
            Tier              = $Definition.Tier
            ExpectedRisk      = $Definition.ExpectedRisk
            IsProtectionGroup = [bool]$Definition.IsProtectionGroup
            IsExtraGroup      = [bool]$Definition.IsExtraGroup
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
        $parameters = @{
            Identity    = $Group.DistinguishedName
            ErrorAction = "Stop"
        }
        foreach ($key in $CommonParameters.Keys) {
            $parameters[$key] = $CommonParameters[$key]
        }
        $result["DirectMembers"] = @(Get-ADGroupMember @parameters)
    }
    catch {
        $result["Errors"] = @($result["Errors"]) + "Could not read direct members for $($Group.Name): $($_.Exception.Message)"
    }

    try {
        $parameters = @{
            Identity    = $Group.DistinguishedName
            Recursive   = $true
            ErrorAction = "Stop"
        }
        foreach ($key in $CommonParameters.Keys) {
            $parameters[$key] = $CommonParameters[$key]
        }
        $result["RecursiveMembers"] = @(Get-ADGroupMember @parameters)
    }
    catch {
        $result["Errors"] = @($result["Errors"]) + "Could not read recursive members for $($Group.Name): $($_.Exception.Message)"
    }

    return $result
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

function Add-UniqueValue {
    param(
        [Parameter(Mandatory = $true)][object]$Record,
        [Parameter(Mandatory = $true)][string]$Property,
        [AllowNull()][object]$Value
    )

    if ($null -eq $Value -or "$Value" -eq "") {
        return
    }

    $current = @(Get-ObjectValue -InputObject $Record -Name $Property | Where-Object { $_ })
    $Record.$Property = @($current + "$Value" | Sort-Object -Unique)
}

function New-MembershipRow {
    param(
        [Parameter(Mandatory = $true)][object]$Group,
        [Parameter(Mandatory = $true)][object]$Member,
        [Parameter(Mandatory = $true)][string]$MembershipType
    )

    [pscustomobject][ordered]@{
        GroupKey          = $Group.Key
        GroupName         = $Group.Name
        GroupSID          = $Group.SID
        GroupTier         = $Group.Tier
        GroupExpectedRisk = $Group.ExpectedRisk
        IsProtectionGroup = [bool]$Group.IsProtectionGroup
        MembershipType    = $MembershipType
        MemberKey         = Get-MemberKey -Member $Member
        MemberName        = Get-ObjectValue -InputObject $Member -Name "Name"
        MemberSamAccountName = Get-ObjectValue -InputObject $Member -Name "SamAccountName"
        MemberObjectClass = "$(Get-ObjectValue -InputObject $Member -Name "ObjectClass")"
        MemberSID         = "$(Get-ObjectValue -InputObject $Member -Name "SID")"
        MemberDN          = Get-ObjectValue -InputObject $Member -Name "DistinguishedName"
    }
}

function Add-IdentityMembership {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Map,
        [Parameter(Mandatory = $true)][object]$Group,
        [Parameter(Mandatory = $true)][object]$Member,
        [Parameter(Mandatory = $true)][string]$MembershipType
    )

    $key = Get-MemberKey -Member $Member
    if (-not $Map.ContainsKey($key)) {
        $Map[$key] = [pscustomobject][ordered]@{
            Key                 = $key
            Member              = $Member
            DirectAccessGroups  = @()
            EffectiveAccessGroups = @()
            ProtectionGroups    = @()
            SourceGroupRisks    = @()
            SourceGroupTiers    = @()
            HasNestedAccess     = $false
        }
    }

    $record = $Map[$key]
    if ($Group.IsProtectionGroup) {
        Add-UniqueValue -Record $record -Property "ProtectionGroups" -Value $Group.Name
        return
    }

    if ($MembershipType -eq "Direct") {
        Add-UniqueValue -Record $record -Property "DirectAccessGroups" -Value $Group.Name
        Add-UniqueValue -Record $record -Property "EffectiveAccessGroups" -Value $Group.Name
    }
    else {
        Add-UniqueValue -Record $record -Property "EffectiveAccessGroups" -Value $Group.Name
        if (-not (@($record.DirectAccessGroups) -contains $Group.Name)) {
            $record.HasNestedAccess = $true
        }
    }
    Add-UniqueValue -Record $record -Property "SourceGroupRisks" -Value $Group.ExpectedRisk
    Add-UniqueValue -Record $record -Property "SourceGroupTiers" -Value $Group.Tier
}

function Get-ADUserDetail {
    param(
        [Parameter(Mandatory = $true)][object]$Member,
        [Parameter(Mandatory = $true)][hashtable]$CommonParameters
    )

    $identity = Get-ObjectValue -InputObject $Member -Name "DistinguishedName"
    if (-not $identity) {
        $identity = Get-ObjectValue -InputObject $Member -Name "SID"
    }
    if (-not $identity) {
        $identity = Get-ObjectValue -InputObject $Member -Name "SamAccountName"
    }

    try {
        $parameters = @{
            Identity    = $identity
            Properties  = @(
                "AccountExpirationDate",
                "AccountNotDelegated",
                "AdminCount",
                "AllowReversiblePasswordEncryption",
                "Description",
                "DoesNotRequirePreAuth",
                "Enabled",
                "info",
                "LastLogonDate",
                "lastLogonTimestamp",
                "LockedOut",
                "Manager",
                "memberOf",
                "msDS-SupportedEncryptionTypes",
                "PasswordExpired",
                "PasswordLastSet",
                "PasswordNeverExpires",
                "ServicePrincipalName",
                "SID",
                "SmartcardLogonRequired",
                "TrustedForDelegation",
                "TrustedToAuthForDelegation",
                "UserPrincipalName",
                "whenChanged",
                "WhenCreated"
            )
            ErrorAction = "Stop"
        }
        foreach ($key in $CommonParameters.Keys) {
            $parameters[$key] = $CommonParameters[$key]
        }
        $user = Get-ADUser @parameters
        return [ordered]@{
            Succeeded = $true
            Error     = ""
            User      = $user
        }
    }
    catch {
        return [ordered]@{
            Succeeded = $false
            Error     = $_.Exception.Message
            User      = $Member
        }
    }
}

function Test-ProtectedUsersMember {
    param(
        [Parameter(Mandatory = $true)][object]$User,
        [AllowNull()][object[]]$ProtectionGroups
    )

    if (@($ProtectionGroups | Where-Object { $_ -eq "Protected Users" }).Count -gt 0) {
        return $true
    }

    $memberOf = @(Get-ObjectValue -InputObject $User -Name "memberOf" | Where-Object { $_ })
    return [bool](@($memberOf | Where-Object { $_ -match '(?i)^CN=Protected Users,' }).Count -gt 0)
}

function Get-IdentityCategory {
    param(
        [Parameter(Mandatory = $true)][object]$User,
        [string[]]$EffectiveGroups
    )

    $sam = Get-ObjectValue -InputObject $User -Name "SamAccountName"
    $sid = "$(Get-ObjectValue -InputObject $User -Name "SID")"
    if ($sam -eq "Administrator" -or $sid -match "-500$") {
        return "BuiltInAdministrator"
    }
    if (@($EffectiveGroups | Where-Object { $_ -in @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators") }).Count -gt 0) {
        return "Tier0Administrator"
    }
    if (@($EffectiveGroups | Where-Object { $_ -in @("Account Operators", "Server Operators", "Backup Operators", "Print Operators", "DnsAdmins", "Group Policy Creator Owners", "Key Admins", "Enterprise Key Admins") }).Count -gt 0) {
        return "PrivilegedOperator"
    }
    return "PrivilegedIdentity"
}

function Get-ProtectionAssessment {
    param(
        [Parameter(Mandatory = $true)][object]$AccountRecord,
        [Parameter(Mandatory = $true)][string]$IdentityCategory,
        [Parameter(Mandatory = $true)][string[]]$EffectiveGroups,
        [Parameter(Mandatory = $true)][string[]]$SourceGroupRisks,
        [bool]$UserQuerySucceeded,
        [AllowNull()][string]$UserQueryError,
        [bool]$HasNestedAccess,
        [bool]$IsProtectedUsersMember,
        [AllowNull()][object]$CredentialAgeDays,
        [AllowNull()][object]$InactiveDays
    )

    $flags = New-Object System.Collections.Generic.List[string]
    $reasons = New-Object System.Collections.Generic.List[string]
    $enabled = [bool](Get-ObjectValue -InputObject $AccountRecord -Name "Enabled")
    $criticalGroup = @($SourceGroupRisks | Where-Object { $_ -eq "Critical" }).Count -gt 0
    $passwordNeverExpires = [bool](Get-ObjectValue -InputObject $AccountRecord -Name "PasswordNeverExpires")
    $doesNotRequirePreAuth = [bool](Get-ObjectValue -InputObject $AccountRecord -Name "DoesNotRequirePreAuth")
    $trustedForDelegation = [bool](Get-ObjectValue -InputObject $AccountRecord -Name "TrustedForDelegation")
    $trustedToAuthForDelegation = [bool](Get-ObjectValue -InputObject $AccountRecord -Name "TrustedToAuthForDelegation")
    $accountNotDelegated = [bool](Get-ObjectValue -InputObject $AccountRecord -Name "AccountNotDelegated")
    $smartcardRequired = [bool](Get-ObjectValue -InputObject $AccountRecord -Name "SmartcardLogonRequired")
    $allowReversiblePasswordEncryption = [bool](Get-ObjectValue -InputObject $AccountRecord -Name "AllowReversiblePasswordEncryption")
    $spns = @(Get-ObjectValue -InputObject $AccountRecord -Name "ServicePrincipalName" | Where-Object { $_ })
    $manager = Get-ObjectValue -InputObject $AccountRecord -Name "Manager"
    $description = Get-ObjectValue -InputObject $AccountRecord -Name "Description"
    $info = Get-ObjectValue -InputObject $AccountRecord -Name "info"
    $missingOwner = -not ($manager -or $description -or $info)

    if (-not $UserQuerySucceeded) {
        $flags.Add("UserDetailQueryFailed") | Out-Null
        $reasons.Add("Could not query full AD user properties: $UserQueryError") | Out-Null
    }
    if ($enabled) {
        $flags.Add("EnabledPrivilegedAccount") | Out-Null
    }
    else {
        $flags.Add("DisabledPrivilegedMembership") | Out-Null
        $reasons.Add("Disabled account still has privileged group membership.") | Out-Null
    }
    if ($IdentityCategory -eq "BuiltInAdministrator") {
        $flags.Add("BuiltInAdministrator") | Out-Null
        $reasons.Add("Built-in Administrator account is privileged by design.") | Out-Null
    }
    if ($criticalGroup) {
        $flags.Add("CriticalPrivilegedGroup") | Out-Null
    }
    if ($HasNestedAccess) {
        $flags.Add("NestedPrivilegedAccess") | Out-Null
        $reasons.Add("Privileged access is inherited through nested group membership.") | Out-Null
    }
    if ($passwordNeverExpires) {
        $flags.Add("PasswordNeverExpires") | Out-Null
        $reasons.Add("Privileged identity has PasswordNeverExpires set.") | Out-Null
    }
    if ($CredentialAgeDays -ne $null -and [int]$CredentialAgeDays -gt $MaxCredentialAgeDays) {
        $flags.Add("OldPassword") | Out-Null
        $reasons.Add("Password age exceeds the configured privileged-account review threshold.") | Out-Null
    }
    if ($doesNotRequirePreAuth) {
        $flags.Add("DoesNotRequirePreAuth") | Out-Null
        $reasons.Add("Kerberos pre-authentication is disabled.") | Out-Null
    }
    if ($trustedForDelegation) {
        $flags.Add("UnconstrainedDelegation") | Out-Null
        $reasons.Add("Unconstrained delegation is enabled on a privileged identity.") | Out-Null
    }
    if ($trustedToAuthForDelegation) {
        $flags.Add("ConstrainedDelegation") | Out-Null
        $reasons.Add("Protocol-transition delegation is enabled on a privileged identity.") | Out-Null
    }
    if (-not $accountNotDelegated) {
        $flags.Add("DelegationAllowed") | Out-Null
        $reasons.Add("Account is not marked sensitive and cannot be delegated.") | Out-Null
    }
    if (-not $smartcardRequired) {
        $flags.Add("SmartcardNotRequired") | Out-Null
        $reasons.Add("Smartcard required for interactive logon is not set.") | Out-Null
    }
    if (-not $IsProtectedUsersMember -and $criticalGroup) {
        $flags.Add("NotInProtectedUsers") | Out-Null
        $reasons.Add("Critical privileged identity is not a member of Protected Users.") | Out-Null
    }
    if ($allowReversiblePasswordEncryption) {
        $flags.Add("ReversiblePasswordEncryptionAllowed") | Out-Null
        $reasons.Add("Reversible password encryption is allowed.") | Out-Null
    }
    if ($spns.Count -gt 0) {
        $flags.Add("HasSPN") | Out-Null
        $reasons.Add("SPN is present on a privileged identity.") | Out-Null
    }
    if ($enabled -and $InactiveDays -ne $null -and [int]$InactiveDays -gt $StaleDays) {
        $flags.Add("StaleEnabledPrivilegedAccount") | Out-Null
        $reasons.Add("Enabled privileged identity has stale logon evidence.") | Out-Null
    }
    if ($missingOwner) {
        $flags.Add("MissingOwnerEvidence") | Out-Null
        $reasons.Add("No owner evidence found in Manager, Description, or Info.") | Out-Null
    }

    $priority = "Medium"
    if (-not $UserQuerySucceeded) {
        $priority = "High"
    }
    elseif (-not $enabled) {
        $priority = "Medium"
    }
    elseif ($IdentityCategory -eq "BuiltInAdministrator" -or $doesNotRequirePreAuth -or $trustedForDelegation -or ($criticalGroup -and ($passwordNeverExpires -or $spns.Count -gt 0 -or $allowReversiblePasswordEncryption))) {
        $priority = "Critical"
    }
    elseif ($criticalGroup -and ((-not $smartcardRequired) -or (-not $IsProtectedUsersMember) -or (-not $accountNotDelegated) -or ($CredentialAgeDays -ne $null -and [int]$CredentialAgeDays -gt $MaxCredentialAgeDays))) {
        $priority = "High"
    }
    elseif ($enabled -and ($trustedToAuthForDelegation -or $HasNestedAccess -or $missingOwner -or ($InactiveDays -ne $null -and [int]$InactiveDays -gt $StaleDays))) {
        $priority = "High"
    }

    $recommendedAction = switch ($priority) {
        "Critical" { "Review immediately with identity/security owner. Remove unsafe delegation/SPN/password exception or reduce privilege through approved change control." }
        "High" { "Confirm owner, protection controls, and business need. Add missing protections or document a time-bound exception." }
        "Medium" { "Review privileged membership, especially disabled or nested access, and clean up if no longer required." }
        default { "Review manually." }
    }

    $nextStep = switch ($priority) {
        "Critical" { "Open urgent privileged identity review; verify recent changes, owner, and rollback plan." }
        "High" { "Assign owner and create remediation or exception record." }
        "Medium" { "Validate membership and add to recurring privileged access review." }
        default { "Review manually." }
    }

    [ordered]@{
        ReviewPriority   = $priority
        RiskFlags        = @($flags.ToArray())
        ReviewReasons    = @($reasons.ToArray())
        RecommendedAction = $recommendedAction
        NextReviewStep   = $nextStep
    }
}

function ConvertTo-PrivilegedIdentityRow {
    param(
        [Parameter(Mandatory = $true)][object]$Record,
        [Parameter(Mandatory = $true)][hashtable]$CommonParameters,
        [Parameter(Mandatory = $true)][datetime]$Now
    )

    $detail = Get-ADUserDetail -Member $Record.Member -CommonParameters $CommonParameters
    $user = $detail.User
    $effectiveGroups = @($Record.EffectiveAccessGroups | Where-Object { $_ })
    $directGroups = @($Record.DirectAccessGroups | Where-Object { $_ })
    $protectionGroups = @($Record.ProtectionGroups | Where-Object { $_ })
    $sourceGroupRisks = @($Record.SourceGroupRisks | Where-Object { $_ })
    $identityCategory = Get-IdentityCategory -User $user -EffectiveGroups $effectiveGroups
    $passwordLastSet = Get-ObjectValue -InputObject $user -Name "PasswordLastSet"
    $lastLogonDate = Get-ObjectValue -InputObject $user -Name "LastLogonDate"
    $passwordAgeDays = Get-AgeDays -Value $passwordLastSet -Now $Now
    $inactiveDays = Get-AgeDays -Value $lastLogonDate -Now $Now
    $spns = @(Get-ObjectValue -InputObject $user -Name "ServicePrincipalName" | Where-Object { $_ })
    $isProtectedUsersMember = Test-ProtectedUsersMember -User $user -ProtectionGroups $protectionGroups
    $assessment = Get-ProtectionAssessment -AccountRecord $user -IdentityCategory $identityCategory -EffectiveGroups $effectiveGroups -SourceGroupRisks $sourceGroupRisks -UserQuerySucceeded ([bool]$detail.Succeeded) -UserQueryError "$($detail.Error)" -HasNestedAccess ([bool]$Record.HasNestedAccess) -IsProtectedUsersMember $isProtectedUsersMember -CredentialAgeDays $passwordAgeDays -InactiveDays $inactiveDays

    [pscustomobject][ordered]@{
        ReviewPriority          = $assessment.ReviewPriority
        ActionPriority          = Get-ActionPriority -ReviewPriority $assessment.ReviewPriority
        IdentityCategory        = $identityCategory
        SamAccountName          = Get-ObjectValue -InputObject $user -Name "SamAccountName"
        Name                    = Get-ObjectValue -InputObject $user -Name "Name"
        UserPrincipalName       = Get-ObjectValue -InputObject $user -Name "UserPrincipalName"
        SID                     = "$(Get-ObjectValue -InputObject $user -Name "SID")"
        Enabled                 = [bool](Get-ObjectValue -InputObject $user -Name "Enabled")
        DirectPrivilegedGroups  = @($directGroups)
        DirectPrivilegedGroupsText = if ($directGroups.Count -gt 0) { $directGroups -join "; " } else { "" }
        EffectivePrivilegedGroups = @($effectiveGroups)
        EffectivePrivilegedGroupsText = if ($effectiveGroups.Count -gt 0) { $effectiveGroups -join "; " } else { "" }
        CriticalGroupMember     = [bool](@($sourceGroupRisks | Where-Object { $_ -eq "Critical" }).Count -gt 0)
        NestedPrivilegedAccess  = [bool]$Record.HasNestedAccess
        ProtectedUsersMember    = [bool]$isProtectedUsersMember
        SmartcardLogonRequired  = [bool](Get-ObjectValue -InputObject $user -Name "SmartcardLogonRequired")
        AccountNotDelegated     = [bool](Get-ObjectValue -InputObject $user -Name "AccountNotDelegated")
        PasswordNeverExpires    = [bool](Get-ObjectValue -InputObject $user -Name "PasswordNeverExpires")
        PasswordExpired         = [bool](Get-ObjectValue -InputObject $user -Name "PasswordExpired")
        PasswordLastSetUtc      = Format-DateTimeUtc -Value $passwordLastSet
        PasswordAgeDays         = $passwordAgeDays
        LastLogonDateUtc        = Format-DateTimeUtc -Value $lastLogonDate
        LastLogonTimestampUtc   = Convert-ADFileTimeToUtc -Value (Get-ObjectValue -InputObject $user -Name "lastLogonTimestamp")
        InactiveDays            = $inactiveDays
        NeverLoggedOn           = [bool]($null -eq $lastLogonDate)
        DoesNotRequirePreAuth   = [bool](Get-ObjectValue -InputObject $user -Name "DoesNotRequirePreAuth")
        TrustedForDelegation    = [bool](Get-ObjectValue -InputObject $user -Name "TrustedForDelegation")
        TrustedToAuthForDelegation = [bool](Get-ObjectValue -InputObject $user -Name "TrustedToAuthForDelegation")
        AllowReversiblePasswordEncryption = [bool](Get-ObjectValue -InputObject $user -Name "AllowReversiblePasswordEncryption")
        HasSPN                  = [bool]($spns.Count -gt 0)
        SPNCount                = $spns.Count
        ServicePrincipalNames   = @($spns)
        ServicePrincipalNamesText = if ($spns.Count -gt 0) { $spns -join "; " } else { "" }
        AdminCount              = Get-ObjectValue -InputObject $user -Name "AdminCount"
        LockedOut               = [bool](Get-ObjectValue -InputObject $user -Name "LockedOut")
        AccountExpirationDateUtc = Format-DateTimeUtc -Value (Get-ObjectValue -InputObject $user -Name "AccountExpirationDate")
        Manager                 = Get-ObjectValue -InputObject $user -Name "Manager"
        OwnerEvidenceMissing    = [bool](-not ((Get-ObjectValue -InputObject $user -Name "Manager") -or (Get-ObjectValue -InputObject $user -Name "Description") -or (Get-ObjectValue -InputObject $user -Name "info")))
        MFAConditionalAccessStatus = "NotCheckedOnPremOnly"
        CloudProtectionGap      = "NotVerifiedByThisScript"
        RiskFlags               = @($assessment.RiskFlags)
        RiskFlagsText           = if ($assessment.RiskFlags.Count -gt 0) { $assessment.RiskFlags -join "; " } else { "" }
        ReviewReasons           = @($assessment.ReviewReasons)
        ReviewReasonsText       = if ($assessment.ReviewReasons.Count -gt 0) { $assessment.ReviewReasons -join " " } else { "" }
        ActivityEvidenceSource  = if ($null -ne $lastLogonDate) { "LastLogonDate from AD user detail." } else { "No LastLogonDate provided by this source." }
        ActivityEvidenceConfidence = if ($null -ne $lastLogonDate) { "Medium" } else { "Needs Corroboration" }
        ActivityValidationRequired = $true
        Classification          = $identityCategory
        ClassificationReason    = if ($assessment.ReviewReasons.Count -gt 0) { $assessment.ReviewReasons[0] } else { "Privileged identity category assigned from group membership evidence." }
        AccountReviewReason     = "Validate privileged purpose, owner, protection controls, and approval before account or group changes."
        RecommendedAction       = $assessment.RecommendedAction
        NextReviewStep          = $assessment.NextReviewStep
        UserQuerySucceeded      = [bool]$detail.Succeeded
        UserQueryError          = "$($detail.Error)"
        Description             = Get-ObjectValue -InputObject $user -Name "Description"
        DistinguishedName       = Get-ObjectValue -InputObject $user -Name "DistinguishedName"
    }
}

function New-FindingRow {
    param(
        [Parameter(Mandatory = $true)][string]$FindingType,
        [Parameter(Mandatory = $true)][string]$Severity,
        [AllowNull()][string]$Subject,
        [AllowNull()][string]$GroupName,
        [AllowNull()][string]$Evidence,
        [AllowNull()][string]$AdminAction,
        [AllowNull()][string]$VerificationStep
    )

    [pscustomobject][ordered]@{
        FindingType      = $FindingType
        Severity         = $Severity
        ActionPriority   = Get-ActionPriority -ReviewPriority $Severity
        Subject          = $Subject
        GroupName        = $GroupName
        Evidence         = $Evidence
        AdminAction      = $AdminAction
        VerificationStep = $VerificationStep
    }
}

function Get-ActionPriority {
    param([string]$ReviewPriority)

    switch ($ReviewPriority) {
        "Critical" { return "P1 - Immediate privileged identity review" }
        "High" { return "P2 - Protection gap review" }
        "Medium" { return "P3 - Membership cleanup review" }
        "Low" { return "P4 - Routine review" }
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
            ReportType     = "ADPrivilegedIdentityProtection"
            Status         = "Failed"
            GeneratedAtUtc = (Get-Date).ToUniversalTime().ToString("o")
            ComputerName   = $env:COMPUTERNAME
            Server         = if ($Server) { $Server } else { $null }
        }
        Summary = [ordered]@{
            Status = "Failed"
            Reason = $Reason
        }
        PrivilegedIdentities = @()
        Findings             = @()
    }

    $report | ConvertTo-Json -Depth 6 | Out-File -FilePath $JsonPath -Encoding utf8
}

function Add-MarkdownIdentityTable {
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

    Add-MarkdownLine -Lines $Lines -Text "| Priority | Account | Category | Enabled | Groups | Risk flags | Next step |"
    Add-MarkdownLine -Lines $Lines -Text "|---|---|---|---:|---|---|---|"
    foreach ($row in @($Rows | Select-Object -First $Limit)) {
        Add-MarkdownLine -Lines $Lines -Text ("| {0} | {1} | {2} | {3} | {4} | {5} | {6} |" -f `
                (ConvertTo-MarkdownSafeText $row.ActionPriority),
            (ConvertTo-MarkdownSafeText $row.SamAccountName),
            (ConvertTo-MarkdownSafeText $row.IdentityCategory),
            (ConvertTo-MarkdownSafeText $row.Enabled),
            (ConvertTo-MarkdownSafeText $row.EffectivePrivilegedGroupsText),
            (ConvertTo-MarkdownSafeText $row.RiskFlagsText),
            (ConvertTo-MarkdownSafeText $row.NextReviewStep))
    }

    if ($Rows.Count -gt $Limit) {
        Add-MarkdownLine -Lines $Lines
        Add-MarkdownLine -Lines $Lines -Text "Showing first $Limit of $($Rows.Count). See CSV/JSON for the full list."
    }
    Add-MarkdownLine -Lines $Lines
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

    Add-MarkdownLine -Lines $Lines -Text "| Priority | Type | Subject | Group | Evidence | Action |"
    Add-MarkdownLine -Lines $Lines -Text "|---|---|---|---|---|---|"
    foreach ($row in @($Rows | Select-Object -First $Limit)) {
        Add-MarkdownLine -Lines $Lines -Text ("| {0} | {1} | {2} | {3} | {4} | {5} |" -f `
                (ConvertTo-MarkdownSafeText $row.ActionPriority),
            (ConvertTo-MarkdownSafeText $row.FindingType),
            (ConvertTo-MarkdownSafeText $row.Subject),
            (ConvertTo-MarkdownSafeText $row.GroupName),
            (ConvertTo-MarkdownSafeText $row.Evidence),
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
    $rows = @($Report["PrivilegedIdentities"])
    $findings = @($Report["Findings"])
    $lines = New-Object System.Collections.Generic.List[string]

    Add-MarkdownLine -Lines $lines -Text "# AD Privileged Identity Protection Review"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "Generated UTC: ``$($metadata.GeneratedAtUtc)``"
    Add-MarkdownLine -Lines $lines -Text "Computer: ``$($metadata.ComputerName)``"
    Add-MarkdownLine -Lines $lines -Text "Mode: ``On-prem AD only; MFA/Conditional Access not checked``"
    Add-MarkdownLine -Lines $lines

    Add-MarkdownLine -Lines $lines -Text "## Summary"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "| Metric | Count |"
    Add-MarkdownLine -Lines $lines -Text "|---|---:|"
    foreach ($metric in @("PrivilegedIdentityCount", "CriticalIdentities", "HighIdentities", "DisabledPrivilegedMemberships", "NestedPrivilegedIdentities", "NotProtectedUsersMembers", "SmartcardNotRequired", "DelegationAllowed", "PasswordNeverExpires", "SPNPrivilegedIdentities", "CloudProtectionNotChecked")) {
        Add-MarkdownLine -Lines $lines -Text ("| {0} | {1} |" -f $metric, $summary.$metric)
    }
    Add-MarkdownLine -Lines $lines

    Add-MarkdownLine -Lines $lines -Text "## Admin Action Plan"
    Add-MarkdownLine -Lines $lines
    if ($summary.CriticalIdentities -gt 0) {
        Add-MarkdownLine -Lines $lines -Text "Critical privileged identity protection gaps exist. Start with built-in Administrator, delegation, pre-authentication disabled, privileged SPNs, and PasswordNeverExpires."
    }
    elseif ($summary.HighIdentities -gt 0) {
        Add-MarkdownLine -Lines $lines -Text "High privileged identity protection gaps exist. Prioritize Protected Users membership, smartcard requirements, delegation protection, owner evidence, and old passwords."
    }
    else {
        Add-MarkdownLine -Lines $lines -Text "No Critical or High privileged identity protection gaps were detected in the on-prem checks."
    }
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "This report cannot prove MFA or Conditional Access coverage. Use the future Entra/Microsoft Graph expansion to verify cloud-side protection."
    Add-MarkdownLine -Lines $lines

    Add-MarkdownLine -Lines $lines -Text "## Critical"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownIdentityTable -Lines $lines -Rows @($rows | Where-Object { $_.ReviewPriority -eq "Critical" } | Sort-Object SamAccountName)

    Add-MarkdownLine -Lines $lines -Text "## High"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownIdentityTable -Lines $lines -Rows @($rows | Where-Object { $_.ReviewPriority -eq "High" } | Sort-Object SamAccountName)

    Add-MarkdownLine -Lines $lines -Text "## Structural Findings"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownFindingTable -Lines $lines -Rows @($findings | Where-Object { $_.FindingType -ne "PrivilegedIdentityProtectionGap" } | Sort-Object @{ Expression = { Get-PrioritySortValue -Value $_.ActionPriority } }, Subject) -Limit 100

    Add-MarkdownLine -Lines $lines -Text "## All Privileged Identities"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownIdentityTable -Lines $lines -Rows @($rows | Sort-Object @{ Expression = { Get-PrioritySortValue -Value $_.ActionPriority } }, SamAccountName) -Limit 100

    Add-MarkdownLine -Lines $lines -Text "## Review Rules"
    Add-MarkdownLine -Lines $lines
    foreach ($note in @($summary.Notes)) {
        Add-MarkdownLine -Lines $lines -Text "- $note"
    }

    $lines | Out-File -FilePath $Path -Encoding utf8
}

New-Directory -Path $OutputDirectory
$resolvedOutputDirectory = (Resolve-Path -Path $OutputDirectory).Path
$jsonPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "privileged-identity-protection.json"
$identityCsvPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "privileged-identities.csv"
$membershipCsvPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "privileged-group-memberships.csv"
$findingCsvPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "privileged-identity-findings.csv"
$markdownPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "privileged-identity-protection-review.md"

if (-not (Import-ActiveDirectoryModule)) {
    $reason = "ActiveDirectory PowerShell module was not found. Install RSAT Active Directory tools or run this script on a domain management host."
    Write-FailedReport -JsonPath $jsonPath -Reason $reason
    throw $reason
}

$now = Get-Date
$commonParameters = Get-ADCommonParameters
$domainSummary = Get-DomainSummary -CommonParameters $commonParameters
$groupDefinitions = @(Get-DefaultGroupDefinitions -DomainSID "$($domainSummary.DomainSID)")
$groupRows = New-Object System.Collections.Generic.List[object]
$membershipRows = New-Object System.Collections.Generic.List[object]
$identityMap = @{}
$findingRows = New-Object System.Collections.Generic.List[object]
$reportErrors = New-Object System.Collections.Generic.List[string]

foreach ($definition in $groupDefinitions) {
    $group = Resolve-GroupDefinition -Definition $definition -CommonParameters $commonParameters
    $membership = Get-GroupMembershipRows -Group $group -CommonParameters $commonParameters
    foreach ($errorMessage in @($membership["Errors"])) {
        $reportErrors.Add($errorMessage) | Out-Null
        $findingRows.Add((New-FindingRow -FindingType "GroupQueryIssue" -Severity "High" -Subject $group.Name -GroupName $group.Name -Evidence $errorMessage -AdminAction "Verify the group exists and the account running the report can read membership." -VerificationStep "Run Get-ADGroupMember for the group from an AD management host.")) | Out-Null
    }

    foreach ($member in @($membership["DirectMembers"])) {
        $membershipRows.Add((New-MembershipRow -Group $group -Member $member -MembershipType "Direct")) | Out-Null
        $objectClass = "$(Get-ObjectValue -InputObject $member -Name "ObjectClass")"
        if ($objectClass -eq "user") {
            Add-IdentityMembership -Map $identityMap -Group $group -Member $member -MembershipType "Direct"
        }
        elseif (-not $group.IsProtectionGroup -and $objectClass -eq "group") {
            $findingRows.Add((New-FindingRow -FindingType "NestedPrivilegedGroup" -Severity "High" -Subject (Get-ObjectValue -InputObject $member -Name "Name") -GroupName $group.Name -Evidence "Nested group has direct membership in privileged group." -AdminAction "Review nested group membership and document why nested privileged access is required." -VerificationStep "Open the group in ADUC/PowerShell and review direct and recursive members.")) | Out-Null
        }
        elseif (-not $group.IsProtectionGroup -and $objectClass -in @("computer", "foreignSecurityPrincipal")) {
            $findingRows.Add((New-FindingRow -FindingType "NonUserPrivilegedPrincipal" -Severity "High" -Subject (Get-ObjectValue -InputObject $member -Name "Name") -GroupName $group.Name -Evidence "Non-user principal type '$objectClass' is directly in privileged group." -AdminAction "Confirm this principal is expected and remove it if unauthorized." -VerificationStep "Review direct group membership and ownership evidence.")) | Out-Null
        }
    }

    foreach ($member in @($membership["RecursiveMembers"])) {
        $membershipRows.Add((New-MembershipRow -Group $group -Member $member -MembershipType "Effective")) | Out-Null
        $objectClass = "$(Get-ObjectValue -InputObject $member -Name "ObjectClass")"
        if ($objectClass -eq "user") {
            Add-IdentityMembership -Map $identityMap -Group $group -Member $member -MembershipType "Effective"
        }
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
            IsProtectionGroup    = [bool]$group.IsProtectionGroup
            IsExtraGroup         = [bool]$group.IsExtraGroup
            DirectMemberCount    = @($membership["DirectMembers"]).Count
            EffectiveMemberCount = @($membership["RecursiveMembers"]).Count
            Description          = $group.Description
        }) | Out-Null
}

$identityRows = New-Object System.Collections.Generic.List[object]
foreach ($record in @($identityMap.Values)) {
    if (@($record.EffectiveAccessGroups | Where-Object { $_ }).Count -eq 0) {
        continue
    }

    $row = ConvertTo-PrivilegedIdentityRow -Record $record -CommonParameters $commonParameters -Now $now
    $identityRows.Add($row) | Out-Null
    if ($row.ReviewPriority -in @("Critical", "High")) {
        $findingRows.Add((New-FindingRow -FindingType "PrivilegedIdentityProtectionGap" -Severity $row.ReviewPriority -Subject $row.SamAccountName -GroupName $row.EffectivePrivilegedGroupsText -Evidence $row.RiskFlagsText -AdminAction $row.RecommendedAction -VerificationStep $row.NextReviewStep)) | Out-Null
    }
}

$identityRowsFinal = @($identityRows.ToArray() | Sort-Object @{ Expression = { Get-PrioritySortValue -Value $_.ActionPriority } }, SamAccountName)
$membershipRowsFinal = @($membershipRows.ToArray() | Sort-Object GroupName, MembershipType, MemberName)
$findingRowsFinal = @($findingRows.ToArray() | Sort-Object @{ Expression = { Get-PrioritySortValue -Value $_.ActionPriority } }, FindingType, Subject)
$groupRowsFinal = @($groupRows.ToArray() | Sort-Object Name)

$summary = [ordered]@{
    GroupsAudited                  = $groupRowsFinal.Count
    GroupsResolved                 = @($groupRowsFinal | Where-Object { $_.Succeeded }).Count
    GroupsFailed                   = @($groupRowsFinal | Where-Object { -not $_.Succeeded }).Count
    PrivilegedIdentityCount        = $identityRowsFinal.Count
    CriticalIdentities             = @($identityRowsFinal | Where-Object { $_.ReviewPriority -eq "Critical" }).Count
    HighIdentities                 = @($identityRowsFinal | Where-Object { $_.ReviewPriority -eq "High" }).Count
    MediumIdentities               = @($identityRowsFinal | Where-Object { $_.ReviewPriority -eq "Medium" }).Count
    DisabledPrivilegedMemberships  = @($identityRowsFinal | Where-Object { -not $_.Enabled }).Count
    NestedPrivilegedIdentities     = @($identityRowsFinal | Where-Object { $_.NestedPrivilegedAccess }).Count
    NotProtectedUsersMembers       = @($identityRowsFinal | Where-Object { $_.CriticalGroupMember -and -not $_.ProtectedUsersMember }).Count
    SmartcardNotRequired           = @($identityRowsFinal | Where-Object { -not $_.SmartcardLogonRequired }).Count
    DelegationAllowed              = @($identityRowsFinal | Where-Object { -not $_.AccountNotDelegated }).Count
    PasswordNeverExpires           = @($identityRowsFinal | Where-Object { $_.PasswordNeverExpires }).Count
    SPNPrivilegedIdentities        = @($identityRowsFinal | Where-Object { $_.HasSPN }).Count
    CloudProtectionNotChecked      = $identityRowsFinal.Count
    StructuralFindings             = @($findingRowsFinal | Where-Object { $_.FindingType -ne "PrivilegedIdentityProtectionGap" }).Count
    ReportErrors                   = @($reportErrors.ToArray())
    Notes                          = @(
        "This script is audit-only and does not change group membership or account properties.",
        "This version checks on-prem AD signals only. It cannot verify Entra ID MFA, Conditional Access, or cloud role protection.",
        "Critical groups are Domain Admins, Enterprise Admins, Schema Admins, and Builtin Administrators.",
        "Protected Users membership is treated as a useful on-prem protection signal, but it may not fit every legacy service dependency.",
        "Smartcard required, AccountNotDelegated, Protected Users, and password rotation changes must be tested through approved change control.",
        "Disabled accounts should not remain in privileged groups unless there is a documented break-glass or recovery reason."
    )
}

$report = [ordered]@{
    ReportMetadata = [ordered]@{
        SchemaVersion      = "1.0"
        ReportType         = "ADPrivilegedIdentityProtection"
        Status             = "Completed"
        GeneratedAtUtc     = (Get-Date).ToUniversalTime().ToString("o")
        ComputerName       = $env:COMPUTERNAME
        RunBy              = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        Server             = if ($Server) { $Server } else { $null }
        StaleDays          = $StaleDays
        MaxCredentialAgeDays = $MaxCredentialAgeDays
        ExtraGroups        = @($GroupName)
        OutputDirectory    = $resolvedOutputDirectory
        JsonPath           = $jsonPath
        IdentityCsvPath    = $identityCsvPath
        MembershipCsvPath  = $membershipCsvPath
        FindingCsvPath     = $findingCsvPath
        MarkdownPath       = $markdownPath
    }
    Domain               = $domainSummary
    Summary              = $summary
    Groups               = @($groupRowsFinal)
    Memberships          = @($membershipRowsFinal)
    PrivilegedIdentities = @($identityRowsFinal)
    Findings             = @($findingRowsFinal)
}

$report | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding utf8
Write-CsvReport -Path $identityCsvPath -Rows $identityRowsFinal -Columns @("ReviewPriority", "ActionPriority", "IdentityCategory", "Classification", "ClassificationReason", "AccountReviewReason", "ActivityEvidenceSource", "ActivityEvidenceConfidence", "ActivityValidationRequired", "SamAccountName", "Name", "UserPrincipalName", "SID", "Enabled", "DirectPrivilegedGroupsText", "EffectivePrivilegedGroupsText", "CriticalGroupMember", "NestedPrivilegedAccess", "ProtectedUsersMember", "SmartcardLogonRequired", "AccountNotDelegated", "PasswordNeverExpires", "PasswordLastSetUtc", "PasswordAgeDays", "LastLogonDateUtc", "InactiveDays", "DoesNotRequirePreAuth", "TrustedForDelegation", "TrustedToAuthForDelegation", "AllowReversiblePasswordEncryption", "HasSPN", "SPNCount", "AdminCount", "OwnerEvidenceMissing", "MFAConditionalAccessStatus", "RiskFlagsText", "ReviewReasonsText", "RecommendedAction", "NextReviewStep", "UserQuerySucceeded", "UserQueryError", "Description", "DistinguishedName")
Write-CsvReport -Path $membershipCsvPath -Rows $membershipRowsFinal -Columns @("GroupName", "GroupSID", "GroupTier", "GroupExpectedRisk", "IsProtectionGroup", "MembershipType", "MemberName", "MemberSamAccountName", "MemberObjectClass", "MemberSID", "MemberDN")
Write-CsvReport -Path $findingCsvPath -Rows $findingRowsFinal -Columns @("FindingType", "Severity", "ActionPriority", "Subject", "GroupName", "Evidence", "AdminAction", "VerificationStep")
Write-MarkdownReport -Path $markdownPath -Report $report

if (-not $Quiet) {
    Write-Host "AD privileged identity protection report written to: $jsonPath"
    Write-Host "AD privileged identity protection review written to: $markdownPath"
    Write-Host "Privileged identities: $($summary.PrivilegedIdentityCount)"
    Write-Host "Critical: $($summary.CriticalIdentities)"
    Write-Host "High: $($summary.HighIdentities)"
    Write-Host "Cloud MFA/Conditional Access: not checked in this on-prem-only version"
}
