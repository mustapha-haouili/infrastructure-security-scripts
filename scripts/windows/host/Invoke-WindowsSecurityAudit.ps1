<#
.SYNOPSIS
Collects a defensive Windows security baseline and writes a JSON report.

.DESCRIPTION
This script gathers common enterprise security posture signals from a local
Windows host. It does not change system configuration.

Run from an elevated PowerShell session for complete results.

.PARAMETER OutputPath
Path for the JSON report. The parent directory is created when needed.
Default: .\reports\windows-security-audit-COMPUTER-TIMESTAMP.json

.PARAMETER IncludeHotfixes
Includes the latest installed hotfix records in the report. This can make the
report larger, but helps when reviewing patch state.

.PARAMETER Quiet
Suppresses the console summary after the JSON report is written. Useful for
scheduled tasks or automation that only needs the report file.

.EXAMPLE
.\Invoke-WindowsSecurityAudit.ps1

Run the audit with the default report path.

.EXAMPLE
.\Invoke-WindowsSecurityAudit.ps1 -IncludeHotfixes

Run the audit and include recent hotfix details.

.EXAMPLE
.\Invoke-WindowsSecurityAudit.ps1 -OutputPath .\reports\server01-audit.json

Write the audit report to a specific file.

.EXAMPLE
.\Invoke-WindowsSecurityAudit.ps1 -OutputPath .\reports\server01-audit.json -IncludeHotfixes -Quiet

Write a quiet automation-friendly report with hotfix evidence included.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ".\reports\windows-security-audit-$env:COMPUTERNAME-$(Get-Date -Format 'yyyyMMdd-HHmmss').json",
    [switch]$IncludeHotfixes,
    [switch]$Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-Safe {
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,
        [object]$Default = $null
    )

    try {
        & $ScriptBlock
    }
    catch {
        $Default
    }
}

function New-ParentDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)

    $parent = Split-Path -Path $Path -Parent
    if ($parent -and -not (Test-Path -Path $parent)) {
        New-Item -Path $parent -ItemType Directory -Force | Out-Null
    }
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-RegistryValueSafe {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )

    Invoke-Safe -ScriptBlock {
        $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        $item.$Name
    } -Default $null
}

function Get-LocalAdministratorsSafe {
    $members = Invoke-Safe -ScriptBlock {
        Get-LocalGroupMember -Group "Administrators" | ForEach-Object {
            [ordered]@{
                Name        = $_.Name
                ObjectClass = $_.ObjectClass
                PrincipalSource = $_.PrincipalSource
            }
        }
    } -Default $null

    if ($members) {
        return $members
    }

    $raw = Invoke-Safe -ScriptBlock { net localgroup Administrators } -Default @()
    return @($raw | Where-Object { $_ -and $_ -notmatch "command completed|---|Alias name|Comment|Members" })
}

function Get-ListeningPortsSafe {
    Invoke-Safe -ScriptBlock {
        Get-NetTCPConnection -State Listen | Sort-Object LocalPort, LocalAddress | ForEach-Object {
            $connection = $_
            $processName = Invoke-Safe -ScriptBlock {
                (Get-Process -Id $connection.OwningProcess -ErrorAction Stop).ProcessName
            } -Default "unknown"

            [ordered]@{
                LocalAddress = $connection.LocalAddress
                LocalPort    = $connection.LocalPort
                ProcessId    = $connection.OwningProcess
                ProcessName  = $processName
            }
        }
    } -Default @()
}

function Get-PasswordPolicySafe {
    $lines = Invoke-Safe -ScriptBlock { net accounts } -Default @()
    $policy = [ordered]@{}

    foreach ($line in $lines) {
        if ($line -match "^(.+?):\s+(.+)$") {
            $key = ($Matches[1] -replace "\s+", " ").Trim()
            $value = $Matches[2].Trim()
            $policy[$key] = $value
        }
    }

    return $policy
}

function Get-AuditPolicySafe {
    $csv = Invoke-Safe -ScriptBlock { auditpol /get /category:* /r 2>$null } -Default @()
    if (-not $csv) {
        return @()
    }

    Invoke-Safe -ScriptBlock {
        $csv | ConvertFrom-Csv
    } -Default $csv
}

function Get-SecurityServiceState {
    $serviceNames = @(
        "WinDefend",
        "MpsSvc",
        "wuauserv",
        "BITS",
        "EventLog",
        "WinRM",
        "LanmanServer",
        "LanmanWorkstation"
    )

    foreach ($name in $serviceNames) {
        Invoke-Safe -ScriptBlock {
            $svc = Get-Service -Name $name -ErrorAction Stop
            [ordered]@{
                Name        = $svc.Name
                DisplayName = $svc.DisplayName
                Status      = $svc.Status.ToString()
                StartType   = (Get-CimInstance -ClassName Win32_Service -Filter "Name='$name'").StartMode
            }
        } -Default ([ordered]@{
            Name = $name
            DisplayName = $null
            Status = "NotFound"
            StartType = $null
        })
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

function Test-EnabledValue {
    param([AllowNull()][object]$Value)

    $text = "$Value"
    return $Value -eq $true -or $text -eq "1" -or $text -eq "True" -or $text -eq "Enabled"
}

function Test-DwordValueEquals {
    param(
        [AllowNull()][object]$Value,
        [Parameter(Mandatory = $true)][int]$Expected
    )

    if ($null -eq $Value) {
        return $false
    }

    return "$Value" -eq "$Expected"
}

function New-FindingList {
    New-Object System.Collections.Generic.List[object]
}

function New-CisReference {
    param(
        [Parameter(Mandatory = $true)][string]$Recommendation,
        [string]$Level = "",
        [string]$WazuhWin2019CheckId = "",
        [string]$WazuhWin11EnterpriseCheckId = ""
    )

    [ordered]@{
        Standard                    = "CIS"
        Recommendation              = $Recommendation
        Level                       = $Level
        Source                      = "Wazuh SCA"
        WazuhWin2019CheckId         = $WazuhWin2019CheckId
        WazuhWin11EnterpriseCheckId = $WazuhWin11EnterpriseCheckId
    }
}

function Add-Finding {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Findings,
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$Severity,
        [Parameter(Mandatory = $true)][string]$Area,
        [Parameter(Mandatory = $true)][string]$Title,
        [Parameter(Mandatory = $true)][string]$WhyItMatters,
        [Parameter(Mandatory = $true)][string]$Recommendation,
        [Parameter(Mandatory = $true)][string]$Evidence,
        [string]$OperationalNote = "",
        [object[]]$Standards = @(),
        [string]$SuggestedFix = "",
        [bool]$AutoFixEligible = $false,
        [bool]$RequiresAdmin = $true,
        [string]$RiskLevel = "Review",
        [string]$ExceptionGuidance = "Document an approved exception if this setting is intentionally managed elsewhere or required for a business-specific control."
    )

    if (-not $SuggestedFix) {
        $SuggestedFix = $Recommendation
    }

    $Findings.Add([ordered]@{
        Id                = $Id
        Severity          = $Severity
        Area              = $Area
        Title             = $Title
        WhyItMatters      = $WhyItMatters
        Recommendation    = $Recommendation
        SuggestedFix      = $SuggestedFix
        AutoFixEligible   = $AutoFixEligible
        RequiresAdmin     = $RequiresAdmin
        RiskLevel         = $RiskLevel
        ExceptionGuidance = $ExceptionGuidance
        Evidence          = $Evidence
        OperationalNote   = $OperationalNote
        Standards         = @($Standards)
    }) | Out-Null
}

function Get-CountBySeverity {
    param([object[]]$Findings)

    $counts = [ordered]@{
        Critical = 0
        High     = 0
        Medium   = 0
        Low      = 0
        Info     = 0
    }

    foreach ($finding in @($Findings)) {
        $severity = Get-ObjectValue -InputObject $finding -Name "Severity"
        if ($severity -and $counts.Contains($severity)) {
            $counts[$severity]++
        }
    }

    return $counts
}

function Get-PostureRating {
    param([object]$SeverityCounts)

    if ($SeverityCounts["Critical"] -gt 0) {
        return "Critical review required"
    }
    if ($SeverityCounts["High"] -gt 0) {
        return "High priority review required"
    }
    if ($SeverityCounts["Medium"] -gt 0) {
        return "Review recommended"
    }
    return "No high-signal issues detected by built-in checks"
}

function Get-WindowsAuditFindings {
    param([Parameter(Mandatory = $true)][object]$Audit)

    $findings = New-FindingList
    $firewallStateStandards = @{
        Domain  = @(New-CisReference -Recommendation "9.1.1" -Level "L1" -WazuhWin2019CheckId "16577" -WazuhWin11EnterpriseCheckId "26116")
        Private = @(New-CisReference -Recommendation "9.2.1" -Level "L1" -WazuhWin2019CheckId "16585" -WazuhWin11EnterpriseCheckId "26123")
        Public  = @(New-CisReference -Recommendation "9.3.1" -Level "L1" -WazuhWin2019CheckId "16593" -WazuhWin11EnterpriseCheckId "26130")
    }
    $firewallInboundStandards = @{
        Domain  = @(New-CisReference -Recommendation "9.1.2" -Level "L1" -WazuhWin2019CheckId "16578" -WazuhWin11EnterpriseCheckId "26117")
        Private = @(New-CisReference -Recommendation "9.2.2" -Level "L1" -WazuhWin2019CheckId "16586" -WazuhWin11EnterpriseCheckId "26124")
        Public  = @(New-CisReference -Recommendation "9.3.2" -Level "L1" -WazuhWin2019CheckId "16594" -WazuhWin11EnterpriseCheckId "26131")
    }

    foreach ($profile in @($Audit["FirewallProfiles"])) {
        $name = Get-ObjectValue -InputObject $profile -Name "Name"
        $enabled = Get-ObjectValue -InputObject $profile -Name "Enabled"
        if (-not (Test-EnabledValue -Value $enabled)) {
            Add-Finding -Findings $findings `
                -Id "WIN-FW-001" `
                -Severity "High" `
                -Area "Firewall" `
                -Title "Windows Firewall profile is disabled" `
                -WhyItMatters "Disabled firewall profiles increase exposure from lateral movement, unwanted inbound connections, and service misconfiguration." `
                -Recommendation "Enable Windows Firewall for the $name profile and review allowed inbound rules before production rollout." `
                -Evidence "$name profile Enabled=$enabled" `
                -OperationalNote "On an RDP server, validate required RDP, application, monitoring, and management rules before enforcing." `
                -Standards @($firewallStateStandards[$name]) `
                -SuggestedFix "Enable the $name firewall profile after confirming required RDP, application, monitoring, and management allow rules are present." `
                -AutoFixEligible $true `
                -RiskLevel "Medium" `
                -ExceptionGuidance "Document the network control that replaces host firewall enforcement if this profile is intentionally disabled."
        }

        $defaultInbound = Get-ObjectValue -InputObject $profile -Name "DefaultInboundAction"
        if ($defaultInbound -and "$defaultInbound" -ne "Block") {
            Add-Finding -Findings $findings `
                -Id "WIN-FW-002" `
                -Severity "Medium" `
                -Area "Firewall" `
                -Title "Windows Firewall profile does not block inbound connections by default" `
                -WhyItMatters "A permissive default inbound policy can expose services that should only be reachable through explicit firewall rules." `
                -Recommendation "Set the $name profile default inbound action to Block and allow only required services." `
                -Evidence "$name profile DefaultInboundAction=$defaultInbound" `
                -OperationalNote "Review application, RDP, monitoring, and management allow rules before changing production firewall defaults." `
                -Standards @($firewallInboundStandards[$name]) `
                -SuggestedFix "Set the $name firewall profile default inbound action to Block, then keep explicit allow rules for required services." `
                -AutoFixEligible $true `
                -RiskLevel "Medium" `
                -ExceptionGuidance "Document any centrally managed firewall baseline or host role that requires a different default inbound posture."
        }
    }

    $defender = $Audit["Defender"]
    if ($null -eq $defender) {
        Add-Finding -Findings $findings -Id "WIN-DEF-001" -Severity "Medium" -Area "Endpoint protection" -Title "Defender status could not be collected" -WhyItMatters "The audit could not confirm endpoint protection state." -Recommendation "Confirm Microsoft Defender or an approved EDR is installed, healthy, and centrally managed." -Evidence "Get-MpComputerStatus returned no data." -SuggestedFix "Run the audit as Administrator and verify endpoint protection health in Microsoft Defender, ESET, or the approved EDR console." -AutoFixEligible $false -RiskLevel "Medium" -ExceptionGuidance "If a third-party EDR replaces Defender, record the EDR product, management console, policy owner, and last healthy check-in."
    }
    else {
        $disabledDefenderComponents = New-Object System.Collections.Generic.List[string]
        foreach ($name in @("AMServiceEnabled", "AntivirusEnabled", "RealTimeProtectionEnabled", "BehaviorMonitorEnabled", "IoavProtectionEnabled")) {
            $value = Get-ObjectValue -InputObject $defender -Name $name
            if (-not (Test-EnabledValue -Value $value)) {
                $disabledDefenderComponents.Add("$name=$value") | Out-Null
            }
        }

        if ($disabledDefenderComponents.Count -gt 0) {
            Add-Finding -Findings $findings `
                -Id "WIN-DEF-002" `
                -Severity "High" `
                -Area "Endpoint protection" `
                -Title "Microsoft Defender protection components are disabled" `
                -WhyItMatters "Disabled antivirus or real-time protection reduces malware detection and response coverage." `
                -Recommendation "Enable Defender protection or document the approved replacement EDR control." `
                -Evidence ($disabledDefenderComponents.ToArray() -join "; ") `
                -SuggestedFix "Confirm whether an approved EDR replaces Defender. If not, enable Microsoft Defender Antivirus plus real-time, behavior, and IOAV protections." `
                -AutoFixEligible $false `
                -RequiresAdmin $true `
                -RiskLevel "High" `
                -ExceptionGuidance "If ESET or another managed EDR is the approved control, record the product, central policy owner, host assignment, and current healthy status instead of enabling Defender."
        }
    }

    $passwordPolicy = $Audit["PasswordPolicy"]
    $minimumLength = Get-ObjectValue -InputObject $passwordPolicy -Name "Minimum password length"
    if ($minimumLength -and [int]$minimumLength -lt 14) {
        Add-Finding -Findings $findings `
            -Id "WIN-PWD-001" `
            -Severity "Medium" `
            -Area "Password policy" `
            -Title "Minimum password length is below 14 characters" `
            -WhyItMatters "Shorter passwords are easier to guess, spray, or crack offline if hashes are exposed." `
            -Recommendation "Use at least 14 characters unless domain policy, MFA, or passwordless controls provide an approved exception." `
            -Evidence "Minimum password length=$minimumLength" `
            -Standards @(New-CisReference -Recommendation "1.1.4" -Level "L1" -WazuhWin2019CheckId "16502" -WazuhWin11EnterpriseCheckId "26003") `
            -SuggestedFix "Set local or domain minimum password length to at least 14 characters, or confirm password policy is enforced by another identity control." `
            -AutoFixEligible $true `
            -RiskLevel "Medium" `
            -ExceptionGuidance "Document the domain, Entra ID, MFA, passwordless, or privileged-access policy that supersedes local password settings."
    }

    $lockoutThreshold = Get-ObjectValue -InputObject $passwordPolicy -Name "Lockout threshold"
    if ($lockoutThreshold -and ([int]$lockoutThreshold -eq 0)) {
        Add-Finding -Findings $findings `
            -Id "WIN-PWD-002" `
            -Severity "High" `
            -Area "Password policy" `
            -Title "Account lockout threshold is disabled" `
            -WhyItMatters "No lockout threshold allows unlimited password guessing against local or domain accounts, depending on policy scope." `
            -Recommendation "Set a lockout threshold and observation window that match your identity policy." `
            -Evidence "Lockout threshold=$lockoutThreshold" `
            -Standards @(New-CisReference -Recommendation "1.2.2" -Level "L1" -WazuhWin2019CheckId "16504" -WazuhWin11EnterpriseCheckId "26006") `
            -SuggestedFix "Set a nonzero account lockout threshold of 5 or fewer invalid attempts and align duration/window with identity policy." `
            -AutoFixEligible $true `
            -RiskLevel "Medium" `
            -ExceptionGuidance "Document any domain, Entra ID, MFA, or passwordless policy that intentionally owns lockout behavior."
    }

    $localAccounts = $Audit["LocalAccounts"]
    $guestAccount = Get-ObjectValue -InputObject $localAccounts -Name "Guest"
    if ($null -eq $guestAccount) {
        Add-Finding -Findings $findings `
            -Id "WIN-LOCAL-001" `
            -Severity "Info" `
            -Area "Local accounts" `
            -Title "Local Guest account status could not be verified" `
            -WhyItMatters "The built-in Guest account should be disabled or intentionally managed by policy." `
            -Recommendation "Run the audit as Administrator and confirm the local Guest account is disabled." `
            -Evidence "Guest account query returned no data" `
            -Standards @(New-CisReference -Recommendation "2.3.1.2" -Level "L1" -WazuhWin2019CheckId "16507" -WazuhWin11EnterpriseCheckId "26009") `
            -SuggestedFix "Rerun the audit as Administrator, then disable the built-in Guest account if it is enabled." `
            -AutoFixEligible $false `
            -RiskLevel "Low"
    }
    else {
        $guestDisabled = Get-ObjectValue -InputObject $guestAccount -Name "Disabled"
        if (-not (Test-EnabledValue -Value $guestDisabled)) {
            Add-Finding -Findings $findings `
                -Id "WIN-LOCAL-002" `
                -Severity "High" `
                -Area "Local accounts" `
                -Title "Built-in Guest account is enabled" `
                -WhyItMatters "Guest access can provide unaudited or weakly controlled local access paths." `
                -Recommendation "Disable the built-in Guest account unless there is a documented exception." `
                -Evidence "Guest Disabled=$guestDisabled" `
                -Standards @(New-CisReference -Recommendation "2.3.1.2" -Level "L1" -WazuhWin2019CheckId "16507" -WazuhWin11EnterpriseCheckId "26009") `
                -SuggestedFix "Disable the built-in Guest account." `
                -AutoFixEligible $true `
                -RiskLevel "Low" `
                -ExceptionGuidance "Document any temporary support exception and remove it after the support window closes."
        }
    }

    $requiredAuditSubcategories = @(
        @{ Id = "WIN-AUDIT-LOGON"; Name = "Logon"; Guid = "{0CCE9215-69AE-11D9-BED3-505054503030}"; Severity = "High"; RequiredInclusion = @("Success", "Failure"); Standards = @(New-CisReference -Recommendation "17.5.4" -Level "L1" -WazuhWin2019CheckId "16619" -WazuhWin11EnterpriseCheckId "26148") },
        @{ Id = "WIN-AUDIT-LOCKOUT"; Name = "Account Lockout"; Guid = "{0CCE9217-69AE-11D9-BED3-505054503030}"; Severity = "High"; RequiredInclusion = @("Failure"); Standards = @(New-CisReference -Recommendation "17.5.1" -Level "L1" -WazuhWin2019CheckId "16616" -WazuhWin11EnterpriseCheckId "26145") },
        @{ Id = "WIN-AUDIT-UAM"; Name = "User Account Management"; Guid = "{0CCE9235-69AE-11D9-BED3-505054503030}"; Severity = "Medium"; RequiredInclusion = @("Success", "Failure"); Standards = @(New-CisReference -Recommendation "17.2.6 / 17.2.3" -Level "L1" -WazuhWin2019CheckId "16611" -WazuhWin11EnterpriseCheckId "26142") },
        @{ Id = "WIN-AUDIT-SGM"; Name = "Security Group Management"; Guid = "{0CCE9237-69AE-11D9-BED3-505054503030}"; Severity = "Medium"; RequiredInclusion = @("Success"); Standards = @(New-CisReference -Recommendation "17.2.5 / 17.2.2" -Level "L1" -WazuhWin2019CheckId "16610" -WazuhWin11EnterpriseCheckId "26141") },
        @{ Id = "WIN-AUDIT-PROC"; Name = "Process Creation"; Guid = "{0CCE922B-69AE-11D9-BED3-505054503030}"; Severity = "Medium"; RequiredInclusion = @("Success"); Standards = @(New-CisReference -Recommendation "17.3.2" -Level "L1" -WazuhWin2019CheckId "16613" -WazuhWin11EnterpriseCheckId "26144") },
        @{ Id = "WIN-AUDIT-POLICY"; Name = "Audit Policy Change"; Guid = "{0CCE922F-69AE-11D9-BED3-505054503030}"; Severity = "Medium"; RequiredInclusion = @("Success"); Standards = @(New-CisReference -Recommendation "17.7.1" -Level "L1" -WazuhWin2019CheckId "16626" -WazuhWin11EnterpriseCheckId "26155") }
    )

    foreach ($required in $requiredAuditSubcategories) {
        $record = @($Audit["AuditPolicy"] | Where-Object { (Get-ObjectValue -InputObject $_ -Name "Subcategory GUID") -eq $required.Guid } | Select-Object -First 1)
        if (-not $record) {
            Add-Finding -Findings $findings -Id $required.Id -Severity "Info" -Area "Audit policy" -Title "Audit policy subcategory was not found" -WhyItMatters "The report could not verify this audit category." -Recommendation "Run the audit as Administrator and confirm auditpol output." -Evidence "$($required.Name) GUID $($required.Guid) not present." -Standards @($required.Standards) -SuggestedFix "Rerun the audit as Administrator so auditpol output can be collected, then remediate only if $($required.Name) is still incomplete." -AutoFixEligible $false -RequiresAdmin $true -RiskLevel "Verification"
            continue
        }

        $setting = Get-ObjectValue -InputObject $record[0] -Name "Inclusion Setting"
        $missingInclusion = @($required.RequiredInclusion | Where-Object { $setting -notmatch $_ })
        if ($missingInclusion.Count -gt 0) {
            Add-Finding -Findings $findings `
                -Id $required.Id `
                -Severity $required.Severity `
                -Area "Audit policy" `
                -Title "$($required.Name) auditing is incomplete" `
                -WhyItMatters "Missing audit events reduce investigation visibility after suspicious logon, account, process, or policy activity." `
                -Recommendation "Enable $($required.RequiredInclusion -join ' and ') auditing for $($required.Name)." `
                -Evidence "$($required.Name) Inclusion Setting=$setting; missing $($missingInclusion -join ', ')" `
                -Standards @($required.Standards) `
                -SuggestedFix "Enable $($required.RequiredInclusion -join ' and ') auditing for $($required.Name) using auditpol, Group Policy, or your central baseline." `
                -AutoFixEligible $true `
                -RiskLevel "Low" `
                -ExceptionGuidance "Document any central audit policy that intentionally uses a different setting and include SIEM coverage evidence."
        }
    }

    $remoteAccess = $Audit["RemoteAccess"]
    $rdpDeny = Get-ObjectValue -InputObject $remoteAccess -Name "RdpDenyConnections"
    $rdpNla = Get-ObjectValue -InputObject $remoteAccess -Name "RdpNlaRequired"
    if ($rdpDeny -eq 0 -and $rdpNla -ne 1) {
        Add-Finding -Findings $findings `
            -Id "WIN-RDP-001" `
            -Severity "High" `
            -Area "Remote access" `
            -Title "RDP is enabled without Network Level Authentication" `
            -WhyItMatters "RDP without NLA exposes the host to more pre-authentication attack surface." `
            -Recommendation "Require NLA for RDP unless a documented legacy exception exists." `
            -Evidence "RdpDenyConnections=$rdpDeny; RdpNlaRequired=$rdpNla" `
            -Standards @(New-CisReference -Recommendation "18.10.57.3.9.4 / 18.10.56.3.9.4" -Level "L1" -WazuhWin2019CheckId "16811" -WazuhWin11EnterpriseCheckId "26426") `
            -SuggestedFix "Enable RDP Network Level Authentication or disable RDP if remote desktop access is not required." `
            -AutoFixEligible $true `
            -RiskLevel "Medium" `
            -ExceptionGuidance "Document any legacy client or MFA/RDP gateway constraint that prevents NLA enforcement."
    }
    elseif ($rdpDeny -eq 0) {
        Add-Finding -Findings $findings `
            -Id "WIN-RDP-002" `
            -Severity "Info" `
            -Area "Remote access" `
            -Title "RDP is enabled" `
            -WhyItMatters "RDP is expected on many terminal servers, but it should be restricted and monitored." `
            -Recommendation "Confirm RDP is limited by firewall, VPN, or network policy and that NLA remains enabled." `
            -Evidence "RdpDenyConnections=$rdpDeny; RdpNlaRequired=$rdpNla" `
            -SuggestedFix "Confirm RDP is required, NLA remains enabled, and access is restricted to trusted management networks or VPN." `
            -AutoFixEligible $false `
            -RiskLevel "Review" `
            -ExceptionGuidance "Document the business owner, allowed source networks, and monitoring for hosts that intentionally expose RDP."
    }

    $winRmStatus = Get-ObjectValue -InputObject $remoteAccess -Name "WinRmService"
    if ($winRmStatus -eq "Running") {
        Add-Finding -Findings $findings `
            -Id "WIN-WINRM-001" `
            -Severity "Info" `
            -Area "Remote management" `
            -Title "WinRM service is running" `
            -WhyItMatters "WinRM is useful for administration but increases remote management exposure if broadly reachable." `
            -Recommendation "Confirm WinRM is required, restricted to management networks, and logged." `
            -Evidence "WinRM service status=$winRmStatus" `
            -SuggestedFix "Disable WinRM if not required, or restrict it to trusted management networks with approved authentication and logging." `
            -AutoFixEligible $false `
            -RiskLevel "Review" `
            -ExceptionGuidance "Document the management platform, allowed source networks, authentication method, and logging coverage for WinRM-enabled hosts."
    }

    $coreSettings = $Audit["CoreSettings"]
    $smb1Enabled = Get-ObjectValue -InputObject $coreSettings -Name "Smb1ServerEnabled"
    if (Test-EnabledValue -Value $smb1Enabled) {
        Add-Finding -Findings $findings `
            -Id "WIN-SMB-001" `
            -Severity "Critical" `
            -Area "Legacy protocols" `
            -Title "SMBv1 server protocol is enabled" `
            -WhyItMatters "SMBv1 is obsolete and has a long history of severe exploitation and lateral movement risk." `
            -Recommendation "Disable SMBv1 server protocol unless a formally approved legacy dependency exists." `
            -Evidence "Smb1ServerEnabled=$smb1Enabled" `
            -Standards @(New-CisReference -Recommendation "18.4.4" -Level "L1" -WazuhWin2019CheckId "16650" -WazuhWin11EnterpriseCheckId "26173") `
            -SuggestedFix "Disable the SMBv1 server protocol after confirming no legacy file-sharing dependency remains." `
            -AutoFixEligible $true `
            -RiskLevel "Medium" `
            -ExceptionGuidance "Document the legacy system, owner, compensating controls, and retirement date if SMBv1 must remain enabled."
    }

    $smb1ClientDriverStart = Get-ObjectValue -InputObject $coreSettings -Name "Smb1ClientDriverStart"
    if ($smb1ClientDriverStart -and -not (Test-DwordValueEquals -Value $smb1ClientDriverStart -Expected 4)) {
        Add-Finding -Findings $findings `
            -Id "WIN-SMB-002" `
            -Severity "High" `
            -Area "Legacy protocols" `
            -Title "SMBv1 client driver is not disabled" `
            -WhyItMatters "The legacy SMBv1 client increases exposure to obsolete file-sharing protocol risks." `
            -Recommendation "Disable the SMBv1 client driver after validating legacy dependencies." `
            -Evidence "mrxsmb10 Start=$smb1ClientDriverStart; expected 4" `
            -Standards @(New-CisReference -Recommendation "18.4.3" -Level "L1" -WazuhWin2019CheckId "16649" -WazuhWin11EnterpriseCheckId "26172") `
            -SuggestedFix "Set the SMBv1 client driver start value to Disabled after confirming no legacy SMB dependency remains." `
            -AutoFixEligible $true `
            -RiskLevel "Medium" `
            -ExceptionGuidance "Document any legacy SMB endpoint, allowed network path, and retirement plan if SMBv1 client support is still required."
    }

    $insecureGuestAuth = Get-ObjectValue -InputObject $coreSettings -Name "InsecureGuestAuthPolicy"
    if (Test-EnabledValue -Value $insecureGuestAuth) {
        Add-Finding -Findings $findings `
            -Id "WIN-SMB-003" `
            -Severity "High" `
            -Area "Legacy protocols" `
            -Title "Insecure SMB guest logons are allowed" `
            -WhyItMatters "Guest SMB logons weaken authentication and can expose file-sharing paths without accountable user identity." `
            -Recommendation "Disable insecure guest logons unless a documented legacy exception exists." `
            -Evidence "AllowInsecureGuestAuth=$insecureGuestAuth" `
            -Standards @(New-CisReference -Recommendation "18.6.8.1" -Level "L1" -WazuhWin2019CheckId "16669" -WazuhWin11EnterpriseCheckId "26195") `
            -SuggestedFix "Set AllowInsecureGuestAuth to 0 or remove the policy so SMB guest logons are not allowed." `
            -AutoFixEligible $true `
            -RiskLevel "Low" `
            -ExceptionGuidance "Document any legacy NAS or application dependency and restrict access until it is removed."
    }

    $uacEnabled = Get-ObjectValue -InputObject $coreSettings -Name "UacEnabled"
    if ($uacEnabled -ne 1) {
        Add-Finding -Findings $findings `
            -Id "WIN-UAC-001" `
            -Severity "High" `
            -Area "Privilege control" `
            -Title "User Account Control is disabled" `
            -WhyItMatters "Disabling UAC weakens privilege boundaries and increases the impact of malware or user-session compromise." `
            -Recommendation "Enable UAC and validate administrative workflows." `
            -Evidence "EnableLUA=$uacEnabled" `
            -Standards @(New-CisReference -Recommendation "2.3.17.6" -Level "L1" -WazuhWin2019CheckId "16572" -WazuhWin11EnterpriseCheckId "26069") `
            -SuggestedFix "Set EnableLUA to 1 and reboot during a maintenance window if required." `
            -AutoFixEligible $true `
            -RiskLevel "Medium" `
            -ExceptionGuidance "Document any legacy application dependency that prevents UAC from being enabled."
    }

    $uacConsentPrompt = Get-ObjectValue -InputObject $coreSettings -Name "UacConsentPromptBehaviorAdmin"
    if ($null -eq $uacConsentPrompt -or "$uacConsentPrompt" -notin @("1", "2")) {
        Add-Finding -Findings $findings `
            -Id "WIN-UAC-002" `
            -Severity "Medium" `
            -Area "Privilege control" `
            -Title "Administrator elevation prompt is not set to a secure desktop prompt" `
            -WhyItMatters "Weak elevation prompts can make administrative actions less explicit and easier to spoof." `
            -Recommendation "Set administrator elevation behavior to a secure desktop credential or consent prompt and validate admin workflows." `
            -Evidence "ConsentPromptBehaviorAdmin=$uacConsentPrompt; expected 1 or 2 for CIS-aligned secure desktop prompting" `
            -Standards @(New-CisReference -Recommendation "2.3.17.2" -Level "L1" -WazuhWin2019CheckId "16568" -WazuhWin11EnterpriseCheckId "26065") `
            -SuggestedFix "Set ConsentPromptBehaviorAdmin to 2 for consent on the secure desktop, or 1 if credential prompt on secure desktop is the chosen baseline." `
            -AutoFixEligible $true `
            -RiskLevel "Low" `
            -ExceptionGuidance "Document any managed elevation workflow that requires a different UAC prompt behavior."
    }

    $uacPromptSecureDesktop = Get-ObjectValue -InputObject $coreSettings -Name "UacPromptOnSecureDesktop"
    if (-not (Test-DwordValueEquals -Value $uacPromptSecureDesktop -Expected 1)) {
        Add-Finding -Findings $findings `
            -Id "WIN-UAC-003" `
            -Severity "Medium" `
            -Area "Privilege control" `
            -Title "UAC secure desktop prompting is not enabled" `
            -WhyItMatters "Secure desktop prompting reduces spoofing and tampering opportunities during elevation." `
            -Recommendation "Enable secure desktop prompting for UAC elevation prompts." `
            -Evidence "PromptOnSecureDesktop=$uacPromptSecureDesktop; expected 1" `
            -Standards @(New-CisReference -Recommendation "2.3.17.7" -Level "L1" -WazuhWin2019CheckId "16573" -WazuhWin11EnterpriseCheckId "26070") `
            -SuggestedFix "Set PromptOnSecureDesktop to 1." `
            -AutoFixEligible $true `
            -RiskLevel "Low" `
            -ExceptionGuidance "Document any assistive technology or remote-support workflow that requires a different prompt behavior."
    }

    $llmnrPolicy = Get-ObjectValue -InputObject $coreSettings -Name "LlmnrEnabledPolicy"
    if ($llmnrPolicy -ne 0) {
        Add-Finding -Findings $findings `
            -Id "WIN-LLMNR-001" `
            -Severity "Medium" `
            -Area "Name resolution" `
            -Title "LLMNR disable policy is not enforced" `
            -WhyItMatters "LLMNR can support spoofing and credential capture attacks on local networks." `
            -Recommendation "Set EnableMulticast to 0 through policy if LLMNR is not required." `
            -Evidence "EnableMulticast=$llmnrPolicy" `
            -Standards @(New-CisReference -Recommendation "18.6.4.2 / 18.6.4.3" -Level "L1" -WazuhWin2019CheckId "16667" -WazuhWin11EnterpriseCheckId "26193") `
            -SuggestedFix "Set EnableMulticast to 0 through policy after confirming DNS or another approved name-resolution method is available." `
            -AutoFixEligible $true `
            -RiskLevel "Low" `
            -ExceptionGuidance "Document any legacy name-resolution dependency that requires LLMNR."
    }

    $defenderDisabledPolicy = Get-ObjectValue -InputObject $coreSettings -Name "DefenderDisableAntiSpywarePolicy"
    if (Test-EnabledValue -Value $defenderDisabledPolicy) {
        Add-Finding -Findings $findings `
            -Id "WIN-DEF-003" `
            -Severity "High" `
            -Area "Endpoint protection" `
            -Title "Microsoft Defender Antivirus is disabled by policy" `
            -WhyItMatters "A policy that turns off antivirus can remove a core malware prevention and detection layer." `
            -Recommendation "Set DisableAntiSpyware to 0 or remove the policy unless an approved EDR replacement owns this control." `
            -Evidence "DisableAntiSpyware=$defenderDisabledPolicy" `
            -Standards @(New-CisReference -Recommendation "18.10.43.17 / 18.10.42.17" -Level "L1" -WazuhWin2019CheckId "16799" -WazuhWin11EnterpriseCheckId "26403") `
            -SuggestedFix "Remove the Defender-disable policy or set DisableAntiSpyware to 0 unless a centrally managed EDR owns endpoint protection." `
            -AutoFixEligible $false `
            -RiskLevel "High" `
            -ExceptionGuidance "If ESET or another EDR owns this control, record the product, management policy, owner, and current healthy status."
    }

    $powerShellLogging = $Audit["PowerShellLogging"]
    $scriptBlockLogging = Get-ObjectValue -InputObject $powerShellLogging -Name "ScriptBlockLoggingEnabled"
    if (-not (Test-DwordValueEquals -Value $scriptBlockLogging -Expected 1)) {
        Add-Finding -Findings $findings `
            -Id "WIN-PS-001" `
            -Severity "Medium" `
            -Area "PowerShell logging" `
            -Title "PowerShell script block logging is not enabled by policy" `
            -WhyItMatters "Script block logging improves visibility into suspicious PowerShell execution during investigations." `
            -Recommendation "Enable PowerShell script block logging and send logs to a protected central collection path." `
            -Evidence "EnableScriptBlockLogging=$scriptBlockLogging; expected 1" `
            -OperationalNote "Review log retention and sensitive-data handling before broad rollout." `
            -Standards @(New-CisReference -Recommendation "18.10.87.1 / 18.10.86.1" -Level "L1/L2" -WazuhWin2019CheckId "16829" -WazuhWin11EnterpriseCheckId "26460") `
            -SuggestedFix "Enable PowerShell script block logging and forward the event log to protected central collection." `
            -AutoFixEligible $true `
            -RiskLevel "Low" `
            -ExceptionGuidance "Document the alternate PowerShell monitoring control if script block logging is intentionally disabled."
    }

    $transcription = Get-ObjectValue -InputObject $powerShellLogging -Name "TranscriptionEnabled"
    if (-not (Test-DwordValueEquals -Value $transcription -Expected 1)) {
        Add-Finding -Findings $findings `
            -Id "WIN-PS-002" `
            -Severity "Medium" `
            -Area "PowerShell logging" `
            -Title "PowerShell transcription is not enabled by policy" `
            -WhyItMatters "PowerShell transcripts can provide useful command history for incident review." `
            -Recommendation "Enable PowerShell transcription and protect the transcript output location." `
            -Evidence "EnableTranscripting=$transcription; expected 1" `
            -OperationalNote "Transcripts can contain sensitive data; restrict read access and centralize collection where possible." `
            -Standards @(New-CisReference -Recommendation "18.10.87.2 / 18.10.86.2" -Level "L1/L2" -WazuhWin2019CheckId "16830" -WazuhWin11EnterpriseCheckId "26461") `
            -SuggestedFix "Enable PowerShell transcription only after choosing a protected transcript path with restricted read access and retention rules." `
            -AutoFixEligible $false `
            -RiskLevel "Medium" `
            -ExceptionGuidance "Document the sensitive-data risk decision or alternate PowerShell command logging control if transcription is not enabled."
    }

    $winRmPolicy = $Audit["WinRmPolicy"]
    $winRmDisabledPolicies = @(
        @{ Id = "WIN-WINRM-002"; Name = "ClientAllowBasic"; Title = "WinRM client Basic authentication is allowed"; Recommendation = "Disable WinRM client Basic authentication."; EvidenceName = "Client AllowBasic"; Standard = @(New-CisReference -Recommendation "18.10.89.1.1 / 18.10.88.1.1" -Level "L1" -WazuhWin2019CheckId "16831" -WazuhWin11EnterpriseCheckId "26462"); SuggestedFix = "Set WinRM client AllowBasic to 0." },
        @{ Id = "WIN-WINRM-003"; Name = "ClientAllowUnencryptedTraffic"; Title = "WinRM client unencrypted traffic is allowed"; Recommendation = "Disable unencrypted WinRM client traffic."; EvidenceName = "Client AllowUnencryptedTraffic"; Standard = @(New-CisReference -Recommendation "18.10.89.1.2 / 18.10.88.1.2" -Level "L1" -WazuhWin2019CheckId "16832" -WazuhWin11EnterpriseCheckId "26463"); SuggestedFix = "Set WinRM client AllowUnencryptedTraffic to 0." },
        @{ Id = "WIN-WINRM-004"; Name = "ClientAllowDigest"; Title = "WinRM client Digest authentication is allowed"; Recommendation = "Disallow WinRM client Digest authentication."; EvidenceName = "Client AllowDigest"; Standard = @(New-CisReference -Recommendation "18.10.89.1.3 / 18.10.88.1.3" -Level "L1" -WazuhWin2019CheckId "16833" -WazuhWin11EnterpriseCheckId "26464"); SuggestedFix = "Set WinRM client AllowDigest to 0." },
        @{ Id = "WIN-WINRM-005"; Name = "ServiceAllowBasic"; Title = "WinRM service Basic authentication is allowed"; Recommendation = "Disable WinRM service Basic authentication."; EvidenceName = "Service AllowBasic"; Standard = @(New-CisReference -Recommendation "18.10.89.2.1 / 18.10.88.2.1" -Level "L1" -WazuhWin2019CheckId "16834" -WazuhWin11EnterpriseCheckId "26465"); SuggestedFix = "Set WinRM service AllowBasic to 0." },
        @{ Id = "WIN-WINRM-006"; Name = "ServiceAllowAutoConfig"; Title = "WinRM service automatic listener configuration is allowed"; Recommendation = "Disable automatic WinRM listener configuration unless remote management is explicitly required and restricted."; EvidenceName = "Service AllowAutoConfig"; Standard = @(New-CisReference -Recommendation "18.10.89.2.2 / 18.10.88.2.2" -Level "L2" -WazuhWin2019CheckId "16835" -WazuhWin11EnterpriseCheckId "26466"); SuggestedFix = "Set WinRM service AllowAutoConfig to 0 unless a managed remote administration baseline requires it."; RiskLevel = "Medium" },
        @{ Id = "WIN-WINRM-007"; Name = "ServiceAllowUnencryptedTraffic"; Title = "WinRM service unencrypted traffic is allowed"; Recommendation = "Disable unencrypted WinRM service traffic."; EvidenceName = "Service AllowUnencryptedTraffic"; Standard = @(New-CisReference -Recommendation "18.10.89.2.3 / 18.10.88.2.3" -Level "L1" -WazuhWin2019CheckId "16836" -WazuhWin11EnterpriseCheckId "26467"); SuggestedFix = "Set WinRM service AllowUnencryptedTraffic to 0." },
        @{ Id = "WIN-WINRM-009"; Name = "AllowRemoteShellAccess"; Title = "WinRM remote shell access is allowed"; Recommendation = "Disable remote shell access unless explicitly required and controlled."; EvidenceName = "WinRS AllowRemoteShellAccess"; Standard = @(New-CisReference -Recommendation "18.10.90.1 / 18.10.89.1" -Level "L2" -WazuhWin2019CheckId "16838" -WazuhWin11EnterpriseCheckId "26469"); SuggestedFix = "Set WinRS AllowRemoteShellAccess to 0 unless remote shell access is explicitly required."; RiskLevel = "Medium" }
    )

    foreach ($policy in $winRmDisabledPolicies) {
        $value = Get-ObjectValue -InputObject $winRmPolicy -Name $policy.Name
        if (Test-EnabledValue -Value $value) {
            Add-Finding -Findings $findings `
                -Id $policy.Id `
                -Severity "Medium" `
                -Area "Remote management" `
                -Title $policy.Title `
                -WhyItMatters "Weak WinRM authentication, encryption, or shell settings increase remote management exposure." `
                -Recommendation $policy.Recommendation `
                -Evidence "$($policy.EvidenceName)=$value" `
                -Standards @($policy.Standard) `
                -SuggestedFix $policy.SuggestedFix `
                -AutoFixEligible $true `
                -RiskLevel $(if ($policy.Contains("RiskLevel")) { $policy.RiskLevel } else { "Low" }) `
                -ExceptionGuidance "Document the remote management platform, allowed source networks, authentication method, and logging controls if this WinRM policy is intentionally different."
        }
    }

    $disableRunAs = Get-ObjectValue -InputObject $winRmPolicy -Name "ServiceDisableRunAs"
    if (-not (Test-DwordValueEquals -Value $disableRunAs -Expected 1)) {
        Add-Finding -Findings $findings `
            -Id "WIN-WINRM-008" `
            -Severity "Medium" `
            -Area "Remote management" `
            -Title "WinRM RunAs credential storage is not disallowed by policy" `
            -WhyItMatters "Stored RunAs credentials can increase account compromise impact if the host or a management plug-in is abused." `
            -Recommendation "Set WinRM service DisableRunAs to 1 unless a documented management exception requires otherwise." `
            -Evidence "Service DisableRunAs=$disableRunAs; expected 1" `
            -Standards @(New-CisReference -Recommendation "18.10.89.2.4 / 18.10.88.2.4" -Level "L1" -WazuhWin2019CheckId "16837" -WazuhWin11EnterpriseCheckId "26468") `
            -SuggestedFix "Set WinRM service DisableRunAs to 1." `
            -AutoFixEligible $true `
            -RiskLevel "Low" `
            -ExceptionGuidance "Document any management plug-in that explicitly requires RunAs credential storage and how those credentials are protected."
    }

    $highRiskPorts = @(135, 139, 445, 3389, 5985, 5986)
    $listening = @($Audit["ListeningTcpPorts"] | Where-Object {
            $port = Get-ObjectValue -InputObject $_ -Name "LocalPort"
            $address = Get-ObjectValue -InputObject $_ -Name "LocalAddress"
            $highRiskPorts -contains [int]$port -and $address -in @("0.0.0.0", "::")
        })
    if ($listening.Count -gt 0) {
        $evidence = @($listening | ForEach-Object {
                "$(Get-ObjectValue -InputObject $_ -Name "LocalAddress"):$(Get-ObjectValue -InputObject $_ -Name "LocalPort") $(Get-ObjectValue -InputObject $_ -Name "ProcessName")"
            }) -join "; "
        Add-Finding -Findings $findings `
            -Id "WIN-NET-001" `
            -Severity "Medium" `
            -Area "Network exposure" `
            -Title "High-value Windows management or file-sharing ports are listening broadly" `
            -WhyItMatters "Broadly listening management and file-sharing ports should be limited to trusted networks, especially on terminal servers." `
            -Recommendation "Confirm firewall rules restrict these ports to required management, domain, or application networks." `
            -Evidence $evidence `
            -SuggestedFix "Review firewall rules and bind/exposure for the listed ports; restrict SMB/RPC/RDP/WinRM access to trusted local, domain, VPN, or management networks." `
            -AutoFixEligible $false `
            -RequiresAdmin $true `
            -RiskLevel "Review" `
            -ExceptionGuidance "Document the host role, required services, allowed source networks, and compensating network controls for any broadly listening management or file-sharing ports."
    }

    foreach ($service in @($Audit["SecurityServices"])) {
        $name = Get-ObjectValue -InputObject $service -Name "Name"
        $status = Get-ObjectValue -InputObject $service -Name "Status"
        if ($name -in @("WinDefend", "MpsSvc", "EventLog") -and $status -ne "Running") {
            $serviceFix = if ($name -eq "WinDefend") {
                "Confirm whether an approved EDR replaces Defender. If not, start and enable the WinDefend service and Defender protections."
            }
            else {
                "Start the $name service and restore its expected startup configuration."
            }
            $serviceException = if ($name -eq "WinDefend") {
                "If ESET or another EDR owns endpoint protection, document the product, central policy owner, host assignment, and current healthy status."
            }
            else {
                "Document the approved replacement control if this Windows security service is intentionally stopped."
            }
            Add-Finding -Findings $findings `
                -Id "WIN-SVC-001" `
                -Severity "High" `
                -Area "Security services" `
                -Title "Critical Windows security service is not running" `
                -WhyItMatters "Stopped security services reduce protection, filtering, or logging coverage." `
                -Recommendation "Start the service or document the approved replacement control." `
                -Evidence "$name status=$status" `
                -SuggestedFix $serviceFix `
                -AutoFixEligible $false `
                -RequiresAdmin $true `
                -RiskLevel "High" `
                -ExceptionGuidance $serviceException
        }
    }

    return @($findings.ToArray())
}

function New-AuditSummary {
    param(
        [Parameter(Mandatory = $true)][object]$Audit,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Findings
    )

    $severityCounts = Get-CountBySeverity -Findings $Findings
    $reviewOrder = New-Object System.Collections.Generic.List[object]
    foreach ($finding in @($Findings)) {
        $severity = Get-ObjectValue -InputObject $finding -Name "Severity"
        if ($severity -in @("Critical", "High", "Medium")) {
            $reviewOrder.Add([ordered]@{
                Id             = Get-ObjectValue -InputObject $finding -Name "Id"
                Severity       = $severity
                Area           = Get-ObjectValue -InputObject $finding -Name "Area"
                Title          = Get-ObjectValue -InputObject $finding -Name "Title"
                Recommendation = Get-ObjectValue -InputObject $finding -Name "Recommendation"
                SuggestedFix   = Get-ObjectValue -InputObject $finding -Name "SuggestedFix"
                AutoFixEligible = Get-ObjectValue -InputObject $finding -Name "AutoFixEligible"
                RequiresAdmin  = Get-ObjectValue -InputObject $finding -Name "RequiresAdmin"
                RiskLevel      = Get-ObjectValue -InputObject $finding -Name "RiskLevel"
                ExceptionGuidance = Get-ObjectValue -InputObject $finding -Name "ExceptionGuidance"
                Standards      = @(Get-ObjectValue -InputObject $finding -Name "Standards")
            }) | Out-Null
        }
    }

    [ordered]@{
        Posture             = Get-PostureRating -SeverityCounts $severityCounts
        FindingCount        = $Findings.Count
        SeverityCounts      = $severityCounts
        RecommendedReviewOrder = @($reviewOrder.ToArray())
        Notes               = @(
            "Severity is a practical triage score for this script, not a formal compliance result.",
            "SuggestedFix describes the next remediation action; AutoFixEligible means the control is a candidate for a future hardening script, not that it was changed by this audit.",
            "Info findings can still matter on an RDP server; use them to verify exposure and intent.",
            "Raw evidence remains in the lower report sections for manual review."
        )
    }
}

$os = Invoke-Safe -ScriptBlock { Get-CimInstance -ClassName Win32_OperatingSystem } -Default $null
$computer = Invoke-Safe -ScriptBlock { Get-CimInstance -ClassName Win32_ComputerSystem } -Default $null

$audit = [ordered]@{
    ReportMetadata = [ordered]@{
        ComputerName      = $env:COMPUTERNAME
        GeneratedAtUtc    = (Get-Date).ToUniversalTime().ToString("o")
        User              = "$env:USERDOMAIN\$env:USERNAME"
        IsAdministrator   = Test-IsAdministrator
        ScriptName        = $MyInvocation.MyCommand.Name
    }
    OperatingSystem = [ordered]@{
        Caption          = if ($os) { $os.Caption } else { $null }
        Version          = if ($os) { $os.Version } else { $null }
        BuildNumber      = if ($os) { $os.BuildNumber } else { $null }
        InstallDate      = if ($os) { $os.InstallDate } else { $null }
        LastBootUpTime   = if ($os) { $os.LastBootUpTime } else { $null }
        Domain           = if ($computer) { $computer.Domain } else { $null }
        Manufacturer     = if ($computer) { $computer.Manufacturer } else { $null }
        Model            = if ($computer) { $computer.Model } else { $null }
    }
    FirewallProfiles = Invoke-Safe -ScriptBlock {
        Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, AllowInboundRules, NotifyOnListen, LogFileName, LogMaxSizeKilobytes, LogAllowed, LogBlocked
    } -Default @()
    Defender = Invoke-Safe -ScriptBlock {
        Get-MpComputerStatus | Select-Object AMServiceEnabled, AntispywareEnabled, AntivirusEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled, IoavProtectionEnabled, NISEnabled, AntivirusSignatureLastUpdated
    } -Default $null
    LocalAdministrators = @(Get-LocalAdministratorsSafe)
    LocalAccounts = [ordered]@{
        Guest = Invoke-Safe -ScriptBlock {
            Get-CimInstance -Query "SELECT Name,Disabled,SID,LocalAccount FROM Win32_UserAccount WHERE LocalAccount = TRUE AND SID LIKE 'S-1-5-21-%-501'" | Select-Object -First 1 Name, Disabled, SID, LocalAccount
        } -Default $null
    }
    PasswordPolicy = Get-PasswordPolicySafe
    AuditPolicy = @(Get-AuditPolicySafe)
    SecurityServices = @(Get-SecurityServiceState)
    ListeningTcpPorts = @(Get-ListeningPortsSafe)
    RemoteAccess = [ordered]@{
        RdpDenyConnections = Get-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections"
        RdpNlaRequired = Get-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication"
        WinRmService = Invoke-Safe -ScriptBlock { (Get-Service -Name WinRM).Status.ToString() } -Default "Unknown"
    }
    CoreSettings = [ordered]@{
        Smb1ServerEnabled = Invoke-Safe -ScriptBlock { (Get-SmbServerConfiguration).EnableSMB1Protocol } -Default $null
        Smb1ServerRegistry = Get-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1"
        Smb1ClientDriverStart = Get-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" -Name "Start"
        UacEnabled = Get-RegistryValueSafe -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA"
        UacConsentPromptBehaviorAdmin = Get-RegistryValueSafe -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin"
        UacPromptOnSecureDesktop = Get-RegistryValueSafe -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop"
        LlmnrEnabledPolicy = Get-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast"
        InsecureGuestAuthPolicy = Get-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" -Name "AllowInsecureGuestAuth"
        DefenderDisableAntiSpywarePolicy = Get-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware"
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    }
    PowerShellLogging = [ordered]@{
        ScriptBlockLoggingEnabled = Get-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging"
        TranscriptionEnabled = Get-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting"
    }
    WinRmPolicy = [ordered]@{
        ClientAllowBasic = Get-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowBasic"
        ClientAllowUnencryptedTraffic = Get-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowUnencryptedTraffic"
        ClientAllowDigest = Get-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowDigest"
        ServiceAllowBasic = Get-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowBasic"
        ServiceAllowAutoConfig = Get-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowAutoConfig"
        ServiceAllowUnencryptedTraffic = Get-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowUnencryptedTraffic"
        ServiceDisableRunAs = Get-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "DisableRunAs"
        AllowRemoteShellAccess = Get-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" -Name "AllowRemoteShellAccess"
    }
    BitLocker = Invoke-Safe -ScriptBlock {
        Get-BitLockerVolume -ErrorAction SilentlyContinue 2>$null | Select-Object MountPoint, VolumeStatus, ProtectionStatus, EncryptionPercentage, EncryptionMethod
    } -Default @()
}

if ($IncludeHotfixes) {
    $audit["Hotfixes"] = @(Invoke-Safe -ScriptBlock {
        Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 60 HotFixID, Description, InstalledBy, InstalledOn
    } -Default @())
}

$findings = @(Get-WindowsAuditFindings -Audit $audit)
$summary = New-AuditSummary -Audit $audit -Findings $findings

$auditWithSummary = [ordered]@{
    ReportMetadata = $audit["ReportMetadata"]
    Summary        = $summary
    Findings       = $findings
}

foreach ($key in $audit.Keys) {
    if ($key -ne "ReportMetadata") {
        $auditWithSummary[$key] = $audit[$key]
    }
}

$audit = $auditWithSummary

New-ParentDirectory -Path $OutputPath
$audit | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding utf8

if (-not $Quiet) {
    Write-Host "Windows security audit written to: $OutputPath"
    Write-Host "Computer: $env:COMPUTERNAME"
    Write-Host "Administrator: $(Test-IsAdministrator)"
    Write-Host "Posture: $($audit.Summary.Posture)"
    Write-Host "Findings: $($audit.Summary.FindingCount)"
    Write-Host "Listening TCP ports: $(@($audit.ListeningTcpPorts).Count)"
    Write-Host "Local administrators: $(@($audit.LocalAdministrators).Count)"
}
