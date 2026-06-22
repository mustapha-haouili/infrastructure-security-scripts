<#
.SYNOPSIS
Audits local Remote Desktop exposure on a Windows host.

.DESCRIPTION
This script checks whether Remote Desktop is enabled, whether Network Level
Authentication is required, which port is configured, whether the service is
running, which local principals are allowed through the Remote Desktop Users
group, and whether local firewall rules appear to allow RDP.

It writes JSON, CSV, and Markdown reports and does not change system
configuration.

.PARAMETER OutputDirectory
Directory where windows-rdp-exposure.json, windows-rdp-exposure-findings.csv,
and windows-rdp-exposure-review.md are written.
Default: .\reports\windows-rdp-exposure-COMPUTER-TIMESTAMP

.PARAMETER Quiet
Suppress console summary.

.EXAMPLE
.\Get-WindowsRDPExposureAudit.ps1

Audit local RDP exposure and write reports.
#>

[CmdletBinding()]
param(
    [string]$OutputDirectory = ".\reports\windows-rdp-exposure-$env:COMPUTERNAME-$(Get-Date -Format 'yyyyMMdd-HHmmss')",
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

function Get-RemoteDesktopUsersGroup {
    $group = Invoke-Safe -ScriptBlock { Get-LocalGroup -SID "S-1-5-32-555" -ErrorAction Stop } -Default $null
    if ($group) {
        return $group
    }

    return Invoke-Safe -ScriptBlock { Get-LocalGroup -Name "Remote Desktop Users" -ErrorAction Stop } -Default $null
}

function Get-LocalGroupMembersSafe {
    param([AllowNull()][object]$Group)

    if (-not $Group) {
        return @()
    }

    Invoke-Safe -ScriptBlock {
        Get-LocalGroupMember -Group $Group.Name -ErrorAction Stop | ForEach-Object {
            [pscustomobject][ordered]@{
                Name              = "$($_.Name)"
                ObjectClass       = "$($_.ObjectClass)"
                PrincipalSource   = "$($_.PrincipalSource)"
                Sid               = "$($_.SID)"
            }
        }
    } -Default @()
}

function Get-ServiceStateSafe {
    param([Parameter(Mandatory = $true)][string]$Name)

    Invoke-Safe -ScriptBlock {
        $service = Get-Service -Name $Name -ErrorAction Stop
        $cim = Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'" -ErrorAction Stop
        [pscustomobject][ordered]@{
            Name        = $service.Name
            DisplayName = $service.DisplayName
            Status      = "$($service.Status)"
            StartMode   = "$($cim.StartMode)"
        }
    } -Default ([pscustomobject][ordered]@{
        Name        = $Name
        DisplayName = ""
        Status      = "Unknown"
        StartMode   = "Unknown"
    })
}

function Get-RdpFirewallRules {
    Invoke-Safe -ScriptBlock {
        Get-NetFirewallRule -ErrorAction Stop |
            Where-Object { $_.DisplayGroup -like "*Remote Desktop*" -or $_.DisplayName -like "*Remote Desktop*" } |
            ForEach-Object {
                [pscustomobject][ordered]@{
                    Name         = "$($_.Name)"
                    DisplayName  = "$($_.DisplayName)"
                    DisplayGroup = "$($_.DisplayGroup)"
                    Enabled      = "$($_.Enabled)"
                    Direction    = "$($_.Direction)"
                    Action       = "$($_.Action)"
                    Profile      = "$($_.Profile)"
                }
            }
    } -Default @()
}

function Get-RdpListeners {
    param([int]$Port)

    Invoke-Safe -ScriptBlock {
        Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction Stop |
            ForEach-Object {
                $owningProcess = $_.OwningProcess
                [pscustomobject][ordered]@{
                    LocalAddress  = "$($_.LocalAddress)"
                    LocalPort     = $_.LocalPort
                    OwningProcess = $owningProcess
                    ProcessName   = Invoke-Safe -ScriptBlock { (Get-Process -Id $owningProcess -ErrorAction Stop).ProcessName } -Default "unknown"
                }
            }
    } -Default @()
}

function New-RdpFinding {
    param(
        [Parameter(Mandatory = $true)][string]$FindingType,
        [Parameter(Mandatory = $true)][string]$Severity,
        [Parameter(Mandatory = $true)][string]$Title,
        [Parameter(Mandatory = $true)][string]$Evidence,
        [Parameter(Mandatory = $true)][string]$Recommendation
    )

    [pscustomobject][ordered]@{
        FindingType          = $FindingType
        Severity             = $Severity
        Title                = $Title
        Evidence             = $Evidence
        Recommendation       = $Recommendation
        RequiresOwnerReview  = $true
        SafeToAutoRemediate  = $false
    }
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
    Add-MarkdownLine -Lines $lines -Text "# Windows RDP Exposure Audit"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "Generated at UTC: ``$($Report.GeneratedAtUtc)``"
    Add-MarkdownLine -Lines $lines -Text "Computer: ``$($Report.ComputerName)``"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "## Summary"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "- RDP enabled: $($Report.Summary.RdpEnabled)"
    Add-MarkdownLine -Lines $lines -Text "- NLA required: $($Report.Summary.NetworkLevelAuthenticationRequired)"
    Add-MarkdownLine -Lines $lines -Text "- RDP port: $($Report.Summary.RdpPort)"
    Add-MarkdownLine -Lines $lines -Text "- Listener count: $($Report.Summary.ListenerCount)"
    Add-MarkdownLine -Lines $lines -Text "- Finding count: $($Report.Summary.FindingCount)"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "## Findings"
    Add-MarkdownLine -Lines $lines
    if ($Report.Findings.Count -eq 0) {
        Add-MarkdownLine -Lines $lines -Text "- None identified."
    }
    else {
        Add-MarkdownLine -Lines $lines -Text "| Severity | Finding | Evidence | Recommendation |"
        Add-MarkdownLine -Lines $lines -Text "|---|---|---|---|"
        foreach ($finding in $Report.Findings) {
            Add-MarkdownLine -Lines $lines -Text "| $(Escape-MarkdownCell $finding.Severity) | $(Escape-MarkdownCell $finding.Title) | $(Escape-MarkdownCell $finding.Evidence) | $(Escape-MarkdownCell $finding.Recommendation) |"
        }
    }
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "## Allowed Remote Desktop Users"
    Add-MarkdownLine -Lines $lines
    if ($Report.RemoteDesktopUsers.Count -eq 0) {
        Add-MarkdownLine -Lines $lines -Text "- No direct members found or membership could not be read."
    }
    else {
        foreach ($member in $Report.RemoteDesktopUsers) {
            Add-MarkdownLine -Lines $lines -Text "- ``$($member.Name)`` ($($member.ObjectClass), $($member.PrincipalSource))"
        }
    }
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "## Safety Notes"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "- This script does not enable, disable, or reconfigure RDP."
    Add-MarkdownLine -Lines $lines -Text "- RDP changes can break administration paths and require explicit change approval."

    $lines | Out-File -FilePath $Path -Encoding utf8
}

New-Directory -Path $OutputDirectory
$resolvedOutputDirectory = (Resolve-Path -Path $OutputDirectory).Path
$jsonPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "windows-rdp-exposure.json"
$csvPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "windows-rdp-exposure-findings.csv"
$markdownPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "windows-rdp-exposure-review.md"
$generatedAtUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$findings = New-Object System.Collections.Generic.List[object]

$terminalServerPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
$rdpTcpPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
$fDeny = Get-RegistryValueSafe -Path $terminalServerPath -Name "fDenyTSConnections"
$nla = Get-RegistryValueSafe -Path $rdpTcpPath -Name "UserAuthentication"
$portNumber = Get-RegistryValueSafe -Path $rdpTcpPath -Name "PortNumber"
if ($null -eq $portNumber) {
    $portNumber = 3389
}
$rdpEnabled = ($fDeny -eq 0)
$nlaRequired = ($nla -eq 1)
$termService = Get-ServiceStateSafe -Name "TermService"
$rdpGroup = Get-RemoteDesktopUsersGroup
$rdpMembers = @(Get-LocalGroupMembersSafe -Group $rdpGroup)
$firewallRules = @(Get-RdpFirewallRules)
$enabledAllowRules = @($firewallRules | Where-Object { $_.Enabled -eq "True" -and $_.Action -eq "Allow" -and $_.Direction -eq "Inbound" })
$listeners = @(Get-RdpListeners -Port ([int]$portNumber))

if ($rdpEnabled) {
    $findings.Add((New-RdpFinding -FindingType "RdpEnabled" -Severity "Medium" -Title "Remote Desktop is enabled" -Evidence "fDenyTSConnections=$fDeny; TermService=$($termService.Status); Port=$portNumber." -Recommendation "Confirm RDP is business-required and restricted to approved management networks.")) | Out-Null
}
if ($rdpEnabled -and -not $nlaRequired) {
    $findings.Add((New-RdpFinding -FindingType "RdpNlaDisabled" -Severity "High" -Title "RDP Network Level Authentication is not required" -Evidence "UserAuthentication=$nla." -Recommendation "Require NLA unless a documented legacy client exception exists.")) | Out-Null
}
if ($rdpMembers.Count -gt 0) {
    $findings.Add((New-RdpFinding -FindingType "RdpAllowedUsersPresent" -Severity "Medium" -Title "Remote Desktop Users group has direct members" -Evidence "$($rdpMembers.Count) direct member(s) are present." -Recommendation "Review each member and prefer approved groups with controlled membership.")) | Out-Null
}
if ($enabledAllowRules.Count -gt 0 -and $rdpEnabled) {
    $findings.Add((New-RdpFinding -FindingType "RdpFirewallAllowsInbound" -Severity "Medium" -Title "Firewall has enabled inbound Remote Desktop allow rules" -Evidence "$($enabledAllowRules.Count) enabled allow rule(s) were found." -Recommendation "Restrict RDP firewall exposure to trusted management networks and confirm profile scope.")) | Out-Null
}
if ($listeners.Count -gt 0) {
    $findings.Add((New-RdpFinding -FindingType "RdpListening" -Severity "High" -Title "RDP listener is active" -Evidence "TCP port $portNumber has $($listeners.Count) listening endpoint(s)." -Recommendation "Confirm exposure is intended and externally restricted by host and network firewalls.")) | Out-Null
}

$severityCounts = [ordered]@{
    Critical = @($findings | Where-Object { $_.Severity -eq "Critical" }).Count
    High     = @($findings | Where-Object { $_.Severity -eq "High" }).Count
    Medium   = @($findings | Where-Object { $_.Severity -eq "Medium" }).Count
    Low      = @($findings | Where-Object { $_.Severity -eq "Low" }).Count
    Info     = @($findings | Where-Object { $_.Severity -eq "Info" }).Count
}

$report = [pscustomobject][ordered]@{
    ToolName        = "Get-WindowsRDPExposureAudit"
    ReportType      = "windows-rdp-exposure"
    GeneratedAtUtc  = $generatedAtUtc
    ComputerName    = $env:COMPUTERNAME
    Summary         = [ordered]@{
        RdpEnabled                         = [bool]$rdpEnabled
        NetworkLevelAuthenticationRequired = [bool]$nlaRequired
        RdpPort                            = [int]$portNumber
        TermServiceStatus                  = $termService.Status
        TermServiceStartMode               = $termService.StartMode
        RemoteDesktopUserCount             = $rdpMembers.Count
        EnabledInboundAllowRuleCount       = $enabledAllowRules.Count
        ListenerCount                      = $listeners.Count
        FindingCount                       = $findings.Count
        SeverityCounts                     = $severityCounts
    }
    Registry        = [ordered]@{
        fDenyTSConnections = $fDeny
        UserAuthentication = $nla
        PortNumber         = $portNumber
    }
    TermService     = $termService
    RemoteDesktopUsers = @($rdpMembers)
    FirewallRules   = @($firewallRules)
    Listeners       = @($listeners)
    Findings        = @($findings.ToArray())
    Notes           = @(
        "This report is audit-only and does not change Remote Desktop configuration.",
        "Remote access changes require owner review and approved change control."
    )
}

$report | ConvertTo-Json -Depth 8 | Out-File -FilePath $jsonPath -Encoding utf8
Write-CsvReport -Path $csvPath -Rows @($findings.ToArray())
Write-MarkdownReport -Path $markdownPath -Report $report

if (-not $Quiet) {
    Write-Host "Windows RDP exposure report written to: $jsonPath"
    Write-Host "RDP enabled: $rdpEnabled"
    Write-Host "Findings: $($findings.Count)"
}
