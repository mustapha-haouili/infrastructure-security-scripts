<#
.SYNOPSIS
Applies a controlled Windows baseline hardening set.

.DESCRIPTION
The script is safe by default. Without -Apply it prints the planned actions
and writes a report, but does not change system configuration.

The baseline focuses on common enterprise controls that are usually safe for
servers and workstations. Review the code and test before production use.

.EXAMPLE
.\Set-WindowsBaselineHardening.ps1

.EXAMPLE
.\Set-WindowsBaselineHardening.ps1 -Apply
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Apply,
    [string]$ReportPath = ".\reports\windows-hardening-plan-$env:COMPUTERNAME-$(Get-Date -Format 'yyyyMMdd-HHmmss').json",
    [string]$BackupDirectory = ".\backups\windows-baseline-$env:COMPUTERNAME-$(Get-Date -Format 'yyyyMMdd-HHmmss')",
    [switch]$SkipDefender,
    [switch]$SkipAuditPolicy
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$Results = New-Object System.Collections.Generic.List[object]

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function New-ParentDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)

    $parent = Split-Path -Path $Path -Parent
    if ($parent -and -not (Test-Path -Path $parent)) {
        New-Item -Path $parent -ItemType Directory -Force | Out-Null
    }
}

function Add-Result {
    param(
        [string]$Control,
        [string]$Action,
        [string]$Status,
        [string]$Details
    )

    $Results.Add([ordered]@{
        Control = $Control
        Action = $Action
        Status = $Status
        Details = $Details
    }) | Out-Null
}

function Invoke-SafeChange {
    param(
        [string]$Control,
        [string]$Action,
        [scriptblock]$ScriptBlock
    )

    if (-not $Apply) {
        Add-Result -Control $Control -Action $Action -Status "DryRun" -Details "No change applied. Run with -Apply to enforce."
        return
    }

    try {
        if ($PSCmdlet.ShouldProcess($Control, $Action)) {
            & $ScriptBlock
            Add-Result -Control $Control -Action $Action -Status "Applied" -Details "Completed"
        }
        else {
            Add-Result -Control $Control -Action $Action -Status "Skipped" -Details "ShouldProcess declined"
        }
    }
    catch {
        Add-Result -Control $Control -Action $Action -Status "Failed" -Details $_.Exception.Message
    }
}

function Set-RegistryDword {
    param(
        [string]$Control,
        [string]$Path,
        [string]$Name,
        [int]$Value
    )

    Invoke-SafeChange -Control $Control -Action "Set $Path\$Name to $Value" -ScriptBlock {
        if (-not (Test-Path -Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
    }
}

function Backup-RegistryKey {
    param(
        [string]$Name,
        [string]$RegPath
    )

    if (-not $Apply) {
        return
    }

    if (-not (Test-Path -Path $BackupDirectory)) {
        New-Item -Path $BackupDirectory -ItemType Directory -Force | Out-Null
    }

    $target = Join-Path -Path $BackupDirectory -ChildPath "$Name.reg"
    & reg.exe export $RegPath $target /y | Out-Null
}

if ($Apply -and -not (Test-IsAdministrator)) {
    throw "Run PowerShell as Administrator when using -Apply."
}

if ($Apply) {
    New-Item -Path $BackupDirectory -ItemType Directory -Force | Out-Null
    Backup-RegistryKey -Name "system-policies" -RegPath "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    Backup-RegistryKey -Name "dnsclient-policy" -RegPath "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    Backup-RegistryKey -Name "terminal-server" -RegPath "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server"
}

Invoke-SafeChange -Control "Windows Firewall" -Action "Enable all firewall profiles" -ScriptBlock {
    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
}

Invoke-SafeChange -Control "SMBv1" -Action "Disable SMBv1 server protocol" -ScriptBlock {
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
}

Invoke-SafeChange -Control "SMBv1 Optional Feature" -Action "Disable SMB1Protocol feature if present" -ScriptBlock {
    $feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
    if ($feature -and $feature.State -ne "Disabled") {
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart | Out-Null
    }
}

Set-RegistryDword -Control "UAC" -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1
Set-RegistryDword -Control "UAC" -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 5
Set-RegistryDword -Control "UAC" -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 1
Set-RegistryDword -Control "LLMNR" -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0
Set-RegistryDword -Control "RDP Network Level Authentication" -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1

Invoke-SafeChange -Control "Guest Account" -Action "Disable local Guest account" -ScriptBlock {
    Disable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
}

if (-not $SkipDefender) {
    Invoke-SafeChange -Control "Microsoft Defender" -Action "Ensure real-time monitoring is enabled" -ScriptBlock {
        Set-MpPreference -DisableRealtimeMonitoring $false
        Set-MpPreference -DisableBehaviorMonitoring $false
        Set-MpPreference -DisableIOAVProtection $false
    }
}
else {
    Add-Result -Control "Microsoft Defender" -Action "Ensure real-time monitoring is enabled" -Status "Skipped" -Details "Skipped by parameter"
}

if (-not $SkipAuditPolicy) {
    $auditCommands = @(
        'auditpol /set /subcategory:"Logon" /success:enable /failure:enable',
        'auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable',
        'auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable',
        'auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable',
        'auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable',
        'auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable'
    )

    foreach ($command in $auditCommands) {
        Invoke-SafeChange -Control "Audit Policy" -Action $command -ScriptBlock {
            cmd.exe /c $command | Out-Null
        }
    }
}
else {
    Add-Result -Control "Audit Policy" -Action "Configure audit policy" -Status "Skipped" -Details "Skipped by parameter"
}

$report = [ordered]@{
    ComputerName = $env:COMPUTERNAME
    GeneratedAtUtc = (Get-Date).ToUniversalTime().ToString("o")
    Applied = [bool]$Apply
    BackupDirectory = if ($Apply) { $BackupDirectory } else { $null }
    Results = $Results
}

New-ParentDirectory -Path $ReportPath
$report | ConvertTo-Json -Depth 6 | Out-File -FilePath $ReportPath -Encoding utf8

Write-Host "Windows hardening report written to: $ReportPath"
if (-not $Apply) {
    Write-Host "Dry run complete. Run with -Apply to enforce the baseline."
}
