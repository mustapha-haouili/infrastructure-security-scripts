<#
.SYNOPSIS
Main menu launcher for Windows security scripts.

.DESCRIPTION
This script is the single interactive entry point for Windows scripts in this
repository. It shows category menus, lets an admin choose one script or run the
default-safe scripts in a category, prompts for supported parameters, previews
the command, and then starts the selected script.

Implementation scripts remain in their category folders such as ad, gpo, host,
server, and workstation. This launcher does not change system configuration by
itself. Any child script that can apply changes still requires its own explicit
parameter, such as -Apply or -ApplyApproved.

.PARAMETER ListScripts
Print all scripts known to the menu and exit.

.PARAMETER Group
Open a specific group menu by group ID, such as AD, Host, Server, or Workstation.

.PARAMETER ToolId
Run a specific menu tool by ID, such as AD-INACTIVE-USERS or HOST-AUDIT.

.PARAMETER RunAll
With -Group, run the default-safe scripts in that group.

.PARAMETER UseDefaults
Use default child-script parameters instead of prompting. Required parameters
are still prompted.

.PARAMETER ConfigPath
Optional JSON parameter file. Values in the file are used as defaults for child
script parameters. Tool values override group values, and group values override
global defaults.

.EXAMPLE
.\Start-WindowsSecurity.ps1

Open the interactive Windows security menu.

.EXAMPLE
.\Start-WindowsSecurity.ps1 -ListScripts

List every tool available from the menu.

.EXAMPLE
.\Start-WindowsSecurity.ps1 -ToolId AD-GPO-HEALTH

Open parameter prompts for the GPO health report and run it.

.EXAMPLE
.\Start-WindowsSecurity.ps1 -Group AD -RunAll

Run the default-safe AD and GPO reports.

.EXAMPLE
.\Start-WindowsSecurity.ps1 -Group AD -RunAll -UseDefaults -ConfigPath .\examples\windows-security.config.example.json

Run the default-safe AD and GPO reports using shared values from a JSON
parameter file.
#>

[CmdletBinding()]
param(
    [switch]$ListScripts,
    [string]$Group = "",
    [string]$ToolId = "",
    [switch]$RunAll,
    [switch]$UseDefaults,
    [string]$ConfigPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$script:QuitRequested = $false

function New-ParameterDefinition {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [ValidateSet("String", "Int", "Switch", "StringArray", "Credential")]
        [string]$Type = "String",
        [string]$Description = "",
        [AllowNull()][object]$Default = $null,
        [switch]$Required,
        [switch]$HighImpact
    )

    [pscustomobject][ordered]@{
        Name        = $Name
        Type        = $Type
        Description = $Description
        Default     = $Default
        Required    = [bool]$Required
        HighImpact  = [bool]$HighImpact
    }
}

function New-ToolDefinition {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$GroupId,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$RelativePath,
        [Parameter(Mandatory = $true)][string]$DefaultMode,
        [string]$Description = "",
        [bool]$IncludeInRunAll = $true,
        [object[]]$Parameters = @()
    )

    [pscustomobject][ordered]@{
        Id              = $Id
        GroupId         = $GroupId
        Name            = $Name
        RelativePath    = $RelativePath
        DefaultMode     = $DefaultMode
        Description     = $Description
        IncludeInRunAll = $IncludeInRunAll
        Parameters      = @($Parameters)
    }
}

function Get-GroupCatalog {
    @(
        [pscustomobject][ordered]@{
            Id          = "AD"
            Label       = "AD and GPO"
            Description = "Active Directory identity and Group Policy reports"
        }
        [pscustomobject][ordered]@{
            Id          = "Host"
            Label       = "Windows Host"
            Description = "Local Windows audit, events, remediation, and hardening"
        }
        [pscustomobject][ordered]@{
            Id          = "Server"
            Label       = "Windows Server"
            Description = "Server-focused operational and exposure checks"
        }
        [pscustomobject][ordered]@{
            Id          = "Workstation"
            Label       = "Windows Workstation"
            Description = "Workstation endpoint posture checks"
        }
    )
}

function Get-ToolCatalog {
    @(
        New-ToolDefinition -Id "AD-INACTIVE-USERS" -GroupId "AD" -Name "Inactive AD users" -RelativePath "ad\Get-ADInactiveUserReport.ps1" -DefaultMode "Audit" -Description "Report inactive Active Directory users with priority and deletion-readiness guidance." -Parameters @(
            New-ParameterDefinition -Name "DaysInactive" -Type "Int" -Default 90 -Description "Days since last logon before a user is reported."
            New-ParameterDefinition -Name "SearchBase" -Description "Optional OU or domain distinguished name to search."
            New-ParameterDefinition -Name "Server" -Description "Optional domain controller to query."
            New-ParameterDefinition -Name "Credential" -Type "Credential" -Description "Optional alternate AD credential."
            New-ParameterDefinition -Name "IncludeDisabled" -Type "Switch" -Description "Include disabled accounts."
            New-ParameterDefinition -Name "ExcludeNeverLoggedOn" -Type "Switch" -Description "Exclude accounts that never logged on."
            New-ParameterDefinition -Name "OutputDirectory" -Description "Optional output directory. Blank uses the script default."
            New-ParameterDefinition -Name "Quiet" -Type "Switch" -Description "Suppress console summary."
        )

        New-ToolDefinition -Id "AD-STALE-COMPUTERS" -GroupId "AD" -Name "Stale AD computers" -RelativePath "ad\Get-ADStaleComputerReport.ps1" -DefaultMode "Audit" -Description "Report stale Active Directory computer accounts with priority and cleanup-readiness guidance." -Parameters @(
            New-ParameterDefinition -Name "DaysInactive" -Type "Int" -Default 90 -Description "Days since last logon before a computer is reported."
            New-ParameterDefinition -Name "SearchBase" -Description "Optional OU or domain distinguished name to search."
            New-ParameterDefinition -Name "Server" -Description "Optional domain controller to query."
            New-ParameterDefinition -Name "Credential" -Type "Credential" -Description "Optional alternate AD credential."
            New-ParameterDefinition -Name "IncludeDisabled" -Type "Switch" -Description "Include disabled computer accounts."
            New-ParameterDefinition -Name "ExcludeNeverLoggedOn" -Type "Switch" -Description "Exclude computers that never logged on."
            New-ParameterDefinition -Name "OutputDirectory" -Description "Optional output directory. Blank uses the script default."
            New-ParameterDefinition -Name "Quiet" -Type "Switch" -Description "Suppress console summary."
        )

        New-ToolDefinition -Id "AD-PRIVILEGED-GROUPS" -GroupId "AD" -Name "Privileged AD group changes" -RelativePath "ad\Watch-ADPrivilegedGroupChanges.ps1" -DefaultMode "Audit" -Description "Compare Domain Admins and other privileged AD groups against a saved membership baseline." -Parameters @(
            New-ParameterDefinition -Name "BaselinePath" -Description "Stable JSON baseline path. Blank uses the script default."
            New-ParameterDefinition -Name "OutputDirectory" -Description "Optional output directory. Blank uses the script default."
            New-ParameterDefinition -Name "GroupName" -Type "StringArray" -Description "Optional extra group identities to audit."
            New-ParameterDefinition -Name "Server" -Description "Optional domain controller to query."
            New-ParameterDefinition -Name "Credential" -Type "Credential" -Description "Optional alternate AD credential."
            New-ParameterDefinition -Name "IncludeRecursiveMembers" -Type "Switch" -Description "Also collect recursive/effective members for visibility."
            New-ParameterDefinition -Name "UpdateBaseline" -Type "Switch" -HighImpact -Description "Replace the baseline with the current snapshot after review."
            New-ParameterDefinition -Name "Quiet" -Type "Switch" -Description "Suppress console summary."
        )

        New-ToolDefinition -Id "AD-SERVICE-ACCOUNTS" -GroupId "AD" -Name "Service account audit" -RelativePath "ad\Get-ADServiceAccountAudit.ps1" -DefaultMode "Audit" -Description "Audit user and managed service accounts for owner, password, SPN, delegation, and privilege risk." -Parameters @(
            New-ParameterDefinition -Name "SearchBase" -Description "Optional OU or domain distinguished name to search."
            New-ParameterDefinition -Name "Server" -Description "Optional domain controller to query."
            New-ParameterDefinition -Name "Credential" -Type "Credential" -Description "Optional alternate AD credential."
            New-ParameterDefinition -Name "IncludeDisabled" -Type "Switch" -Description "Include disabled user accounts."
            New-ParameterDefinition -Name "StaleDays" -Type "Int" -Default 90 -Description "Days since last logon before an enabled service account is considered stale."
            New-ParameterDefinition -Name "MaxPasswordAgeDays" -Type "Int" -Default 180 -Description "Password age threshold used for review."
            New-ParameterDefinition -Name "OutputDirectory" -Description "Optional output directory. Blank uses the script default."
            New-ParameterDefinition -Name "Quiet" -Type "Switch" -Description "Suppress console summary."
        )

        New-ToolDefinition -Id "AD-SPN-EXPOSURE" -GroupId "AD" -Name "SPN exposure audit" -RelativePath "ad\Get-ADSPNExposureAudit.ps1" -DefaultMode "Audit" -Description "Audit SPN-bearing user accounts for Kerberos exposure indicators without offensive actions." -Parameters @(
            New-ParameterDefinition -Name "SearchBase" -Description "Optional OU or domain distinguished name to search."
            New-ParameterDefinition -Name "Server" -Description "Optional domain controller to query."
            New-ParameterDefinition -Name "Credential" -Type "Credential" -Description "Optional alternate AD credential."
            New-ParameterDefinition -Name "IncludeDisabled" -Type "Switch" -Description "Include disabled SPN-bearing accounts."
            New-ParameterDefinition -Name "MaxPasswordAgeDays" -Type "Int" -Default 180 -Description "Password age threshold used for exposure review."
            New-ParameterDefinition -Name "OutputDirectory" -Description "Optional output directory. Blank uses the script default."
            New-ParameterDefinition -Name "Quiet" -Type "Switch" -Description "Suppress console summary."
        )

        New-ToolDefinition -Id "AD-PASSWORD-NEVER-EXPIRES" -GroupId "AD" -Name "PasswordNeverExpires report" -RelativePath "ad\Get-ADPasswordNeverExpiresReport.ps1" -DefaultMode "Audit" -Description "Report accounts with PasswordNeverExpires and classify exception, service, SPN, and privilege risk." -Parameters @(
            New-ParameterDefinition -Name "SearchBase" -Description "Optional OU or domain distinguished name to search."
            New-ParameterDefinition -Name "Server" -Description "Optional domain controller to query."
            New-ParameterDefinition -Name "Credential" -Type "Credential" -Description "Optional alternate AD credential."
            New-ParameterDefinition -Name "IncludeDisabled" -Type "Switch" -Description "Include disabled accounts."
            New-ParameterDefinition -Name "MaxPasswordAgeDays" -Type "Int" -Default 180 -Description "Password age threshold used for review."
            New-ParameterDefinition -Name "OutputDirectory" -Description "Optional output directory. Blank uses the script default."
            New-ParameterDefinition -Name "Quiet" -Type "Switch" -Description "Suppress console summary."
        )

        New-ToolDefinition -Id "AD-PRIVILEGED-IDENTITY-PROTECTION" -GroupId "AD" -Name "Privileged identity protection" -RelativePath "ad\Get-PrivilegedIdentityProtectionAudit.ps1" -DefaultMode "Audit" -Description "Audit on-prem privileged AD users for protection gaps; MFA and Conditional Access are not checked in this version." -Parameters @(
            New-ParameterDefinition -Name "GroupName" -Type "StringArray" -Description "Optional extra privileged group identities to audit."
            New-ParameterDefinition -Name "Server" -Description "Optional domain controller to query."
            New-ParameterDefinition -Name "Credential" -Type "Credential" -Description "Optional alternate AD credential."
            New-ParameterDefinition -Name "StaleDays" -Type "Int" -Default 90 -Description "Days since last logon before an enabled privileged identity is considered stale."
            New-ParameterDefinition -Name "MaxPasswordAgeDays" -Type "Int" -Default 180 -Description "Password age threshold used for privileged account review."
            New-ParameterDefinition -Name "OutputDirectory" -Description "Optional output directory. Blank uses the script default."
            New-ParameterDefinition -Name "Quiet" -Type "Switch" -Description "Suppress console summary."
        )

        New-ToolDefinition -Id "AD-GPO-HEALTH" -GroupId "AD" -Name "GPO health report" -RelativePath "gpo\Get-ADGPOHealthReport.ps1" -DefaultMode "Audit" -Description "Audit Group Policy inventory, links, stale policies, filters, version mismatches, and common health risks." -Parameters @(
            New-ParameterDefinition -Name "OutputDirectory" -Description "Optional output directory. Blank uses the script default."
            New-ParameterDefinition -Name "Domain" -Description "Optional DNS domain name to query."
            New-ParameterDefinition -Name "Server" -Description "Optional domain controller to query."
            New-ParameterDefinition -Name "StaleDays" -Type "Int" -Default 365 -Description "Days since last modification before a GPO is considered stale."
            New-ParameterDefinition -Name "MaxGposPerTarget" -Type "Int" -Default 10 -Description "Direct GPO links on one target before a review finding is created."
            New-ParameterDefinition -Name "LegacyKeyword" -Type "StringArray" -Description "Optional comma-separated legacy keywords. Blank uses the script default."
            New-ParameterDefinition -Name "SkipTargetInventory" -Type "Switch" -Description "Skip OU/domain inheritance inventory."
            New-ParameterDefinition -Name "Quiet" -Type "Switch" -Description "Suppress console summary."
        )

        New-ToolDefinition -Id "HOST-AUDIT" -GroupId "Host" -Name "Windows security audit" -RelativePath "host\Invoke-WindowsSecurityAudit.ps1" -DefaultMode "Audit" -Description "Collect local Windows security posture evidence and write JSON." -Parameters @(
            New-ParameterDefinition -Name "OutputPath" -Description "Optional JSON report path. Blank uses the script default."
            New-ParameterDefinition -Name "IncludeHotfixes" -Type "Switch" -Description "Include installed hotfix evidence."
            New-ParameterDefinition -Name "Quiet" -Type "Switch" -Description "Suppress console summary."
        )

        New-ToolDefinition -Id "HOST-EVENTS" -GroupId "Host" -Name "Windows event security report" -RelativePath "host\Export-WindowsEventSecurityReport.ps1" -DefaultMode "Audit" -Description "Export selected Security and System event activity to CSV, JSON, and text." -Parameters @(
            New-ParameterDefinition -Name "Days" -Type "Int" -Default 7 -Description "Number of days of event history to review."
            New-ParameterDefinition -Name "OutputDirectory" -Description "Optional output directory. Blank uses the script default."
        )

        New-ToolDefinition -Id "HOST-HARDENING" -GroupId "Host" -Name "Windows baseline hardening preview" -RelativePath "host\Set-WindowsBaselineHardening.ps1" -DefaultMode "Dry run" -Description "Preview or apply selected Windows baseline hardening controls." -Parameters @(
            New-ParameterDefinition -Name "Apply" -Type "Switch" -HighImpact -Description "Apply selected controls. Leave off for dry-run preview."
            New-ParameterDefinition -Name "ReportPath" -Description "Optional JSON hardening report path. Blank uses the script default."
            New-ParameterDefinition -Name "BackupDirectory" -Description "Optional backup directory used with -Apply."
            New-ParameterDefinition -Name "PlanPath" -Description "Optional remediation plan path."
            New-ParameterDefinition -Name "SkipDefender" -Type "Switch" -Description "Skip Defender controls."
            New-ParameterDefinition -Name "SkipAuditPolicy" -Type "Switch" -Description "Skip audit policy controls."
            New-ParameterDefinition -Name "ExcludeControlId" -Type "StringArray" -Description "Comma-separated control IDs to exclude."
            New-ParameterDefinition -Name "OnlyControlId" -Type "StringArray" -Description "Comma-separated control IDs to run."
            New-ParameterDefinition -Name "ListControls" -Type "Switch" -Description "List controls and exit."
        )

        New-ToolDefinition -Id "HOST-REMEDIATION-PLAN" -GroupId "Host" -Name "Create remediation plan" -RelativePath "host\New-WindowsRemediationPlan.ps1" -DefaultMode "Audit" -Description "Create a remediation plan from a Windows security audit report." -IncludeInRunAll $false -Parameters @(
            New-ParameterDefinition -Name "AuditReportPath" -Required -Description "Path to a JSON report from Invoke-WindowsSecurityAudit.ps1."
            New-ParameterDefinition -Name "OutputPath" -Description "Optional JSON remediation plan path."
            New-ParameterDefinition -Name "IncludeMarkdown" -Type "Switch" -Description "Write a Markdown review copy."
            New-ParameterDefinition -Name "MarkdownPath" -Description "Optional Markdown output path."
            New-ParameterDefinition -Name "IncludeCsv" -Type "Switch" -Description "Write a CSV review copy."
            New-ParameterDefinition -Name "CsvPath" -Description "Optional CSV output path."
            New-ParameterDefinition -Name "Quiet" -Type "Switch" -Description "Suppress console summary."
        )

        New-ToolDefinition -Id "HOST-GUIDED-REMEDIATION" -GroupId "Host" -Name "Guided audit and remediation workflow" -RelativePath "host\Start-WindowsSecurityRemediation.ps1" -DefaultMode "Dry run until final approval" -Description "Run the guided admin workflow for audit, plan, decisions, preview, and optional apply." -IncludeInRunAll $false -Parameters @(
            New-ParameterDefinition -Name "AuditReportPath" -Description "Optional existing audit report path."
            New-ParameterDefinition -Name "PlanPath" -Description "Optional existing remediation plan path."
            New-ParameterDefinition -Name "OutputDirectory" -Description "Optional output directory. Blank uses the script default."
            New-ParameterDefinition -Name "IncludeHotfixes" -Type "Switch" -Description "Include hotfix records in a new audit."
            New-ParameterDefinition -Name "ApplyApproved" -Type "Switch" -HighImpact -Description "Allow final apply confirmation after dry-run preview."
            New-ParameterDefinition -Name "ReviewDecisions" -Type "Switch" -Description "Review decisions from an existing plan."
            New-ParameterDefinition -Name "NonInteractive" -Type "Switch" -Description "Run without prompts and mark findings skipped."
            New-ParameterDefinition -Name "Quiet" -Type "Switch" -Description "Reduce console output."
        )

        New-ToolDefinition -Id "SERVER-RDP-CACHE" -GroupId "Server" -Name "RDP profile cache cleanup report" -RelativePath "server\Clear-RDPUserProfileCache.ps1" -DefaultMode "Dry run" -Description "Audit and optionally clean safe per-user cache locations on RDP/Terminal Server hosts." -Parameters @(
            New-ParameterDefinition -Name "ProfileRoot" -Default "C:\Users" -Description "Root directory containing user profile folders."
            New-ParameterDefinition -Name "MinimumAgeDays" -Type "Int" -Default 14 -Description "Only report or delete files older than this many days."
            New-ParameterDefinition -Name "ReportPath" -Description "Optional JSON report path. Blank uses the script default."
            New-ParameterDefinition -Name "Apply" -Type "Switch" -HighImpact -Description "Delete eligible files. Leave off for dry-run preview."
            New-ParameterDefinition -Name "IncludeLoadedProfiles" -Type "Switch" -HighImpact -Description "Include currently loaded profiles."
            New-ParameterDefinition -Name "IncludeRecycleBin" -Type "Switch" -Description "Include each user's Recycle Bin when available."
            New-ParameterDefinition -Name "IncludeTemp" -Type "Switch" -Description "Include per-user AppData\Local\Temp."
            New-ParameterDefinition -Name "ExcludeProfileName" -Type "StringArray" -Description "Comma-separated profile folder names to skip."
        )
    )
}

function Get-ToolPath {
    param([Parameter(Mandatory = $true)][object]$Tool)
    Join-Path -Path $PSScriptRoot -ChildPath $Tool.RelativePath
}

function Read-WindowsSecurityConfig {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $null
    }

    try {
        $resolvedPath = (Resolve-Path -LiteralPath $Path -ErrorAction Stop | Select-Object -First 1).ProviderPath
    }
    catch {
        throw "ConfigPath not found: $Path"
    }

    try {
        $content = Get-Content -LiteralPath $resolvedPath -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($content)) {
            throw "The config file is empty."
        }
        $data = $content | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Failed to read ConfigPath '$resolvedPath': $($_.Exception.Message)"
    }

    [pscustomobject][ordered]@{
        SourcePath = $resolvedPath
        Data       = $data
    }
}

function Get-ConfigPropertyValue {
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($null -eq $InputObject) {
        return [pscustomobject]@{ Found = $false; Value = $null }
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($key in $InputObject.Keys) {
            if ("$key" -ieq $Name) {
                return [pscustomobject]@{ Found = $true; Value = $InputObject[$key] }
            }
        }
    }

    foreach ($property in @($InputObject.PSObject.Properties)) {
        if ($property.Name -ieq $Name) {
            return [pscustomobject]@{ Found = $true; Value = $property.Value }
        }
    }

    [pscustomobject]@{ Found = $false; Value = $null }
}

function Get-ConfigSection {
    param(
        [AllowNull()][object]$Config,
        [Parameter(Mandatory = $true)][string[]]$Path
    )

    if ($null -eq $Config) {
        return $null
    }

    $current = $Config.Data
    foreach ($segment in $Path) {
        $result = Get-ConfigPropertyValue -InputObject $current -Name $segment
        if (-not $result.Found) {
            return $null
        }
        $current = $result.Value
    }

    return $current
}

function Get-ConfiguredParameterValue {
    param(
        [Parameter(Mandatory = $true)][object]$Tool,
        [Parameter(Mandatory = $true)][object]$Parameter,
        [AllowNull()][object]$Config
    )

    $configured = [pscustomobject][ordered]@{
        HasValue = $false
        Value    = $null
        Source   = ""
    }

    if ($null -eq $Config) {
        return $configured
    }

    $sections = @(
        [pscustomobject]@{ Name = "Defaults"; Object = (Get-ConfigSection -Config $Config -Path @("Defaults")) }
        [pscustomobject]@{ Name = "Groups.$($Tool.GroupId)"; Object = (Get-ConfigSection -Config $Config -Path @("Groups", $Tool.GroupId)) }
        [pscustomobject]@{ Name = "Tools.$($Tool.Id)"; Object = (Get-ConfigSection -Config $Config -Path @("Tools", $Tool.Id)) }
    )

    foreach ($section in $sections) {
        if ($null -eq $section.Object) {
            continue
        }

        $candidate = Get-ConfigPropertyValue -InputObject $section.Object -Name $Parameter.Name
        if ($candidate.Found) {
            $configured.HasValue = $true
            $configured.Value = $candidate.Value
            $configured.Source = $section.Name
        }
    }

    return $configured
}

function Convert-ConfigValueForParameter {
    param(
        [Parameter(Mandatory = $true)][object]$Parameter,
        [AllowNull()][object]$Value
    )

    $result = [pscustomobject][ordered]@{
        IsValid = $false
        Value   = $null
        Message = ""
    }

    if ($null -eq $Value) {
        $result.Message = "value is null"
        return $result
    }

    switch ($Parameter.Type) {
        "Credential" {
            $result.Message = "credential parameters are intentionally not loaded from config"
            return $result
        }
        "Switch" {
            if ($Value -is [bool]) {
                $result.IsValid = $true
                $result.Value = [bool]$Value
                return $result
            }

            $text = "$Value".Trim().ToLowerInvariant()
            if ($text -match "^(true|yes|y|1|on)$") {
                $result.IsValid = $true
                $result.Value = $true
                return $result
            }
            if ($text -match "^(false|no|n|0|off)$") {
                $result.IsValid = $true
                $result.Value = $false
                return $result
            }

            $result.Message = "expected a boolean value"
            return $result
        }
        "Int" {
            $parsed = 0
            if ([int]::TryParse("$Value", [ref]$parsed)) {
                $result.IsValid = $true
                $result.Value = $parsed
                return $result
            }

            $result.Message = "expected a whole number"
            return $result
        }
        "StringArray" {
            $items = @()
            if ($Value -is [array]) {
                $items = @($Value | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
            }
            else {
                $items = @("$Value" -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            }

            if ($items.Count -gt 0) {
                $result.IsValid = $true
                $result.Value = $items
                return $result
            }

            $result.Message = "expected one or more values"
            return $result
        }
        default {
            $textValue = "$Value".Trim()
            if ($textValue) {
                $result.IsValid = $true
                $result.Value = $textValue
                return $result
            }

            $result.Message = "expected a non-empty string"
            return $result
        }
    }
}

function Read-MenuInput {
    param([string]$Prompt = "Choose")
    (Read-Host $Prompt).Trim()
}

function Read-YesNo {
    param(
        [Parameter(Mandatory = $true)][string]$Prompt,
        [bool]$Default = $false
    )

    $suffix = if ($Default) { "[Y/n]" } else { "[y/N]" }
    while ($true) {
        $answer = (Read-Host "$Prompt $suffix").Trim()
        if (-not $answer) {
            return $Default
        }
        if ($answer -match "^(y|yes)$") {
            return $true
        }
        if ($answer -match "^(n|no)$") {
            return $false
        }
        Write-Host "Please answer yes or no." -ForegroundColor Yellow
    }
}

function Format-DefaultValue {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value -or "$Value" -eq "") {
        return "script default"
    }
    if ($Value -is [array]) {
        return ($Value -join ", ")
    }
    return "$Value"
}

function Format-ParameterPromptDefault {
    param(
        [Parameter(Mandatory = $true)][object]$Parameter,
        [AllowNull()][object]$ConfiguredValue,
        [switch]$HasConfiguredValue
    )

    if ($HasConfiguredValue) {
        return "$(Format-DefaultValue -Value $ConfiguredValue) (config)"
    }

    return (Format-DefaultValue -Value $Parameter.Default)
}

function Read-IntParameter {
    param(
        [Parameter(Mandatory = $true)][object]$Parameter,
        [AllowNull()][object]$ConfiguredValue = $null,
        [switch]$HasConfiguredValue
    )

    while ($true) {
        $defaultText = Format-ParameterPromptDefault -Parameter $Parameter -ConfiguredValue $ConfiguredValue -HasConfiguredValue:$HasConfiguredValue
        $value = (Read-Host "$($Parameter.Name) [$defaultText]").Trim()
        if (-not $value) {
            if ($HasConfiguredValue) {
                return [int]$ConfiguredValue
            }
            if ($Parameter.Required) {
                Write-Host "This parameter is required." -ForegroundColor Yellow
                continue
            }
            return $null
        }
        $parsed = 0
        if ([int]::TryParse($value, [ref]$parsed)) {
            return $parsed
        }
        Write-Host "Enter a whole number." -ForegroundColor Yellow
    }
}

function Read-StringParameter {
    param(
        [Parameter(Mandatory = $true)][object]$Parameter,
        [AllowNull()][object]$ConfiguredValue = $null,
        [switch]$HasConfiguredValue
    )

    while ($true) {
        $defaultText = Format-ParameterPromptDefault -Parameter $Parameter -ConfiguredValue $ConfiguredValue -HasConfiguredValue:$HasConfiguredValue
        $value = (Read-Host "$($Parameter.Name) [$defaultText]").Trim()
        if (-not $value) {
            if ($HasConfiguredValue) {
                return "$ConfiguredValue"
            }
            if ($Parameter.Required) {
                Write-Host "This parameter is required." -ForegroundColor Yellow
                continue
            }
            return $null
        }
        return $value
    }
}

function Read-StringArrayParameter {
    param(
        [Parameter(Mandatory = $true)][object]$Parameter,
        [AllowNull()][object]$ConfiguredValue = $null,
        [switch]$HasConfiguredValue
    )

    $defaultText = Format-ParameterPromptDefault -Parameter $Parameter -ConfiguredValue $ConfiguredValue -HasConfiguredValue:$HasConfiguredValue
    $value = (Read-Host "$($Parameter.Name) comma-separated [$defaultText]").Trim()
    if (-not $value) {
        if ($HasConfiguredValue) {
            return @($ConfiguredValue)
        }
        return $null
    }

    $items = @($value -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($items.Count -eq 0) {
        return $null
    }
    return $items
}

function Read-CredentialParameter {
    param([Parameter(Mandatory = $true)][object]$Parameter)

    if (Read-YesNo -Prompt "Use $($Parameter.Name)?" -Default $false) {
        return Get-Credential
    }
    return $null
}

function Read-SwitchParameter {
    param(
        [Parameter(Mandatory = $true)][object]$Parameter,
        [AllowNull()][object]$ConfiguredValue = $null,
        [switch]$HasConfiguredValue
    )

    $defaultEnabled = $false
    if ($HasConfiguredValue) {
        $defaultEnabled = [bool]$ConfiguredValue
    }

    $enabled = Read-YesNo -Prompt "Enable -$($Parameter.Name)?" -Default $defaultEnabled
    if (-not $enabled) {
        return $null
    }

    if ($Parameter.HighImpact) {
        Write-Host "High-impact option: -$($Parameter.Name)" -ForegroundColor Yellow
        Write-Host $Parameter.Description -ForegroundColor Yellow
        $confirmation = (Read-Host "Type YES to enable this option").Trim()
        if ($confirmation -ne "YES") {
            Write-Host "Skipped -$($Parameter.Name)." -ForegroundColor Yellow
            return $null
        }
    }

    return $true
}

function Read-ToolParameters {
    param(
        [Parameter(Mandatory = $true)][object]$Tool,
        [switch]$UseDefaultValues,
        [AllowNull()][object]$Config = $null
    )

    $arguments = @{}
    foreach ($parameter in @($Tool.Parameters)) {
        $configuredParameter = Get-ConfiguredParameterValue -Tool $Tool -Parameter $parameter -Config $Config
        $configuredValue = $null
        $hasConfiguredValue = $false
        if ($configuredParameter.HasValue) {
            $conversion = Convert-ConfigValueForParameter -Parameter $parameter -Value $configuredParameter.Value
            if ($conversion.IsValid) {
                $configuredValue = $conversion.Value
                $hasConfiguredValue = $true
            }
            else {
                Write-Host "Ignoring config value for -$($parameter.Name) from $($configuredParameter.Source): $($conversion.Message)." -ForegroundColor Yellow
            }
        }

        if ($UseDefaultValues) {
            if ($hasConfiguredValue) {
                if ($parameter.Type -eq "Switch") {
                    if ([bool]$configuredValue) {
                        if ($parameter.HighImpact) {
                            Write-Host "Skipping high-impact config value -$($parameter.Name) from $($configuredParameter.Source). Select the tool directly to confirm it." -ForegroundColor Yellow
                        }
                        else {
                            $arguments[$parameter.Name] = $true
                        }
                    }
                }
                else {
                    $arguments[$parameter.Name] = $configuredValue
                }
                continue
            }

            if (-not $parameter.Required) {
                continue
            }
        }

        Write-Host ""
        Write-Host "-$($parameter.Name) ($($parameter.Type))" -ForegroundColor Cyan
        if ($parameter.Description) {
            Write-Host $parameter.Description
        }
        if ($hasConfiguredValue) {
            Write-Host "Configured default from $($configuredParameter.Source): $(Format-DefaultValue -Value $configuredValue)" -ForegroundColor DarkCyan
        }

        $value = $null
        switch ($parameter.Type) {
            "Int" { $value = Read-IntParameter -Parameter $parameter -ConfiguredValue $configuredValue -HasConfiguredValue:$hasConfiguredValue }
            "Switch" { $value = Read-SwitchParameter -Parameter $parameter -ConfiguredValue $configuredValue -HasConfiguredValue:$hasConfiguredValue }
            "StringArray" { $value = Read-StringArrayParameter -Parameter $parameter -ConfiguredValue $configuredValue -HasConfiguredValue:$hasConfiguredValue }
            "Credential" { $value = Read-CredentialParameter -Parameter $parameter }
            default { $value = Read-StringParameter -Parameter $parameter -ConfiguredValue $configuredValue -HasConfiguredValue:$hasConfiguredValue }
        }

        if ($null -ne $value) {
            $arguments[$parameter.Name] = $value
        }
    }

    return $arguments
}

function Format-ArgumentValue {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return '$null'
    }
    if ($Value -is [System.Management.Automation.PSCredential]) {
        return "<credential>"
    }
    if ($Value -is [array]) {
        return (($Value | ForEach-Object { "'$_'" }) -join ",")
    }
    return "'$Value'"
}

function Format-CommandPreview {
    param(
        [Parameter(Mandatory = $true)][object]$Tool,
        [Parameter(Mandatory = $true)][hashtable]$Arguments
    )

    $scriptPath = Get-ToolPath -Tool $Tool
    $parts = New-Object System.Collections.Generic.List[string]
    $parts.Add(".\$($Tool.RelativePath)") | Out-Null
    foreach ($key in @($Arguments.Keys | Sort-Object)) {
        $value = $Arguments[$key]
        if ($value -is [bool]) {
            if ($value) {
                $parts.Add("-$key") | Out-Null
            }
        }
        else {
            $parts.Add("-$key") | Out-Null
            $parts.Add((Format-ArgumentValue -Value $value)) | Out-Null
        }
    }

    [pscustomobject][ordered]@{
        DisplayPath = $parts -join " "
        FullPath    = $scriptPath
    }
}

function Invoke-MenuTool {
    param(
        [Parameter(Mandatory = $true)][object]$Tool,
        [switch]$UseDefaultValues,
        [AllowNull()][object]$Config = $null
    )

    $scriptPath = Get-ToolPath -Tool $Tool
    if (-not (Test-Path -LiteralPath $scriptPath)) {
        Write-Host "Script not found: $scriptPath" -ForegroundColor Red
        return
    }

    Write-Host ""
    Write-Host "Selected: $($Tool.Name)" -ForegroundColor Green
    Write-Host "Mode: $($Tool.DefaultMode)"
    Write-Host "Path: $($Tool.RelativePath)"
    if ($null -ne $Config) {
        Write-Host "Config: $($Config.SourcePath)"
    }
    if ($Tool.Description) {
        Write-Host $Tool.Description
    }

    $useDefaultParameters = [bool]$UseDefaultValues
    if (-not $useDefaultParameters) {
        $useDefaultParameters = -not (Read-YesNo -Prompt "Do you want to edit parameters before running?" -Default $true)
    }

    $arguments = Read-ToolParameters -Tool $Tool -UseDefaultValues:$useDefaultParameters -Config $Config
    $preview = Format-CommandPreview -Tool $Tool -Arguments $arguments

    Write-Host ""
    Write-Host "Command preview:" -ForegroundColor Cyan
    Write-Host $preview.DisplayPath
    Write-Host ""
    if (-not (Read-YesNo -Prompt "Run this script now?" -Default $true)) {
        Write-Host "Skipped."
        return
    }

    Write-Host ""
    Write-Host "Running $($Tool.Name)..." -ForegroundColor Green
    try {
        & $scriptPath @arguments
        Write-Host ""
        Write-Host "Finished: $($Tool.Name)" -ForegroundColor Green
    }
    catch {
        Write-Host ""
        Write-Host "Failed: $($Tool.Name)" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
    }
}

function Show-ToolList {
    param([object[]]$Tools)

    $Tools |
        Sort-Object GroupId, Name |
        Select-Object GroupId, Id, Name, DefaultMode, RelativePath |
        Format-Table -AutoSize
}

function Show-MainMenu {
    param(
        [object[]]$Groups,
        [object[]]$Tools,
        [AllowNull()][object]$Config = $null
    )

    while (-not $script:QuitRequested) {
        Write-Host ""
        Write-Host "Windows Security Scripts" -ForegroundColor Cyan
        if ($null -ne $Config) {
            Write-Host "Parameter config: $($Config.SourcePath)" -ForegroundColor DarkCyan
        }
        Write-Host "Choose a group:"
        Write-Host ""

        for ($index = 0; $index -lt $Groups.Count; $index++) {
            $groupItem = $Groups[$index]
            $count = @($Tools | Where-Object { $_.GroupId -eq $groupItem.Id }).Count
            Write-Host ("[{0}] {1} ({2}) - {3}" -f ($index + 1), $groupItem.Label, $count, $groupItem.Description)
        }
        Write-Host "[L] List all scripts"
        Write-Host "[Q] Quit"

        $choice = Read-MenuInput
        if ($choice -match "^(q|quit)$") {
            return
        }
        if ($choice -match "^(l|list)$") {
            Show-ToolList -Tools $Tools
            continue
        }
        if ($choice -match "^\d+$") {
            $selectedIndex = [int]$choice - 1
            if ($selectedIndex -ge 0 -and $selectedIndex -lt $Groups.Count) {
                Show-GroupMenu -GroupItem $Groups[$selectedIndex] -Tools $Tools -Config $Config
                continue
            }
        }
        Write-Host "Invalid choice." -ForegroundColor Yellow
    }
}

function Show-GroupMenu {
    param(
        [Parameter(Mandatory = $true)][object]$GroupItem,
        [Parameter(Mandatory = $true)][object[]]$Tools,
        [AllowNull()][object]$Config = $null
    )

    $groupTools = @($Tools | Where-Object { $_.GroupId -eq $GroupItem.Id } | Sort-Object Name)
    if ($groupTools.Count -eq 0) {
        Write-Host ""
        Write-Host "No scripts are available yet for $($GroupItem.Label)." -ForegroundColor Yellow
        return
    }

    while (-not $script:QuitRequested) {
        Write-Host ""
        Write-Host "$($GroupItem.Label) Scripts" -ForegroundColor Cyan
        if ($null -ne $Config) {
            Write-Host "Parameter config: $($Config.SourcePath)" -ForegroundColor DarkCyan
        }
        for ($index = 0; $index -lt $groupTools.Count; $index++) {
            $tool = $groupTools[$index]
            $runAllLabel = if ($tool.IncludeInRunAll) { "default-safe" } else { "manual" }
            Write-Host ("[{0}] {1} ({2}, {3})" -f ($index + 1), $tool.Name, $tool.DefaultMode, $runAllLabel)
        }
        Write-Host "[A] Run all default-safe scripts in this group"
        Write-Host "[B] Back"
        Write-Host "[Q] Quit"

        $choice = Read-MenuInput
        if ($choice -match "^(q|quit)$") {
            $script:QuitRequested = $true
            return
        }
        if ($choice -match "^(b|back)$") {
            return
        }
        if ($choice -match "^(a|all)$") {
            Invoke-GroupRunAll -GroupItem $GroupItem -Tools $groupTools -Config $Config
            continue
        }
        if ($choice -match "^\d+$") {
            $selectedIndex = [int]$choice - 1
            if ($selectedIndex -ge 0 -and $selectedIndex -lt $groupTools.Count) {
                Invoke-MenuTool -Tool $groupTools[$selectedIndex] -UseDefaultValues:$UseDefaults -Config $Config
                continue
            }
        }
        Write-Host "Invalid choice." -ForegroundColor Yellow
    }
}

function Invoke-GroupRunAll {
    param(
        [Parameter(Mandatory = $true)][object]$GroupItem,
        [Parameter(Mandatory = $true)][object[]]$Tools,
        [AllowNull()][object]$Config = $null
    )

    $runnableTools = @($Tools | Where-Object { $_.IncludeInRunAll })
    if ($runnableTools.Count -eq 0) {
        Write-Host "No default-safe scripts are available for this group." -ForegroundColor Yellow
        return
    }

    Write-Host ""
    Write-Host "Default-safe scripts in $($GroupItem.Label):" -ForegroundColor Cyan
    foreach ($tool in $runnableTools) {
        Write-Host "- $($tool.Name) ($($tool.DefaultMode))"
    }
    Write-Host ""
    Write-Host "Manual or apply-oriented scripts are skipped by Run All. Select them directly when needed." -ForegroundColor Yellow

    if (-not (Read-YesNo -Prompt "Continue with Run All?" -Default $false)) {
        return
    }

    foreach ($tool in $runnableTools) {
        if ($script:QuitRequested) {
            return
        }

        Write-Host ""
        Write-Host "Next: $($tool.Name)" -ForegroundColor Cyan
        Write-Host "[D] Defaults  [C] Customize  [S] Skip  [Q] Quit"
        $choice = Read-MenuInput
        switch -Regex ($choice) {
            "^(q|quit)$" {
                $script:QuitRequested = $true
                return
            }
            "^(s|skip)$" {
                Write-Host "Skipped $($tool.Name)."
                continue
            }
            "^(c|custom|customize)$" {
                Invoke-MenuTool -Tool $tool -Config $Config
                continue
            }
            default {
                Invoke-MenuTool -Tool $tool -UseDefaultValues -Config $Config
            }
        }
    }
}

$groups = @(Get-GroupCatalog)
$tools = @(Get-ToolCatalog)
$config = Read-WindowsSecurityConfig -Path $ConfigPath

if ($ListScripts) {
    Show-ToolList -Tools $tools
    return
}

if ($null -ne $config) {
    Write-Host "Loaded parameter config: $($config.SourcePath)" -ForegroundColor DarkCyan
}

if ($ToolId) {
    $selectedTool = @($tools | Where-Object { $_.Id -eq $ToolId -or $_.Name -eq $ToolId } | Select-Object -First 1)
    if ($selectedTool.Count -eq 0) {
        throw "Unknown ToolId '$ToolId'. Use -ListScripts to see available IDs."
    }
    Invoke-MenuTool -Tool $selectedTool[0] -UseDefaultValues:$UseDefaults -Config $config
    return
}

if ($Group) {
    $selectedGroup = @($groups | Where-Object { $_.Id -eq $Group -or $_.Label -eq $Group } | Select-Object -First 1)
    if ($selectedGroup.Count -eq 0) {
        throw "Unknown group '$Group'. Valid groups: $(@($groups | ForEach-Object { $_.Id }) -join ', ')."
    }
    $groupTools = @($tools | Where-Object { $_.GroupId -eq $selectedGroup[0].Id } | Sort-Object Name)
    if ($RunAll) {
        Invoke-GroupRunAll -GroupItem $selectedGroup[0] -Tools $groupTools -Config $config
        return
    }
    Show-GroupMenu -GroupItem $selectedGroup[0] -Tools $tools -Config $config
    return
}

Show-MainMenu -Groups $groups -Tools $tools -Config $config
