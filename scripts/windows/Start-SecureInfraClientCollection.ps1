<#
.SYNOPSIS
Collects supported SecureInfra client-side evidence into one portable bundle.

.DESCRIPTION
Runs the safe, report-only or dry-run Windows checks that exist in this
repository and writes one structured collection folder. The collector does not
apply remediation, update AD baselines, delete files, or change system
configuration.

The output bundle is designed for a client to send back for SecureInfra AI
normalization, dashboard review, and final report generation.

.PARAMETER Scope
Collection scopes to run. Use All for the default supported local scopes.
Current implemented scopes are AD, Host, Server, Workstation, Network, and
Backup. Backup is explicit and is not included in All.

.PARAMETER OutputDirectory
Directory for the collection folder. A zip archive is created next to this
folder unless -SkipArchive is used.

.PARAMETER BaselineDirectory
Persistent local directory for collector baselines. Used by the privileged
group audit so repeated client runs can detect membership changes.

.PARAMETER PrivilegedGroupBaselinePath
Optional explicit baseline path for privileged group monitoring.

.PARAMETER StopOnError
Stop the collection when one task fails. By default, failures are recorded and
the collector continues with the next task.

.EXAMPLE
.\scripts\windows\Start-SecureInfraClientCollection.ps1

Run the default full collection and create a zip bundle under reports.

.EXAMPLE
.\scripts\windows\Start-SecureInfraClientCollection.ps1 -Scope AD,Host -OutputDirectory .\reports\client-collection

Run only AD/GPO and local host checks.
#>

[CmdletBinding()]
param(
    [string[]]$Scope = @("All"),
    [string]$OutputDirectory = ".\reports\secureinfra-client-collection-$env:COMPUTERNAME-$(Get-Date -Format 'yyyyMMdd-HHmmss')",
    [string]$BaselineDirectory = ".\reports\secureinfra-client-baselines",
    [string]$PrivilegedGroupBaselinePath = "",
    [string]$SearchBase = "",
    [string]$Server = "",
    [string]$Domain = "",
    [int]$DaysInactive = 90,
    [int]$StaleDays = 90,
    [int]$MaxPasswordAgeDays = 180,
    [int]$MaxCredentialAgeDays = 180,
    [int]$GpoStaleDays = 365,
    [int]$EventDays = 7,
    [int]$RdpCacheMinimumAgeDays = 14,
    [string[]]$ExpectedBackupPaths = @(),
    [string[]]$ExpectedBackupSoftware = @(),
    [int]$BackupWarningAgeDays = 14,
    [int]$BackupCriticalAgeDays = 30,
    [switch]$IncludeDisabled,
    [switch]$IncludeHotfixes,
    [switch]$SkipArchive,
    [switch]$StopOnError,
    [switch]$Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:TaskResults = New-Object System.Collections.Generic.List[object]
$script:CollectionMessages = New-Object System.Collections.Generic.List[string]
$script:ScriptRoot = $PSScriptRoot

function Resolve-FullPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
}

function New-Directory {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
}

function New-ParentDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)
    $parent = Split-Path -Path $Path -Parent
    if ($parent) {
        New-Directory -Path $parent
    }
}

function ConvertTo-SafeFileName {
    param([Parameter(Mandatory = $true)][string]$Value)
    return (($Value -replace "[^A-Za-z0-9_.-]", "-") -replace "-+", "-").Trim("-")
}

function Get-UtcTimestamp {
    return (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
}

function Test-IsAdministrator {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Add-OptionalStringArgument {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Arguments,
        [Parameter(Mandatory = $true)][string]$Name,
        [AllowEmptyString()][string]$Value
    )
    if (-not [string]::IsNullOrWhiteSpace($Value)) {
        $Arguments[$Name] = $Value
    }
}

function Add-SwitchArgument {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Arguments,
        [Parameter(Mandatory = $true)][string]$Name,
        [bool]$Enabled
    )
    if ($Enabled) {
        $Arguments[$Name] = $true
    }
}

function Resolve-CollectionScopes {
    $defaultAllScopes = @("AD", "Host", "Server", "Workstation", "Network")
    $orderedScopes = @("AD", "Host", "Server", "Workstation", "Network", "Backup")
    $requestedScopes = @(
        foreach ($item in @($Scope)) {
            foreach ($part in ("$item" -split ",")) {
                $trimmed = $part.Trim()
                if ($trimmed) {
                    $trimmed
                }
            }
        }
    )
    if (-not $requestedScopes) {
        $requestedScopes = @("All")
    }
    $validScopes = @("All") + $orderedScopes
    $invalidScopes = @($requestedScopes | Where-Object { $validScopes -notcontains $_ })
    if ($invalidScopes) {
        throw "Unsupported scope value(s): $($invalidScopes -join ', '). Supported values: $($validScopes -join ', ')"
    }
    if ($requestedScopes -contains "All") {
        return $defaultAllScopes
    }
    return @($orderedScopes | Where-Object { $requestedScopes -contains $_ })
}

function Add-SkippedTask {
    param(
        [Parameter(Mandatory = $true)][string]$ScopeName,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Message
    )

    $script:TaskResults.Add([pscustomobject][ordered]@{
            Scope            = $ScopeName
            Name             = $Name
            Status           = "Skipped"
            Message          = $Message
            Script           = ""
            StartedAtUtc     = Get-UtcTimestamp
            FinishedAtUtc    = Get-UtcTimestamp
            DurationSeconds  = 0
            LogPath          = ""
            ExpectedOutputs  = @()
            ExistingOutputs  = @()
        }) | Out-Null
}

function Invoke-CollectionTask {
    param(
        [Parameter(Mandatory = $true)][string]$ScopeName,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [hashtable]$Arguments = @{},
        [string[]]$ExpectedOutputs = @()
    )

    $started = Get-Date
    $startedUtc = Get-UtcTimestamp
    $status = "Succeeded"
    $message = ""
    $safeName = ConvertTo-SafeFileName -Value "$ScopeName-$Name"
    $logPath = Join-Path -Path $script:LogDirectory -ChildPath "$safeName.log"
    $outputLines = New-Object System.Collections.Generic.List[string]

    try {
        if (-not (Test-Path -LiteralPath $ScriptPath)) {
            throw "Script not found: $ScriptPath"
        }

        if (-not $Quiet) {
            Write-Host "Running [$ScopeName] $Name"
        }

        $rawOutput = & $ScriptPath @Arguments 2>&1
        foreach ($line in @($rawOutput)) {
            $outputLines.Add("$line") | Out-Null
        }
    }
    catch {
        $status = "Failed"
        $message = $_.Exception.Message
        $outputLines.Add("ERROR: $message") | Out-Null
    }

    if ($outputLines.Count -eq 0) {
        $outputLines.Add("No console output captured.") | Out-Null
    }
    $outputLines | Out-File -FilePath $logPath -Encoding utf8

    $finished = Get-Date
    $existingOutputs = @(
        $ExpectedOutputs |
            Where-Object { Test-Path -LiteralPath $_ } |
            ForEach-Object { Resolve-FullPath -Path $_ }
    )

    $result = [pscustomobject][ordered]@{
        Scope            = $ScopeName
        Name             = $Name
        Status           = $status
        Message          = $message
        Script           = Resolve-FullPath -Path $ScriptPath
        StartedAtUtc     = $startedUtc
        FinishedAtUtc    = Get-UtcTimestamp
        DurationSeconds  = [math]::Round(($finished - $started).TotalSeconds, 2)
        LogPath          = Resolve-FullPath -Path $logPath
        ExpectedOutputs  = @($ExpectedOutputs)
        ExistingOutputs  = @($existingOutputs)
    }
    $script:TaskResults.Add($result) | Out-Null

    if ($status -eq "Failed" -and $StopOnError) {
        throw "$ScopeName task failed: $Name - $message"
    }
}

function Get-ClientInfo {
    $os = $null
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    }
    catch {
        $script:CollectionMessages.Add("Unable to read Win32_OperatingSystem: $($_.Exception.Message)") | Out-Null
    }

    [pscustomobject][ordered]@{
        ComputerName       = $env:COMPUTERNAME
        UserName           = $env:USERNAME
        UserDomain         = $env:USERDOMAIN
        IsAdministrator    = Test-IsAdministrator
        PowerShellVersion  = $PSVersionTable.PSVersion.ToString()
        OsCaption          = if ($os) { "$($os.Caption)" } else { "" }
        OsVersion          = if ($os) { "$($os.Version)" } else { "" }
        OsBuildNumber      = if ($os) { "$($os.BuildNumber)" } else { "" }
        OsArchitecture     = if ($os) { "$($os.OSArchitecture)" } else { "" }
        CollectionHostUtc  = Get-UtcTimestamp
    }
}

function Write-JsonFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][object]$InputObject,
        [int]$Depth = 10
    )
    New-ParentDirectory -Path $Path
    $InputObject | ConvertTo-Json -Depth $Depth | Out-File -FilePath $Path -Encoding utf8
}

function Get-CollectionFiles {
    Get-ChildItem -LiteralPath $script:OutputDirectory -File -Recurse |
        Sort-Object FullName |
        ForEach-Object {
            $relative = $_.FullName.Substring($script:OutputDirectory.Length) -replace "^[\\/]+", ""
            $hash = ""
            try {
                $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
            }
            catch {
                $hash = ""
            }
            [pscustomobject][ordered]@{
                Path      = $relative
                SizeBytes = $_.Length
                Sha256    = $hash
            }
        }
}

function Get-StatusCounts {
    $counts = [ordered]@{}
    foreach ($result in $script:TaskResults.ToArray()) {
        $status = "$($result.Status)"
        if (-not $counts.Contains($status)) {
            $counts[$status] = 0
        }
        $counts[$status]++
    }
    return $counts
}

function Invoke-ADCollection {
    $adDirectory = Join-Path -Path $script:OutputDirectory -ChildPath "ad-shared"
    New-Directory -Path $adDirectory

    $baselinePath = $PrivilegedGroupBaselinePath
    if ([string]::IsNullOrWhiteSpace($baselinePath)) {
        $resolvedBaselineDirectory = Resolve-FullPath -Path $BaselineDirectory
        New-Directory -Path $resolvedBaselineDirectory
        $baselinePath = Join-Path -Path $resolvedBaselineDirectory -ChildPath "ad-privileged-groups-baseline.json"
    }
    else {
        $baselinePath = Resolve-FullPath -Path $baselinePath
        New-ParentDirectory -Path $baselinePath
    }

    $inactiveArgs = @{ OutputDirectory = $adDirectory; DaysInactive = $DaysInactive; Quiet = $true }
    Add-OptionalStringArgument -Arguments $inactiveArgs -Name "SearchBase" -Value $SearchBase
    Add-OptionalStringArgument -Arguments $inactiveArgs -Name "Server" -Value $Server
    Add-SwitchArgument -Arguments $inactiveArgs -Name "IncludeDisabled" -Enabled ([bool]$IncludeDisabled)
    Invoke-CollectionTask -ScopeName "AD" -Name "Inactive users" -ScriptPath (Join-Path $script:ScriptRoot "ad\Get-ADInactiveUserReport.ps1") -Arguments $inactiveArgs -ExpectedOutputs @(
        (Join-Path -Path $adDirectory -ChildPath "inactive-users.json"),
        (Join-Path -Path $adDirectory -ChildPath "inactive-users.csv"),
        (Join-Path -Path $adDirectory -ChildPath "inactive-users-review.md")
    )

    $computerArgs = @{ OutputDirectory = $adDirectory; DaysInactive = $StaleDays; Quiet = $true }
    Add-OptionalStringArgument -Arguments $computerArgs -Name "SearchBase" -Value $SearchBase
    Add-OptionalStringArgument -Arguments $computerArgs -Name "Server" -Value $Server
    Add-SwitchArgument -Arguments $computerArgs -Name "IncludeDisabled" -Enabled ([bool]$IncludeDisabled)
    Invoke-CollectionTask -ScopeName "AD" -Name "Stale computers" -ScriptPath (Join-Path $script:ScriptRoot "ad\Get-ADStaleComputerReport.ps1") -Arguments $computerArgs -ExpectedOutputs @(
        (Join-Path -Path $adDirectory -ChildPath "stale-computers.json"),
        (Join-Path -Path $adDirectory -ChildPath "stale-computers.csv"),
        (Join-Path -Path $adDirectory -ChildPath "stale-computers-review.md")
    )

    $groupArgs = @{ OutputDirectory = $adDirectory; BaselinePath = $baselinePath; Quiet = $true }
    Add-OptionalStringArgument -Arguments $groupArgs -Name "Server" -Value $Server
    Invoke-CollectionTask -ScopeName "AD" -Name "Privileged groups" -ScriptPath (Join-Path $script:ScriptRoot "ad\Watch-ADPrivilegedGroupChanges.ps1") -Arguments $groupArgs -ExpectedOutputs @(
        (Join-Path -Path $adDirectory -ChildPath "privileged-groups.json"),
        (Join-Path -Path $adDirectory -ChildPath "privileged-groups.csv"),
        (Join-Path -Path $adDirectory -ChildPath "privileged-group-members.csv"),
        (Join-Path -Path $adDirectory -ChildPath "privileged-group-changes.csv"),
        (Join-Path -Path $adDirectory -ChildPath "privileged-groups-review.md")
    )
    if (Test-Path -LiteralPath $baselinePath) {
        Copy-Item -LiteralPath $baselinePath -Destination (Join-Path -Path $adDirectory -ChildPath "ad-privileged-groups-baseline.json") -Force
    }

    $serviceArgs = @{ OutputDirectory = $adDirectory; StaleDays = $StaleDays; MaxPasswordAgeDays = $MaxPasswordAgeDays; Quiet = $true }
    Add-OptionalStringArgument -Arguments $serviceArgs -Name "SearchBase" -Value $SearchBase
    Add-OptionalStringArgument -Arguments $serviceArgs -Name "Server" -Value $Server
    Add-SwitchArgument -Arguments $serviceArgs -Name "IncludeDisabled" -Enabled ([bool]$IncludeDisabled)
    Invoke-CollectionTask -ScopeName "AD" -Name "Service accounts" -ScriptPath (Join-Path $script:ScriptRoot "ad\Get-ADServiceAccountAudit.ps1") -Arguments $serviceArgs -ExpectedOutputs @(
        (Join-Path -Path $adDirectory -ChildPath "service-accounts.json"),
        (Join-Path -Path $adDirectory -ChildPath "service-accounts.csv"),
        (Join-Path -Path $adDirectory -ChildPath "service-accounts-review.md")
    )

    $spnArgs = @{ OutputDirectory = $adDirectory; MaxPasswordAgeDays = $MaxPasswordAgeDays; Quiet = $true }
    Add-OptionalStringArgument -Arguments $spnArgs -Name "SearchBase" -Value $SearchBase
    Add-OptionalStringArgument -Arguments $spnArgs -Name "Server" -Value $Server
    Add-SwitchArgument -Arguments $spnArgs -Name "IncludeDisabled" -Enabled ([bool]$IncludeDisabled)
    Invoke-CollectionTask -ScopeName "AD" -Name "SPN exposure" -ScriptPath (Join-Path $script:ScriptRoot "ad\Get-ADSPNExposureAudit.ps1") -Arguments $spnArgs -ExpectedOutputs @(
        (Join-Path -Path $adDirectory -ChildPath "spn-exposure.json"),
        (Join-Path -Path $adDirectory -ChildPath "spn-exposure.csv"),
        (Join-Path -Path $adDirectory -ChildPath "spn-exposure-review.md")
    )

    $passwordArgs = @{ OutputDirectory = $adDirectory; MaxPasswordAgeDays = $MaxPasswordAgeDays; Quiet = $true }
    Add-OptionalStringArgument -Arguments $passwordArgs -Name "SearchBase" -Value $SearchBase
    Add-OptionalStringArgument -Arguments $passwordArgs -Name "Server" -Value $Server
    Add-SwitchArgument -Arguments $passwordArgs -Name "IncludeDisabled" -Enabled ([bool]$IncludeDisabled)
    Invoke-CollectionTask -ScopeName "AD" -Name "Password never expires" -ScriptPath (Join-Path $script:ScriptRoot "ad\Get-ADPasswordNeverExpiresReport.ps1") -Arguments $passwordArgs -ExpectedOutputs @(
        (Join-Path -Path $adDirectory -ChildPath "password-never-expires.json"),
        (Join-Path -Path $adDirectory -ChildPath "password-never-expires.csv"),
        (Join-Path -Path $adDirectory -ChildPath "password-never-expires-review.md")
    )

    $identityArgs = @{ OutputDirectory = $adDirectory; StaleDays = $StaleDays; MaxCredentialAgeDays = $MaxCredentialAgeDays; Quiet = $true }
    Add-OptionalStringArgument -Arguments $identityArgs -Name "Server" -Value $Server
    Invoke-CollectionTask -ScopeName "AD" -Name "Privileged identity protection" -ScriptPath (Join-Path $script:ScriptRoot "ad\Get-PrivilegedIdentityProtectionAudit.ps1") -Arguments $identityArgs -ExpectedOutputs @(
        (Join-Path -Path $adDirectory -ChildPath "privileged-identity-protection.json"),
        (Join-Path -Path $adDirectory -ChildPath "privileged-identities.csv"),
        (Join-Path -Path $adDirectory -ChildPath "privileged-group-memberships.csv"),
        (Join-Path -Path $adDirectory -ChildPath "privileged-identity-findings.csv"),
        (Join-Path -Path $adDirectory -ChildPath "privileged-identity-protection-review.md")
    )

    $gpoArgs = @{ OutputDirectory = $adDirectory; StaleDays = $GpoStaleDays; Quiet = $true }
    Add-OptionalStringArgument -Arguments $gpoArgs -Name "Domain" -Value $Domain
    Add-OptionalStringArgument -Arguments $gpoArgs -Name "Server" -Value $Server
    Invoke-CollectionTask -ScopeName "AD" -Name "GPO health" -ScriptPath (Join-Path $script:ScriptRoot "gpo\Get-ADGPOHealthReport.ps1") -Arguments $gpoArgs -ExpectedOutputs @(
        (Join-Path -Path $adDirectory -ChildPath "gpo-health.json"),
        (Join-Path -Path $adDirectory -ChildPath "gpos.csv"),
        (Join-Path -Path $adDirectory -ChildPath "gpo-links.csv"),
        (Join-Path -Path $adDirectory -ChildPath "gpo-findings.csv"),
        (Join-Path -Path $adDirectory -ChildPath "gpo-review.md")
    )
}

function Invoke-HostCollection {
    $hostDirectory = Join-Path -Path $script:OutputDirectory -ChildPath "host"
    New-Directory -Path $hostDirectory

    $auditPath = Join-Path -Path $hostDirectory -ChildPath "windows-security-audit.json"
    $auditArgs = @{ OutputPath = $auditPath; Quiet = $true }
    Add-SwitchArgument -Arguments $auditArgs -Name "IncludeHotfixes" -Enabled ([bool]$IncludeHotfixes)
    Invoke-CollectionTask -ScopeName "Host" -Name "Windows security audit" -ScriptPath (Join-Path $script:ScriptRoot "host\Invoke-WindowsSecurityAudit.ps1") -Arguments $auditArgs -ExpectedOutputs @($auditPath)

    if (Test-Path -LiteralPath $auditPath) {
        Invoke-CollectionTask -ScopeName "Host" -Name "Windows remediation plan" -ScriptPath (Join-Path $script:ScriptRoot "host\New-WindowsRemediationPlan.ps1") -Arguments @{
            AuditReportPath = $auditPath
            OutputPath      = Join-Path -Path $hostDirectory -ChildPath "windows-remediation-plan.json"
            IncludeMarkdown = $true
            MarkdownPath    = Join-Path -Path $hostDirectory -ChildPath "windows-remediation-plan.md"
            IncludeCsv      = $true
            CsvPath         = Join-Path -Path $hostDirectory -ChildPath "windows-remediation-plan.csv"
            Quiet           = $true
        } -ExpectedOutputs @(
            (Join-Path -Path $hostDirectory -ChildPath "windows-remediation-plan.json"),
            (Join-Path -Path $hostDirectory -ChildPath "windows-remediation-plan.md"),
            (Join-Path -Path $hostDirectory -ChildPath "windows-remediation-plan.csv")
        )
    }
    else {
        Add-SkippedTask -ScopeName "Host" -Name "Windows remediation plan" -Message "Skipped because windows-security-audit.json was not created."
    }

    Invoke-CollectionTask -ScopeName "Host" -Name "Windows event security report" -ScriptPath (Join-Path $script:ScriptRoot "host\Export-WindowsEventSecurityReport.ps1") -Arguments @{
        Days            = $EventDays
        OutputDirectory = Join-Path -Path $hostDirectory -ChildPath "windows-events"
    } -ExpectedOutputs @(
        (Join-Path -Path $hostDirectory -ChildPath "windows-events\summary.json"),
        (Join-Path -Path $hostDirectory -ChildPath "windows-events\summary.txt"),
        (Join-Path -Path $hostDirectory -ChildPath "windows-events\events.csv")
    )

    Invoke-CollectionTask -ScopeName "Host" -Name "Windows hardening preview" -ScriptPath (Join-Path $script:ScriptRoot "host\Set-WindowsBaselineHardening.ps1") -Arguments @{
        ReportPath = Join-Path -Path $hostDirectory -ChildPath "windows-hardening-preview.json"
    } -ExpectedOutputs @(
        (Join-Path -Path $hostDirectory -ChildPath "windows-hardening-preview.json")
    )
}

function Invoke-ServerCollection {
    $serverDirectory = Join-Path -Path $script:OutputDirectory -ChildPath "server"
    New-Directory -Path $serverDirectory

    Invoke-CollectionTask -ScopeName "Server" -Name "Server security inventory" -ScriptPath (Join-Path $script:ScriptRoot "server\Get-WindowsServerSecurityInventory.ps1") -Arguments @{
        OutputDirectory = $serverDirectory
        Quiet           = $true
    } -ExpectedOutputs @(
        (Join-Path -Path $serverDirectory -ChildPath "windows-server-security.json"),
        (Join-Path -Path $serverDirectory -ChildPath "windows-server-security-findings.csv"),
        (Join-Path -Path $serverDirectory -ChildPath "windows-server-security-review.md")
    )

    Invoke-CollectionTask -ScopeName "Server" -Name "Local administrators inventory" -ScriptPath (Join-Path $script:ScriptRoot "host\Get-WindowsLocalAdminInventory.ps1") -Arguments @{
        OutputDirectory = $serverDirectory
        Quiet           = $true
    } -ExpectedOutputs @(
        (Join-Path -Path $serverDirectory -ChildPath "windows-local-admins.json"),
        (Join-Path -Path $serverDirectory -ChildPath "windows-local-admins.csv"),
        (Join-Path -Path $serverDirectory -ChildPath "windows-local-admins-review.md")
    )

    Invoke-CollectionTask -ScopeName "Server" -Name "RDP exposure audit" -ScriptPath (Join-Path $script:ScriptRoot "host\Get-WindowsRDPExposureAudit.ps1") -Arguments @{
        OutputDirectory = $serverDirectory
        Quiet           = $true
    } -ExpectedOutputs @(
        (Join-Path -Path $serverDirectory -ChildPath "windows-rdp-exposure.json"),
        (Join-Path -Path $serverDirectory -ChildPath "windows-rdp-exposure-findings.csv"),
        (Join-Path -Path $serverDirectory -ChildPath "windows-rdp-exposure-review.md")
    )

    Invoke-CollectionTask -ScopeName "Server" -Name "RDP profile cache dry run" -ScriptPath (Join-Path $script:ScriptRoot "server\Clear-RDPUserProfileCache.ps1") -Arguments @{
        MinimumAgeDays = $RdpCacheMinimumAgeDays
        ReportPath     = Join-Path -Path $serverDirectory -ChildPath "rdp-profile-cache-cleanup.json"
    } -ExpectedOutputs @(
        (Join-Path -Path $serverDirectory -ChildPath "rdp-profile-cache-cleanup.json")
    )
}

function Invoke-WorkstationCollection {
    $workstationDirectory = Join-Path -Path $script:OutputDirectory -ChildPath "workstation"
    New-Directory -Path $workstationDirectory

    Invoke-CollectionTask -ScopeName "Workstation" -Name "Workstation security inventory" -ScriptPath (Join-Path $script:ScriptRoot "workstation\Get-WindowsWorkstationSecurityInventory.ps1") -Arguments @{
        OutputDirectory = $workstationDirectory
        Quiet           = $true
    } -ExpectedOutputs @(
        (Join-Path -Path $workstationDirectory -ChildPath "windows-workstation-security.json"),
        (Join-Path -Path $workstationDirectory -ChildPath "windows-workstation-security-findings.csv"),
        (Join-Path -Path $workstationDirectory -ChildPath "windows-workstation-security-review.md")
    )

    Invoke-CollectionTask -ScopeName "Workstation" -Name "Local administrators inventory" -ScriptPath (Join-Path $script:ScriptRoot "host\Get-WindowsLocalAdminInventory.ps1") -Arguments @{
        OutputDirectory = $workstationDirectory
        Quiet           = $true
    } -ExpectedOutputs @(
        (Join-Path -Path $workstationDirectory -ChildPath "windows-local-admins.json"),
        (Join-Path -Path $workstationDirectory -ChildPath "windows-local-admins.csv"),
        (Join-Path -Path $workstationDirectory -ChildPath "windows-local-admins-review.md")
    )

    Invoke-CollectionTask -ScopeName "Workstation" -Name "RDP exposure audit" -ScriptPath (Join-Path $script:ScriptRoot "host\Get-WindowsRDPExposureAudit.ps1") -Arguments @{
        OutputDirectory = $workstationDirectory
        Quiet           = $true
    } -ExpectedOutputs @(
        (Join-Path -Path $workstationDirectory -ChildPath "windows-rdp-exposure.json"),
        (Join-Path -Path $workstationDirectory -ChildPath "windows-rdp-exposure-findings.csv"),
        (Join-Path -Path $workstationDirectory -ChildPath "windows-rdp-exposure-review.md")
    )
}

function Invoke-NetworkCollection {
    $networkDirectory = Join-Path -Path $script:OutputDirectory -ChildPath "network"
    New-Directory -Path $networkDirectory

    Invoke-CollectionTask -ScopeName "Network" -Name "Network exposure audit" -ScriptPath (Join-Path $script:ScriptRoot "network\Get-WindowsNetworkExposureAudit.ps1") -Arguments @{
        OutputDirectory = $networkDirectory
        Quiet           = $true
    } -ExpectedOutputs @(
        (Join-Path -Path $networkDirectory -ChildPath "windows-network-exposure.json"),
        (Join-Path -Path $networkDirectory -ChildPath "windows-network-exposure-findings.csv"),
        (Join-Path -Path $networkDirectory -ChildPath "windows-network-exposure-review.md")
    )
}

function Invoke-BackupCollection {
    $backupDirectory = Join-Path -Path $script:OutputDirectory -ChildPath "backup"
    New-Directory -Path $backupDirectory

    Invoke-CollectionTask -ScopeName "Backup" -Name "Backup readiness audit" -ScriptPath (Join-Path $script:ScriptRoot "backup\Get-WindowsBackupReadinessAudit.ps1") -Arguments @{
        OutputDirectory        = $backupDirectory
        ExpectedBackupPaths    = @($ExpectedBackupPaths)
        ExpectedBackupSoftware = @($ExpectedBackupSoftware)
        WarningAgeDays         = $BackupWarningAgeDays
        CriticalAgeDays        = $BackupCriticalAgeDays
        Quiet                  = $true
    } -ExpectedOutputs @(
        (Join-Path -Path $backupDirectory -ChildPath "backup-readiness.json"),
        (Join-Path -Path $backupDirectory -ChildPath "backup-readiness-findings.csv"),
        (Join-Path -Path $backupDirectory -ChildPath "backup-readiness-review.md")
    )
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$collectionId = "secureinfra-client-$env:COMPUTERNAME-$timestamp"
$script:OutputDirectory = Resolve-FullPath -Path $OutputDirectory
$script:LogDirectory = Join-Path -Path $script:OutputDirectory -ChildPath "logs"
New-Directory -Path $script:OutputDirectory
New-Directory -Path $script:LogDirectory

$resolvedScopes = Resolve-CollectionScopes
$archivePath = if ($SkipArchive) { "" } else { "$($script:OutputDirectory).zip" }
$clientInfoPath = Join-Path -Path $script:OutputDirectory -ChildPath "client-info.json"
$summaryPath = Join-Path -Path $script:OutputDirectory -ChildPath "collection-summary.json"
$manifestPath = Join-Path -Path $script:OutputDirectory -ChildPath "manifest.json"

Write-JsonFile -Path $clientInfoPath -InputObject (Get-ClientInfo)

foreach ($scopeName in $resolvedScopes) {
    switch ($scopeName) {
        "AD" { Invoke-ADCollection }
        "Host" { Invoke-HostCollection }
        "Server" { Invoke-ServerCollection }
        "Workstation" { Invoke-WorkstationCollection }
        "Network" { Invoke-NetworkCollection }
        "Backup" { Invoke-BackupCollection }
    }
}

$statusCounts = Get-StatusCounts
$taskResults = @($script:TaskResults.ToArray())
$summary = [pscustomobject][ordered]@{
    CollectionId       = $collectionId
    ToolName           = "SecureInfra Client Collection"
    GeneratedAtUtc     = Get-UtcTimestamp
    SafetyMode         = "Audit and dry-run only. No remediation is applied."
    OutputDirectory    = $script:OutputDirectory
    ArchivePath        = $archivePath
    ScopeRequested     = @($Scope)
    ScopeResolved      = @($resolvedScopes)
    TaskCount          = $taskResults.Count
    StatusCounts       = $statusCounts
    SupportedToday     = @("AD", "Host", "Server", "Workstation", "Network", "Backup")
    NotYetImplemented  = @()
    AnalyzerNextStep   = "Run SecureInfra_AI/scripts/reporting/secureinfra_analyzer.py --input <collection-or-zip> --type client-bundle --output <analysis-output> for full bundle normalization."
    SendBackToReviewer = if ($archivePath) { $archivePath } else { $script:OutputDirectory }
    Messages           = @($script:CollectionMessages)
}
Write-JsonFile -Path $summaryPath -InputObject $summary -Depth 8

$manifest = [pscustomobject][ordered]@{
    SchemaVersion      = "1.0"
    CollectionId       = $collectionId
    ToolName           = "SecureInfra Client Collection"
    GeneratedAtUtc     = Get-UtcTimestamp
    ScriptPath         = Resolve-FullPath -Path $PSCommandPath
    SafetyMode         = "Audit and dry-run only"
    ScopeRequested     = @($Scope)
    ScopeResolved      = @($resolvedScopes)
    OutputDirectory    = $script:OutputDirectory
    ArchivePath        = $archivePath
    Tasks              = $taskResults
    Files              = @(Get-CollectionFiles)
}
Write-JsonFile -Path $manifestPath -InputObject $manifest -Depth 12

if (-not $SkipArchive) {
    if (Test-Path -LiteralPath $archivePath) {
        Remove-Item -LiteralPath $archivePath -Force
    }
    Compress-Archive -Path (Join-Path -Path $script:OutputDirectory -ChildPath "*") -DestinationPath $archivePath -Force
}

if (-not $Quiet) {
    Write-Host ""
    Write-Host "SecureInfra client collection complete." -ForegroundColor Green
    Write-Host "Collection folder: $script:OutputDirectory"
    if ($archivePath) {
        Write-Host "Send this archive to the reviewer: $archivePath" -ForegroundColor Yellow
    }
    else {
        Write-Host "Archive skipped. Send this folder to the reviewer: $script:OutputDirectory" -ForegroundColor Yellow
    }
    Write-Host "Summary: $summaryPath"
    Write-Host "Manifest: $manifestPath"
}
