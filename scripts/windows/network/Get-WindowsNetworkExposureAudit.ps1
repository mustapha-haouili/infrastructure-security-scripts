<#
.SYNOPSIS
Audits local Windows network exposure evidence.

.DESCRIPTION
Collects local network adapter, IP, DNS, default route, firewall profile,
network profile, and listening TCP port evidence. The script writes JSON, CSV,
and Markdown reports and does not change firewall, adapter, route, service, or
network configuration.

.PARAMETER OutputDirectory
Directory where windows-network-exposure.json,
windows-network-exposure-findings.csv, and windows-network-exposure-review.md
are written.

.PARAMETER Quiet
Suppress console summary.
#>

[CmdletBinding()]
param(
    [string]$OutputDirectory = ".\reports\windows-network-exposure-$env:COMPUTERNAME-$(Get-Date -Format 'yyyyMMdd-HHmmss')",
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

function ConvertTo-TextList {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) {
        return @()
    }
    return @($Value | ForEach-Object { "$_" })
}

function New-NetworkFinding {
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

function Get-ListenerSeverity {
    param([int]$Port)
    if ($Port -in @(3389, 5985, 5986, 445, 135, 139, 1433, 3306, 5432)) {
        return "High"
    }
    if ($Port -in @(21, 23, 25, 53, 389, 636, 8080, 8443, 9200, 9300)) {
        return "Medium"
    }
    return "Info"
}

function Test-WildcardListener {
    param([AllowNull()][object]$Address)
    $text = "$Address"
    return $text -in @("0.0.0.0", "::", "::0", "*")
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
    Add-MarkdownLine -Lines $lines -Text "# Windows Network Exposure Audit"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "Generated at UTC: ``$($Report.GeneratedAtUtc)``"
    Add-MarkdownLine -Lines $lines -Text "Computer: ``$($Report.ComputerName)``"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "## Summary"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "- Listening TCP ports: $($Report.Summary.ListeningTcpPortCount)"
    Add-MarkdownLine -Lines $lines -Text "- Risky listeners: $($Report.Summary.RiskyListenerCount)"
    Add-MarkdownLine -Lines $lines -Text "- Disabled firewall profiles: $($Report.Summary.DisabledFirewallProfileCount)"
    Add-MarkdownLine -Lines $lines -Text "- Public network profiles: $($Report.Summary.PublicNetworkProfileCount)"
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
    Add-MarkdownLine -Lines $lines -Text "## Safety Notes"
    Add-MarkdownLine -Lines $lines
    Add-MarkdownLine -Lines $lines -Text "- This script does not scan other hosts."
    Add-MarkdownLine -Lines $lines -Text "- This script does not change network or firewall configuration."

    $lines | Out-File -FilePath $Path -Encoding utf8
}

New-Directory -Path $OutputDirectory
$resolvedOutputDirectory = (Resolve-Path -Path $OutputDirectory).Path
$jsonPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "windows-network-exposure.json"
$csvPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "windows-network-exposure-findings.csv"
$markdownPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "windows-network-exposure-review.md"
$generatedAtUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$findings = New-Object System.Collections.Generic.List[object]
$reportErrors = New-Object System.Collections.Generic.List[string]

$adapters = @(Invoke-Safe -ScriptBlock {
        Get-NetAdapter -ErrorAction Stop | ForEach-Object {
            [pscustomobject][ordered]@{
                Name                 = "$($_.Name)"
                InterfaceDescription = "$($_.InterfaceDescription)"
                Status               = "$($_.Status)"
                MacAddress           = "$($_.MacAddress)"
                LinkSpeed            = "$($_.LinkSpeed)"
            }
        }
    } -Default @())

$ipConfigurations = @(Invoke-Safe -ScriptBlock {
        Get-NetIPConfiguration -ErrorAction Stop | ForEach-Object {
            [pscustomobject][ordered]@{
                InterfaceAlias  = "$($_.InterfaceAlias)"
                InterfaceIndex  = $_.InterfaceIndex
                IPv4Address     = @(ConvertTo-TextList -Value @($_.IPv4Address | ForEach-Object { $_.IPAddress }))
                IPv6Address     = @(ConvertTo-TextList -Value @($_.IPv6Address | ForEach-Object { $_.IPAddress }))
                IPv4DefaultGateway = @(ConvertTo-TextList -Value @($_.IPv4DefaultGateway | ForEach-Object { $_.NextHop }))
                DnsServer       = @(ConvertTo-TextList -Value $_.DNSServer.ServerAddresses)
            }
        }
    } -Default @())

$dnsServers = @(Invoke-Safe -ScriptBlock {
        Get-DnsClientServerAddress -ErrorAction Stop | ForEach-Object {
            [pscustomobject][ordered]@{
                InterfaceAlias  = "$($_.InterfaceAlias)"
                AddressFamily   = "$($_.AddressFamily)"
                ServerAddresses = @(ConvertTo-TextList -Value $_.ServerAddresses)
            }
        }
    } -Default @())

$defaultRoutes = @(Invoke-Safe -ScriptBlock {
        Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object { $_.DestinationPrefix -eq "0.0.0.0/0" } |
            ForEach-Object {
                [pscustomobject][ordered]@{
                    InterfaceAlias = "$($_.InterfaceAlias)"
                    NextHop        = "$($_.NextHop)"
                    RouteMetric    = $_.RouteMetric
                    ifMetric       = $_.ifMetric
                }
            }
    } -Default @())

$firewallProfiles = @(Invoke-Safe -ScriptBlock {
        Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object {
            [pscustomobject][ordered]@{
                Name                 = "$($_.Name)"
                Enabled              = [bool]$_.Enabled
                DefaultInboundAction = "$($_.DefaultInboundAction)"
                DefaultOutboundAction = "$($_.DefaultOutboundAction)"
                LogAllowed           = "$($_.LogAllowed)"
                LogBlocked           = "$($_.LogBlocked)"
            }
        }
    } -Default @())

$networkProfiles = @(Invoke-Safe -ScriptBlock {
        Get-NetConnectionProfile -ErrorAction Stop | ForEach-Object {
            [pscustomobject][ordered]@{
                Name             = "$($_.Name)"
                InterfaceAlias   = "$($_.InterfaceAlias)"
                NetworkCategory  = "$($_.NetworkCategory)"
                IPv4Connectivity = "$($_.IPv4Connectivity)"
                IPv6Connectivity = "$($_.IPv6Connectivity)"
            }
        }
    } -Default @())

$listeningTcpPorts = @(Invoke-Safe -ScriptBlock {
        Get-NetTCPConnection -State Listen -ErrorAction Stop | ForEach-Object {
            $owningProcess = $_.OwningProcess
            [pscustomobject][ordered]@{
                LocalAddress  = "$($_.LocalAddress)"
                LocalPort     = [int]$_.LocalPort
                OwningProcess = $owningProcess
                ProcessName   = Invoke-Safe -ScriptBlock { (Get-Process -Id $owningProcess -ErrorAction Stop).ProcessName } -Default "unknown"
            }
        }
    } -Default @())

if ($adapters.Count -eq 0) {
    $reportErrors.Add("No adapter data was collected. NetTCPIP cmdlets may be unavailable.") | Out-Null
}

foreach ($profile in $firewallProfiles) {
    if (-not $profile.Enabled) {
        $severity = if ($profile.Name -eq "Public") { "High" } else { "Medium" }
        $findings.Add((New-NetworkFinding -FindingType "FirewallProfileDisabled" -Severity $severity -Title "Windows Firewall profile is disabled" -Evidence "$($profile.Name) profile Enabled=False." -Recommendation "Enable the firewall profile after validating approved rules and remote administration requirements.")) | Out-Null
    }
}

foreach ($profile in $networkProfiles) {
    if ($profile.NetworkCategory -eq "Public") {
        $findings.Add((New-NetworkFinding -FindingType "PublicNetworkProfileActive" -Severity "Medium" -Title "Public network profile is active" -Evidence "$($profile.InterfaceAlias) is using the Public network category." -Recommendation "Confirm the network classification is intended and firewall rules are restrictive.")) | Out-Null
    }
}

$riskyListeners = @()
foreach ($listener in $listeningTcpPorts) {
    $severity = Get-ListenerSeverity -Port $listener.LocalPort
    if ($severity -eq "Info") {
        continue
    }
    $riskyListeners += $listener
    $wildcardText = if (Test-WildcardListener -Address $listener.LocalAddress) { " on all interfaces" } else { "" }
    $findings.Add((New-NetworkFinding -FindingType "RiskyListeningPort" -Severity $severity -Title "Sensitive TCP port is listening" -Evidence "TCP $($listener.LocalPort) is listening$wildcardText by process $($listener.ProcessName)." -Recommendation "Confirm the listener is required and restricted by host and network firewall policy.")) | Out-Null
}

$severityCounts = [ordered]@{
    Critical = @($findings | Where-Object { $_.Severity -eq "Critical" }).Count
    High     = @($findings | Where-Object { $_.Severity -eq "High" }).Count
    Medium   = @($findings | Where-Object { $_.Severity -eq "Medium" }).Count
    Low      = @($findings | Where-Object { $_.Severity -eq "Low" }).Count
    Info     = @($findings | Where-Object { $_.Severity -eq "Info" }).Count
}

$report = [pscustomobject][ordered]@{
    ToolName        = "Get-WindowsNetworkExposureAudit"
    ReportType      = "windows-network-exposure"
    GeneratedAtUtc  = $generatedAtUtc
    ComputerName    = $env:COMPUTERNAME
    Summary         = [ordered]@{
        AdapterCount                 = $adapters.Count
        IpConfigurationCount         = $ipConfigurations.Count
        DefaultRouteCount            = $defaultRoutes.Count
        FirewallProfileCount         = $firewallProfiles.Count
        DisabledFirewallProfileCount = @($firewallProfiles | Where-Object { -not $_.Enabled }).Count
        PublicNetworkProfileCount    = @($networkProfiles | Where-Object { $_.NetworkCategory -eq "Public" }).Count
        ListeningTcpPortCount        = $listeningTcpPorts.Count
        RiskyListenerCount           = @($riskyListeners).Count
        FindingCount                 = $findings.Count
        SeverityCounts               = $severityCounts
    }
    NetworkAdapters      = @($adapters)
    IPConfigurations     = @($ipConfigurations)
    DnsClientServers     = @($dnsServers)
    DefaultRoutes        = @($defaultRoutes)
    FirewallProfiles     = @($firewallProfiles)
    NetworkProfiles      = @($networkProfiles)
    ListeningTcpPorts    = @($listeningTcpPorts)
    Findings             = @($findings.ToArray())
    ReportErrors         = @($reportErrors.ToArray())
    Notes                = @(
        "This report is audit-only and does not scan remote hosts.",
        "Network and firewall changes require owner review and approved change control."
    )
}

$report | ConvertTo-Json -Depth 8 | Out-File -FilePath $jsonPath -Encoding utf8
Write-CsvReport -Path $csvPath -Rows @($findings.ToArray())
Write-MarkdownReport -Path $markdownPath -Report $report

if (-not $Quiet) {
    Write-Host "Windows network exposure report written to: $jsonPath"
    Write-Host "Listening TCP ports: $($listeningTcpPorts.Count)"
    Write-Host "Findings: $($findings.Count)"
}
