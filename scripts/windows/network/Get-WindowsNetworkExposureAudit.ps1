<#
.SYNOPSIS
Audits local Windows network exposure evidence.

.DESCRIPTION
Collects local network adapter, IP, DNS, default route, firewall profile,
network profile, inbound firewall allow rule, and listening TCP/UDP port evidence. The script writes JSON, CSV,
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
        [Parameter(Mandatory = $true)][string]$Recommendation,
        [string]$Protocol = "",
        [AllowNull()][object]$LocalPort = $null,
        [string]$LocalAddress = "",
        [string]$BindScope = "",
        [AllowNull()][object]$OwningProcess = $null,
        [string]$ProcessName = "",
        [string]$ProcessPath = "",
        [string]$ServiceName = "",
        [string]$ServiceDisplayName = "",
        [string]$ServiceStartMode = "",
        [string]$ServiceState = ""
    )
    $item = [ordered]@{
        FindingType          = $FindingType
        Severity             = $Severity
        Title                = $Title
        Evidence             = $Evidence
        Recommendation       = $Recommendation
        RequiresOwnerReview  = $true
        SafeToAutoRemediate  = $false
    }
    if (-not [string]::IsNullOrWhiteSpace($Protocol)) { $item["Protocol"] = $Protocol }
    if ($null -ne $LocalPort -and "$LocalPort" -ne "") { $item["LocalPort"] = [int]$LocalPort }
    if (-not [string]::IsNullOrWhiteSpace($LocalAddress)) { $item["LocalAddress"] = $LocalAddress }
    if (-not [string]::IsNullOrWhiteSpace($BindScope)) { $item["BindScope"] = $BindScope }
    if ($null -ne $OwningProcess -and "$OwningProcess" -ne "") { $item["OwningProcess"] = $OwningProcess }
    if (-not [string]::IsNullOrWhiteSpace($ProcessName)) { $item["ProcessName"] = $ProcessName }
    if (-not [string]::IsNullOrWhiteSpace($ProcessPath)) { $item["ProcessPath"] = $ProcessPath }
    if (-not [string]::IsNullOrWhiteSpace($ServiceName)) { $item["ServiceName"] = $ServiceName }
    if (-not [string]::IsNullOrWhiteSpace($ServiceDisplayName)) { $item["ServiceDisplayName"] = $ServiceDisplayName }
    if (-not [string]::IsNullOrWhiteSpace($ServiceStartMode)) { $item["ServiceStartMode"] = $ServiceStartMode }
    if (-not [string]::IsNullOrWhiteSpace($ServiceState)) { $item["ServiceState"] = $ServiceState }
    [pscustomobject]$item
}

function Get-ListenerSeverity {
    param(
        [int]$Port,
        [string]$Protocol = "TCP"
    )
    if ($Protocol.ToUpperInvariant() -eq "TCP" -and $Port -in @(3389, 5985, 5986, 445, 135, 139, 1433, 3306, 5432)) {
        return "High"
    }
    if ($Protocol.ToUpperInvariant() -eq "UDP" -and $Port -in @(53, 88, 137, 138, 500, 4500)) {
        return "Medium"
    }
    if ($Port -in @(21, 23, 25, 53, 389, 636, 8080, 8443, 9200, 9300, 161, 162)) {
        return "Medium"
    }
    return "Info"
}

function Get-BindScope {
    param([AllowNull()][object]$Address)
    $text = "$Address".Trim()
    if ($text -in @("0.0.0.0", "::", "::0", "*")) {
        return "All interfaces"
    }
    if ($text -like "127.*" -or $text -eq "::1" -or $text -eq "localhost") {
        return "Loopback only"
    }
    if (-not [string]::IsNullOrWhiteSpace($text)) {
        return "Specific interface"
    }
    return "Not collected"
}

function Get-ProcessLookup {
    $lookup = @{}
    $processRows = @(Invoke-Safe -ScriptBlock {
            Get-CimInstance Win32_Process -ErrorAction Stop | ForEach-Object {
                [pscustomobject][ordered]@{
                    ProcessId       = [int]$_.ProcessId
                    Name            = "$($_.Name)"
                    ExecutablePath  = "$($_.ExecutablePath)"
                    CommandLine     = "$($_.CommandLine)"
                    ParentProcessId = $_.ParentProcessId
                }
            }
        } -Default @())
    foreach ($process in $processRows) {
        $lookup["$($process.ProcessId)"] = $process
    }
    return $lookup
}

function Get-ServiceLookupByProcessId {
    $lookup = @{}
    $services = @(Invoke-Safe -ScriptBlock {
            Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object { $_.ProcessId -gt 0 } | ForEach-Object {
                [pscustomobject][ordered]@{
                    Name        = "$($_.Name)"
                    DisplayName = "$($_.DisplayName)"
                    ProcessId   = [int]$_.ProcessId
                    State       = "$($_.State)"
                    StartMode   = "$($_.StartMode)"
                    PathName    = "$($_.PathName)"
                }
            }
        } -Default @())
    foreach ($service in $services) {
        $pid = "$($service.ProcessId)"
        if (-not $lookup.ContainsKey($pid)) {
            $lookup[$pid] = @()
        }
        $lookup[$pid] = @($lookup[$pid]) + @($service)
    }
    return $lookup
}

function Get-ServiceHint {
    param(
        [hashtable]$ServiceLookup,
        [AllowNull()][object]$ProcessId
    )
    $services = @()
    if ($null -ne $ProcessId -and $ServiceLookup.ContainsKey("$ProcessId")) {
        $services = @($ServiceLookup["$ProcessId"])
    }
    if ($services.Count -eq 0) {
        return [pscustomobject][ordered]@{
            ServiceName        = ""
            ServiceDisplayName = ""
            ServiceStartMode   = ""
            ServiceState       = ""
        }
    }
    return [pscustomobject][ordered]@{
        ServiceName        = (($services | ForEach-Object { $_.Name }) -join ",")
        ServiceDisplayName = (($services | ForEach-Object { $_.DisplayName }) -join ",")
        ServiceStartMode   = (($services | ForEach-Object { $_.StartMode } | Select-Object -Unique) -join ",")
        ServiceState       = (($services | ForEach-Object { $_.State } | Select-Object -Unique) -join ",")
    }
}

function Test-WildcardListener {
    param([AllowNull()][object]$Address)
    $text = "$Address"
    return $text -in @("0.0.0.0", "::", "::0", "*")
}

function Get-SensitiveWindowsPorts {
    return @(135, 139, 445, 3389, 5985, 5986)
}

function Get-MatchingSensitivePorts {
    param([AllowNull()][object]$LocalPort)
    $text = "$LocalPort".Trim()
    $sensitivePorts = @(Get-SensitiveWindowsPorts)
    if ([string]::IsNullOrWhiteSpace($text) -or $text -in @("Any", "RPC", "RPC-EPMap", "RPC Dynamic Ports")) {
        return @()
    }

    $matches = New-Object System.Collections.Generic.List[int]
    foreach ($token in ($text -split "[,;\s]+")) {
        if ([string]::IsNullOrWhiteSpace($token)) { continue }
        if ($token -match "^(\d{1,5})-(\d{1,5})$") {
            $low = [int]$Matches[1]
            $high = [int]$Matches[2]
            foreach ($port in $sensitivePorts) {
                if ($port -ge $low -and $port -le $high) { $matches.Add([int]$port) | Out-Null }
            }
            continue
        }
        $parsed = 0
        if ([int]::TryParse($token, [ref]$parsed) -and $sensitivePorts -contains $parsed) {
            $matches.Add([int]$parsed) | Out-Null
        }
    }
    return @($matches.ToArray() | Sort-Object -Unique)
}

function Get-InboundAllowFirewallRuleInventory {
    $rules = @(Invoke-Safe -ScriptBlock {
            Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction Stop
        } -Default @())

    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($rule in $rules) {
        $portFilters = @(Invoke-Safe -ScriptBlock { Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop } -Default @())
        if ($portFilters.Count -eq 0) { $portFilters = @([pscustomobject]@{ Protocol = "Any"; LocalPort = "Any"; RemotePort = "Any" }) }
        $addressFilters = @(Invoke-Safe -ScriptBlock { Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop } -Default @())
        $applicationFilters = @(Invoke-Safe -ScriptBlock { Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop } -Default @())
        $serviceFilters = @(Invoke-Safe -ScriptBlock { Get-NetFirewallServiceFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop } -Default @())

        $remoteAddresses = (($addressFilters | ForEach-Object { ConvertTo-TextList -Value $_.RemoteAddress }) -join ",")
        $localAddresses = (($addressFilters | ForEach-Object { ConvertTo-TextList -Value $_.LocalAddress }) -join ",")
        $programs = (($applicationFilters | ForEach-Object { "$($_.Program)" } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join ",")
        $services = (($serviceFilters | ForEach-Object { "$($_.Service)" } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join ",")

        foreach ($filter in $portFilters) {
            $rows.Add([pscustomobject][ordered]@{
                    Name            = "$($rule.Name)"
                    DisplayName     = "$($rule.DisplayName)"
                    Group           = "$($rule.Group)"
                    Enabled         = "$($rule.Enabled)"
                    Direction       = "$($rule.Direction)"
                    Action          = "$($rule.Action)"
                    Profiles        = "$($rule.Profile)"
                    Protocol        = "$($filter.Protocol)"
                    LocalPorts      = "$($filter.LocalPort)"
                    RemotePorts     = "$($filter.RemotePort)"
                    LocalAddresses  = $localAddresses
                    RemoteAddresses = $remoteAddresses
                    Program         = $programs
                    ServiceName     = $services
                }) | Out-Null
        }
    }
    return @($rows.ToArray())
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
    Add-MarkdownLine -Lines $lines -Text "- Listening UDP ports: $($Report.Summary.ListeningUdpPortCount)"
    Add-MarkdownLine -Lines $lines -Text "- Risky listeners: $($Report.Summary.RiskyListenerCount)"
    Add-MarkdownLine -Lines $lines -Text "- Listeners mapped to Windows services: $($Report.Summary.ServiceMappedListenerCount)"
    Add-MarkdownLine -Lines $lines -Text "- Inbound allow firewall rules: $($Report.Summary.InboundAllowFirewallRuleCount)"
    Add-MarkdownLine -Lines $lines -Text "- Sensitive inbound firewall rules: $($Report.Summary.SensitiveFirewallRuleCount)"
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

$inboundAllowFirewallRules = @(Get-InboundAllowFirewallRuleInventory)

$processLookup = Get-ProcessLookup
$serviceLookup = Get-ServiceLookupByProcessId

$listeningTcpPorts = @(Invoke-Safe -ScriptBlock {
        Get-NetTCPConnection -State Listen -ErrorAction Stop | ForEach-Object {
            $owningProcess = $_.OwningProcess
            $processDetails = $processLookup["$owningProcess"]
            $serviceHint = Get-ServiceHint -ServiceLookup $serviceLookup -ProcessId $owningProcess
            $processName = if ($processDetails -and $processDetails.Name) { "$($processDetails.Name)" } else { Invoke-Safe -ScriptBlock { (Get-Process -Id $owningProcess -ErrorAction Stop).ProcessName } -Default "unknown" }
            [pscustomobject][ordered]@{
                Protocol           = "TCP"
                LocalAddress       = "$($_.LocalAddress)"
                LocalPort          = [int]$_.LocalPort
                BindScope          = Get-BindScope -Address $_.LocalAddress
                OwningProcess      = $owningProcess
                ProcessName        = $processName
                ProcessPath        = if ($processDetails) { "$($processDetails.ExecutablePath)" } else { "" }
                CommandLine        = if ($processDetails) { "$($processDetails.CommandLine)" } else { "" }
                ServiceName        = $serviceHint.ServiceName
                ServiceDisplayName = $serviceHint.ServiceDisplayName
                ServiceStartMode   = $serviceHint.ServiceStartMode
                ServiceState       = $serviceHint.ServiceState
            }
        }
    } -Default @())

$listeningUdpPorts = @(Invoke-Safe -ScriptBlock {
        Get-NetUDPEndpoint -ErrorAction Stop | ForEach-Object {
            $owningProcess = $_.OwningProcess
            $processDetails = $processLookup["$owningProcess"]
            $serviceHint = Get-ServiceHint -ServiceLookup $serviceLookup -ProcessId $owningProcess
            $processName = if ($processDetails -and $processDetails.Name) { "$($processDetails.Name)" } else { Invoke-Safe -ScriptBlock { (Get-Process -Id $owningProcess -ErrorAction Stop).ProcessName } -Default "unknown" }
            [pscustomobject][ordered]@{
                Protocol           = "UDP"
                LocalAddress       = "$($_.LocalAddress)"
                LocalPort          = [int]$_.LocalPort
                BindScope          = Get-BindScope -Address $_.LocalAddress
                OwningProcess      = $owningProcess
                ProcessName        = $processName
                ProcessPath        = if ($processDetails) { "$($processDetails.ExecutablePath)" } else { "" }
                CommandLine        = if ($processDetails) { "$($processDetails.CommandLine)" } else { "" }
                ServiceName        = $serviceHint.ServiceName
                ServiceDisplayName = $serviceHint.ServiceDisplayName
                ServiceStartMode   = $serviceHint.ServiceStartMode
                ServiceState       = $serviceHint.ServiceState
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

foreach ($rule in $inboundAllowFirewallRules) {
    $protocolText = "$($rule.Protocol)".ToUpperInvariant()
    $matchingPorts = @(Get-MatchingSensitivePorts -LocalPort $rule.LocalPorts)
    foreach ($port in $matchingPorts) {
        $protocolForFinding = if ($protocolText -in @("TCP", "UDP")) { $protocolText } else { "TCP" }
        $severity = Get-ListenerSeverity -Port $port -Protocol $protocolForFinding
        $findings.Add((New-NetworkFinding `
            -FindingType "FirewallAllowsSensitivePort" `
            -Severity $severity `
            -Title "Inbound firewall allow rule permits sensitive Windows port" `
            -Evidence "Firewall rule '$($rule.DisplayName)' allows inbound $protocolForFinding $port on profile $($rule.Profiles) with remote addresses $($rule.RemoteAddresses)." `
            -Recommendation "Validate rule owner, profile scope, remote address restrictions, service dependency, and change approval." `
            -Protocol $protocolForFinding `
            -LocalPort $port `
            -LocalAddress $rule.LocalAddresses `
            -ServiceName $rule.ServiceName)) | Out-Null
        $findings[$findings.Count - 1] | Add-Member -NotePropertyName RuleName -NotePropertyValue $rule.Name -Force
        $findings[$findings.Count - 1] | Add-Member -NotePropertyName RuleDisplayName -NotePropertyValue $rule.DisplayName -Force
        $findings[$findings.Count - 1] | Add-Member -NotePropertyName Profile -NotePropertyValue $rule.Profiles -Force
        $findings[$findings.Count - 1] | Add-Member -NotePropertyName LocalPorts -NotePropertyValue $rule.LocalPorts -Force
        $findings[$findings.Count - 1] | Add-Member -NotePropertyName RemoteAddresses -NotePropertyValue $rule.RemoteAddresses -Force
        $findings[$findings.Count - 1] | Add-Member -NotePropertyName LocalAddresses -NotePropertyValue $rule.LocalAddresses -Force
        $findings[$findings.Count - 1] | Add-Member -NotePropertyName Program -NotePropertyValue $rule.Program -Force
    }
}

$riskyListeners = @()
foreach ($listener in @($listeningTcpPorts + $listeningUdpPorts)) {
    $severity = Get-ListenerSeverity -Port $listener.LocalPort -Protocol $listener.Protocol
    if ($severity -eq "Info") {
        continue
    }
    $riskyListeners += $listener
    $wildcardText = if (Test-WildcardListener -Address $listener.LocalAddress) { " on all interfaces" } else { "" }
    $serviceText = if (-not [string]::IsNullOrWhiteSpace($listener.ServiceName)) { " service $($listener.ServiceName)" } else { "" }
    $findings.Add((New-NetworkFinding `
        -FindingType "RiskyListeningPort" `
        -Severity $severity `
        -Title "Sensitive $($listener.Protocol) port is listening" `
        -Evidence "$($listener.Protocol) $($listener.LocalPort) is listening$wildcardText by process $($listener.ProcessName)$serviceText." `
        -Recommendation "Confirm the listener is required and restricted by host and network firewall policy." `
        -Protocol $listener.Protocol `
        -LocalPort $listener.LocalPort `
        -LocalAddress $listener.LocalAddress `
        -BindScope $listener.BindScope `
        -OwningProcess $listener.OwningProcess `
        -ProcessName $listener.ProcessName `
        -ProcessPath $listener.ProcessPath `
        -ServiceName $listener.ServiceName `
        -ServiceDisplayName $listener.ServiceDisplayName `
        -ServiceStartMode $listener.ServiceStartMode `
        -ServiceState $listener.ServiceState)) | Out-Null
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
        ListeningUdpPortCount        = $listeningUdpPorts.Count
        RiskyListenerCount           = @($riskyListeners).Count
        ServiceMappedListenerCount   = @(@($listeningTcpPorts + $listeningUdpPorts) | Where-Object { -not [string]::IsNullOrWhiteSpace($_.ServiceName) }).Count
        InboundAllowFirewallRuleCount = $inboundAllowFirewallRules.Count
        SensitiveFirewallRuleCount   = @($findings | Where-Object { $_.FindingType -eq "FirewallAllowsSensitivePort" }).Count
        FindingCount                 = $findings.Count
        SeverityCounts               = $severityCounts
    }
    NetworkAdapters      = @($adapters)
    IPConfigurations     = @($ipConfigurations)
    DnsClientServers     = @($dnsServers)
    DefaultRoutes        = @($defaultRoutes)
    FirewallProfiles     = @($firewallProfiles)
    NetworkProfiles      = @($networkProfiles)
    InboundAllowFirewallRules = @($inboundAllowFirewallRules)
    ListeningTcpPorts    = @($listeningTcpPorts)
    ListeningUdpPorts    = @($listeningUdpPorts)
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
    Write-Host "Listening UDP ports: $($listeningUdpPorts.Count)"
    Write-Host "Findings: $($findings.Count)"
}
