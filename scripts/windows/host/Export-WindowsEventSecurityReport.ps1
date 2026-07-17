<#
.SYNOPSIS
Exports key Windows event log activity into CSV, JSON, and readable text reports.

.DESCRIPTION
The script reviews common security event IDs such as failed logons, account
lockouts, account changes, group changes, and service installation events.
It does not modify the system.

.PARAMETER Days
Number of days of event history to review. Default: 7

.PARAMETER OutputDirectory
Directory where events.csv, summary.json, and summary.txt are written.
Default: .\reports\windows-events-COMPUTER-TIMESTAMP

.EXAMPLE
.\Export-WindowsEventSecurityReport.ps1 -Days 7

Export the last 7 days of selected Security and System events.

.EXAMPLE
.\Export-WindowsEventSecurityReport.ps1

Run with the default 7-day window and default report directory.

.EXAMPLE
.\Export-WindowsEventSecurityReport.ps1 -Days 30 -OutputDirectory .\reports\server01-events

Export the last 30 days to a known report directory.
#>

[CmdletBinding()]
param(
    [int]$Days = 7,
    [string]$OutputDirectory = ".\reports\windows-events-$env:COMPUTERNAME-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function New-Directory {
    param([string]$Path)
    if (-not (Test-Path -Path $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
}

function Get-EventDataMap {
    param([System.Diagnostics.Eventing.Reader.EventRecord]$Event)

    $map = [ordered]@{}
    try {
        [xml]$xml = $Event.ToXml()
        foreach ($data in $xml.Event.EventData.Data) {
            $name = $data.Name
            if ($name) {
                $map[$name] = $data.'#text'
            }
        }
    }
    catch {
        $map["ParseError"] = $_.Exception.Message
    }
    return $map
}

function Read-Events {
    param(
        [string]$LogName,
        [int[]]$Ids,
        [datetime]$StartTime
    )

    try {
        Get-WinEvent -FilterHashtable @{ LogName = $LogName; Id = $Ids; StartTime = $StartTime } -ErrorAction Stop
    }
    catch {
        Write-Warning "Could not read $LogName events $($Ids -join ','): $($_.Exception.Message)"
        @()
    }
}

function Get-EventMetadata {
    param([int]$Id)

    $metadata = @{
        4624 = @{ Label = "Successful logon"; Severity = "Info"; Why = "Shows successful access and can help trace user/session activity." }
        4625 = @{ Label = "Failed logon"; Severity = "Medium"; Why = "Repeated failures can indicate password spray, brute force, stale services, or user lockout risk." }
        4634 = @{ Label = "Logoff"; Severity = "Info"; Why = "Shows session termination activity." }
        4648 = @{ Label = "Explicit credential logon"; Severity = "Medium"; Why = "May indicate run-as, remote access, scheduled tasks, or credential use that deserves review." }
        4672 = @{ Label = "Special privileges assigned"; Severity = "Medium"; Why = "Indicates an account logged on with administrative or sensitive privileges." }
        4720 = @{ Label = "User account created"; Severity = "High"; Why = "New accounts should be authorized and traceable." }
        4722 = @{ Label = "User account enabled"; Severity = "Medium"; Why = "Enabled accounts can restore access and should be expected." }
        4725 = @{ Label = "User account disabled"; Severity = "Info"; Why = "Account disable activity is useful for access lifecycle review." }
        4726 = @{ Label = "User account deleted"; Severity = "High"; Why = "Account deletion can remove access or cover tracks." }
        4728 = @{ Label = "Member added to global security group"; Severity = "High"; Why = "Security group membership can grant important access." }
        4732 = @{ Label = "Member added to local security group"; Severity = "High"; Why = "Local group membership can grant administrative or application access." }
        4740 = @{ Label = "User account locked out"; Severity = "Medium"; Why = "Lockouts can indicate password attacks or broken automation." }
        4756 = @{ Label = "Member added to universal security group"; Severity = "High"; Why = "Universal group membership can grant broad access." }
        7045 = @{ Label = "Service installed"; Severity = "High"; Why = "New services can indicate software installation, persistence, or administrative changes." }
    }

    if ($metadata.ContainsKey($Id)) {
        return $metadata[$Id]
    }

    return @{ Label = "Tracked event"; Severity = "Info"; Why = "Tracked by this report." }
}

function Get-RegexValue {
    param(
        [AllowNull()][string]$Text,
        [Parameter(Mandatory = $true)][string]$Pattern
    )

    if ($Text -and $Text -match $Pattern) {
        return $Matches[1].Trim()
    }

    return $null
}

function New-EventReportRecord {
    param(
        [Parameter(Mandatory = $true)][System.Diagnostics.Eventing.Reader.EventRecord]$Event,
        [Parameter(Mandatory = $true)][string]$LogName,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Data
    )

    $metadata = Get-EventMetadata -Id $Event.Id
    $message = ($Event.Message -replace "`r?`n", " ")
    $processName = Get-RegexValue -Text $message -Pattern "Process Name:\s+([^\r\n]+?)(?:\s{2,}|Network Information:|$)"
    $processId = Get-RegexValue -Text $message -Pattern "Process ID:\s+([^\s]+)"
    $targetServer = Get-RegexValue -Text $message -Pattern "Target Server Name:\s+([^\r\n]+?)(?:\s{2,}|Additional Information:|$)"
    $serviceFileName = Get-RegexValue -Text $message -Pattern "Service File Name:\s+([^\r\n]+?)(?:\s{2,}|Service Type:|$)"
    $serviceAccount = Get-RegexValue -Text $message -Pattern "Service Account:\s+([^\r\n]+)$"

    [pscustomobject][ordered]@{
        TimeCreated      = $Event.TimeCreated
        LogName          = $LogName
        Id               = $Event.Id
        EventLabel       = $metadata.Label
        TriageSeverity   = $metadata.Severity
        WhyItMatters     = $metadata.Why
        ProviderName     = $Event.ProviderName
        MachineName      = $Event.MachineName
        TargetUserName   = $Data["TargetUserName"]
        TargetDomainName = $Data["TargetDomainName"]
        SubjectUserName  = $Data["SubjectUserName"]
        IpAddress        = $Data["IpAddress"]
        WorkstationName  = $Data["WorkstationName"]
        LogonType        = $Data["LogonType"]
        Status           = $Data["Status"]
        SubStatus        = $Data["SubStatus"]
        ServiceName      = $Data["ServiceName"]
        ProcessName      = $processName
        ProcessId        = $processId
        TargetServer     = $targetServer
        ServiceFileName  = $serviceFileName
        ServiceAccount   = $serviceAccount
        Message          = $message
    }
}

function New-EventCountSummary {
    param([object[]]$Records)

    @($Records | Group-Object Id | Sort-Object Name | ForEach-Object {
            $id = [int]$_.Name
            $metadata = Get-EventMetadata -Id $id
            [pscustomobject][ordered]@{
                Id             = $id
                EventLabel     = $metadata.Label
                TriageSeverity = $metadata.Severity
                Count          = $_.Count
            }
        })
}

function New-NameCountSummary {
    param(
        [object[]]$Records,
        [string]$PropertyName,
        [int]$First = 20
    )

    @($Records | Where-Object { $_.$PropertyName } | Group-Object $PropertyName | Sort-Object Count -Descending | Select-Object -First $First | ForEach-Object {
            [pscustomobject][ordered]@{
                Name  = $_.Name
                Count = $_.Count
            }
        })
}

function New-InvestigationFinding {
    param(
        [string]$FindingId = "",
        [string]$Severity,
        [string]$Title,
        [string]$WhyItMatters,
        [string]$Recommendation,
        [string]$Evidence,
        [int[]]$EventIds = @(),
        [string]$EventCategory = ""
    )

    [pscustomobject][ordered]@{
        FindingId      = $FindingId
        FindingType    = "WindowsEventSecurityIndicator"
        EventCategory  = $EventCategory
        EventIds       = @($EventIds)
        Severity       = $Severity
        Title          = $Title
        WhyItMatters   = $WhyItMatters
        Recommendation = $Recommendation
        Evidence       = $Evidence
    }
}

function Test-SuspiciousServiceInstallPath {
    param([AllowNull()][string]$ServiceFileName)

    if ([string]::IsNullOrWhiteSpace($ServiceFileName)) {
        return $false
    }

    return [bool]($ServiceFileName -match '(?i)(\\Users\\Public\\|\\AppData\\Local\\Temp\\|\\Windows\\Temp\\|%TEMP%|\\powershell(?:\.exe)?\b|\\pwsh(?:\.exe)?\b|\\cmd\.exe\s+/c\b|\\mshta\.exe\b|\\wscript\.exe\b|\\cscript\.exe\b|\\rundll32\.exe\b|\\regsvr32\.exe\b|^\\\\)')
}

function New-InvestigationSummary {
    param([object[]]$Records)

    $findings = New-Object System.Collections.Generic.List[object]
    $failedLogons = @($Records | Where-Object { $_.Id -eq 4625 })
    $accountChanges = @($Records | Where-Object { $_.Id -in 4720, 4722, 4725, 4726 })
    $groupChanges = @($Records | Where-Object { $_.Id -in 4728, 4732, 4756 })
    $lockouts = @($Records | Where-Object { $_.Id -eq 4740 })
    $serviceInstalls = @($Records | Where-Object { $_.Id -eq 7045 })
    $rdpLogons = @($Records | Where-Object { $_.Id -eq 4624 -and $_.LogonType -eq "10" })
    $networkLogons = @($Records | Where-Object { $_.Id -eq 4624 -and $_.LogonType -eq "3" })
    $explicitCredentials = @($Records | Where-Object { $_.Id -eq 4648 })
    $suspiciousExplicitProcesses = @($explicitCredentials | Where-Object {
            $_.ProcessName -match "\\(cmd|powershell|pwsh|wscript|cscript|rundll32|regsvr32|mshta|psexec|wmic)\.exe$"
        })

    if ($failedLogons.Count -gt 0) {
        $topSources = @(New-NameCountSummary -Records $failedLogons -PropertyName "IpAddress" -First 5 | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join "; "
        $findings.Add((New-InvestigationFinding -FindingId "FAILED-LOGONS" -EventIds @(4625) -EventCategory "Authentication failure" -Severity "High" -Title "Failed logons were detected" -WhyItMatters "Failed logons can indicate password spray, brute force, stale services, or user mistakes." -Recommendation "Review top source IPs and target users. Confirm whether activity is expected." -Evidence "Count=$($failedLogons.Count); TopSources=$topSources")) | Out-Null
    }

    if ($accountChanges.Count -gt 0) {
        $findings.Add((New-InvestigationFinding -FindingId "ACCOUNT-LIFECYCLE-CHANGES" -EventIds @(4720, 4722, 4725, 4726) -EventCategory "Account lifecycle" -Severity "High" -Title "Account lifecycle changes were detected" -WhyItMatters "New, enabled, disabled, or deleted accounts can be legitimate admin work or attacker persistence/cleanup." -Recommendation "Confirm every account change has a ticket, admin owner, and expected timestamp." -Evidence "Count=$($accountChanges.Count)")) | Out-Null
    }

    if ($groupChanges.Count -gt 0) {
        $findings.Add((New-InvestigationFinding -FindingId "SECURITY-GROUP-CHANGES" -EventIds @(4728, 4732, 4756) -EventCategory "Group membership" -Severity "High" -Title "Security group membership changes were detected" -WhyItMatters "Security group changes can grant privileged or application access." -Recommendation "Review changed groups and confirm the requester/approver." -Evidence "Count=$($groupChanges.Count)")) | Out-Null
    }

    if ($lockouts.Count -gt 0) {
        $findings.Add((New-InvestigationFinding -FindingId "ACCOUNT-LOCKOUTS" -EventIds @(4740) -EventCategory "Account lockout" -Severity "Medium" -Title "Account lockouts were detected" -WhyItMatters "Lockouts can indicate password attacks or broken services using old credentials." -Recommendation "Review locked accounts and source machines." -Evidence "Count=$($lockouts.Count)")) | Out-Null
    }

    if ($serviceInstalls.Count -gt 0) {
        $suspiciousServiceInstalls = @($serviceInstalls | Where-Object { Test-SuspiciousServiceInstallPath -ServiceFileName $_.ServiceFileName })
        $serviceSeverity = if ($suspiciousServiceInstalls.Count -gt 0) { "High" } else { "Medium" }
        $serviceTitle = if ($suspiciousServiceInstalls.Count -gt 0) { "Potentially suspicious service installation events require review" } else { "Service installation events require review" }
        $firstObserved = @($serviceInstalls | Sort-Object -Property TimeCreated | Select-Object -First 1)
        $lastObserved = @($serviceInstalls | Sort-Object -Property TimeCreated -Descending | Select-Object -First 1)
        $firstObservedUtc = if ($firstObserved.Count -gt 0) { ConvertTo-ReportTime -Value $firstObserved[0].TimeCreated } else { "unknown" }
        $lastObservedUtc = if ($lastObserved.Count -gt 0) { ConvertTo-ReportTime -Value $lastObserved[0].TimeCreated } else { "unknown" }
        $services = @($serviceInstalls | Select-Object -First 10 | ForEach-Object { "$($_.ServiceName) [$($_.ServiceFileName)]" }) -join "; "
        $findings.Add((New-InvestigationFinding -FindingId "SERVICE-INSTALLATIONS" -EventIds @(7045) -EventCategory "Service installation" -Severity $serviceSeverity -Title $serviceTitle -WhyItMatters "Service installation events can represent normal software deployment or persistence. Severity is raised only when the service image path matches a bounded suspicious-path heuristic." -Recommendation "Verify service name, timestamp, file path, signature, vendor, and change ticket." -Evidence "Count=$($serviceInstalls.Count); WindowDays=$Days; FirstObservedUtc=$firstObservedUtc; LastObservedUtc=$lastObservedUtc; SuspiciousPathCount=$($suspiciousServiceInstalls.Count); Services=$services")) | Out-Null
    }

    if ($rdpLogons.Count -gt 0) {
        $sources = @(New-NameCountSummary -Records $rdpLogons -PropertyName "IpAddress" -First 10 | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join "; "
        $findings.Add((New-InvestigationFinding -FindingId "RDP-LOGONS" -EventIds @(4624) -EventCategory "Remote interactive logon" -Severity "High" -Title "RDP logons were detected" -WhyItMatters "RDP logons should be expected, authorized, and restricted to trusted sources." -Recommendation "Review source IPs, users, and timestamps for unexpected access." -Evidence "Count=$($rdpLogons.Count); Sources=$sources")) | Out-Null
    }

    if ($suspiciousExplicitProcesses.Count -gt 0) {
        $processes = @(New-NameCountSummary -Records $suspiciousExplicitProcesses -PropertyName "ProcessName" -First 10 | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join "; "
        $findings.Add((New-InvestigationFinding -FindingId "SUSPICIOUS-EXPLICIT-CREDENTIALS" -EventIds @(4648) -EventCategory "Explicit credential use" -Severity "High" -Title "Explicit credentials used by suspicious process names" -WhyItMatters "Credential use from command/scripting tools is more suspicious than normal application authentication." -Recommendation "Review command history, process lineage, and whether the admin expected this activity." -Evidence "Count=$($suspiciousExplicitProcesses.Count); Processes=$processes")) | Out-Null
    }

    if ($explicitCredentials.Count -gt 0 -and $suspiciousExplicitProcesses.Count -eq 0) {
        $topProcesses = @(New-NameCountSummary -Records $explicitCredentials -PropertyName "ProcessName" -First 5 | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join "; "
        $topTargets = @(New-NameCountSummary -Records $explicitCredentials -PropertyName "TargetServer" -First 5 | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join "; "
        $findings.Add((New-InvestigationFinding -FindingId "EXPLICIT-CREDENTIAL-USE" -EventIds @(4648) -EventCategory "Explicit credential use" -Severity "Info" -Title "Explicit credential use was detected" -WhyItMatters "Explicit credential events are common for Outlook, scheduled tasks, run-as, and services, but should match expected applications." -Recommendation "Confirm top processes and target servers are expected." -Evidence "Count=$($explicitCredentials.Count); TopProcesses=$topProcesses; TopTargets=$topTargets")) | Out-Null
    }

    $criticalCount = @($findings.ToArray() | Where-Object { $_.Severity -eq "Critical" }).Count
    $highCount = @($findings.ToArray() | Where-Object { $_.Severity -eq "High" }).Count
    $mediumCount = @($findings.ToArray() | Where-Object { $_.Severity -eq "Medium" }).Count
    $verdict = "No obvious attack indicators found"
    if ($criticalCount -gt 0 -or $highCount -gt 0) {
        $verdict = "Review high-priority indicators"
    }
    elseif ($mediumCount -gt 0) {
        $verdict = "Review recommended"
    }

    [ordered]@{
        Verdict = $verdict
        CriticalCount = $criticalCount
        HighCount = $highCount
        MediumCount = $mediumCount
        FindingCount = $findings.Count
        Findings = @($findings.ToArray())
        QuickHowToRead = @(
            "Start with Verdict and Findings.",
            "High does not always mean attack; it means an administrator should verify it.",
            "A likely attack usually has combinations: failed logons, unexpected RDP, account/group changes, suspicious service install, or explicit credentials from scripting tools."
        )
    }
}

function ConvertTo-ReportTime {
    param([AllowNull()]$Value)

    if ($null -eq $Value) {
        return $null
    }

    if ($Value -is [datetime]) {
        return $Value.ToUniversalTime().ToString("o")
    }

    return [string]$Value
}

function Format-ReportValue {
    param([AllowNull()]$Value)

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        return "-"
    }

    return [string]$Value
}

function New-EventBrief {
    param([Parameter(Mandatory = $true)]$Record)

    [pscustomobject][ordered]@{
        TimeCreated    = ConvertTo-ReportTime -Value $Record.TimeCreated
        LogName        = $Record.LogName
        Id             = $Record.Id
        EventLabel     = $Record.EventLabel
        TriageSeverity = $Record.TriageSeverity
        TargetUserName = $Record.TargetUserName
        SubjectUserName = $Record.SubjectUserName
        IpAddress      = $Record.IpAddress
        ServiceName    = $Record.ServiceName
        ServiceFileName = $Record.ServiceFileName
        Message        = $Record.Message
    }
}

function Add-ReportLine {
    param(
        [Parameter(Mandatory = $true)][System.Text.StringBuilder]$Builder,
        [AllowNull()][string]$Text = ""
    )

    [void]$Builder.AppendLine($Text)
}

function New-ReadableEventSummary {
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Summary)

    $builder = New-Object System.Text.StringBuilder
    $investigation = $Summary["InvestigationSummary"]

    Add-ReportLine -Builder $builder -Text "Windows Event Security Report"
    Add-ReportLine -Builder $builder -Text "Computer: $(Format-ReportValue -Value $Summary["ComputerName"])"
    Add-ReportLine -Builder $builder -Text "Generated UTC: $(Format-ReportValue -Value $Summary["GeneratedAtUtc"])"
    Add-ReportLine -Builder $builder -Text "Period start UTC: $(Format-ReportValue -Value $Summary["StartTimeUtc"])"
    Add-ReportLine -Builder $builder -Text "Days reviewed: $(Format-ReportValue -Value $Summary["Days"])"
    Add-ReportLine -Builder $builder -Text "Total tracked events: $(Format-ReportValue -Value $Summary["TotalEvents"])"
    Add-ReportLine -Builder $builder
    Add-ReportLine -Builder $builder -Text "Verdict: $(Format-ReportValue -Value $investigation["Verdict"])"
    Add-ReportLine -Builder $builder -Text "Findings: $(Format-ReportValue -Value $investigation["FindingCount"]) total, High=$($investigation["HighCount"]), Medium=$($investigation["MediumCount"])"
    Add-ReportLine -Builder $builder

    Add-ReportLine -Builder $builder -Text "What to review first"
    $findings = @($investigation["Findings"])
    if ($findings.Count -eq 0) {
        Add-ReportLine -Builder $builder -Text "- No obvious attack indicators were found in the tracked event IDs."
    }
    else {
        foreach ($finding in $findings) {
            Add-ReportLine -Builder $builder -Text "- [$($finding.Severity)] $($finding.Title)"
            Add-ReportLine -Builder $builder -Text "  Why: $($finding.WhyItMatters)"
            Add-ReportLine -Builder $builder -Text "  Action: $($finding.Recommendation)"
            Add-ReportLine -Builder $builder -Text "  Evidence: $($finding.Evidence)"
        }
    }

    Add-ReportLine -Builder $builder
    Add-ReportLine -Builder $builder -Text "Event counts"
    foreach ($count in @($Summary["CountsByEventId"])) {
        Add-ReportLine -Builder $builder -Text "- $($count.Id) $($count.EventLabel) [$($count.TriageSeverity)]: $($count.Count)"
    }

    Add-ReportLine -Builder $builder
    Add-ReportLine -Builder $builder -Text "High-priority recent events"
    $highEvents = @($Summary["RecentHighSeverityEvents"])
    if ($highEvents.Count -eq 0) {
        Add-ReportLine -Builder $builder -Text "- None found."
    }
    else {
        foreach ($event in @($highEvents | Select-Object -First 20)) {
            $detail = "User=$(Format-ReportValue -Value $event.TargetUserName); Subject=$(Format-ReportValue -Value $event.SubjectUserName); Source=$(Format-ReportValue -Value $event.IpAddress); Service=$(Format-ReportValue -Value $event.ServiceName)"
            Add-ReportLine -Builder $builder -Text "- $($event.TimeCreated) $($event.Id) $($event.EventLabel): $detail"
        }
    }

    Add-ReportLine -Builder $builder
    Add-ReportLine -Builder $builder -Text "How to decide if it is critical"
    foreach ($note in @($investigation["QuickHowToRead"])) {
        Add-ReportLine -Builder $builder -Text "- $note"
    }

    Add-ReportLine -Builder $builder
    Add-ReportLine -Builder $builder -Text "Files"
    Add-ReportLine -Builder $builder -Text "- events.csv has one row per event with parsed columns and raw message evidence."
    Add-ReportLine -Builder $builder -Text "- summary.json has the same information for automation or deeper filtering."

    return $builder.ToString()
}

New-Directory -Path $OutputDirectory
$startTime = (Get-Date).AddDays(-1 * [Math]::Abs($Days))

$securityIds = @(4624, 4625, 4634, 4648, 4672, 4720, 4722, 4725, 4726, 4728, 4732, 4740, 4756)
$systemIds = @(7045)

$records = New-Object System.Collections.Generic.List[object]

foreach ($event in (Read-Events -LogName "Security" -Ids $securityIds -StartTime $startTime)) {
    $data = Get-EventDataMap -Event $event
    $records.Add((New-EventReportRecord -Event $event -LogName "Security" -Data $data)) | Out-Null
}

foreach ($event in (Read-Events -LogName "System" -Ids $systemIds -StartTime $startTime)) {
    $data = Get-EventDataMap -Event $event
    $records.Add((New-EventReportRecord -Event $event -LogName "System" -Data $data)) | Out-Null
}

$csvPath = Join-Path -Path $OutputDirectory -ChildPath "events.csv"
$jsonPath = Join-Path -Path $OutputDirectory -ChildPath "summary.json"
$textPath = Join-Path -Path $OutputDirectory -ChildPath "summary.txt"

$recordRows = @($records.ToArray())
$recordRows | Sort-Object TimeCreated -Descending | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

$summary = [ordered]@{
    ComputerName = $env:COMPUTERNAME
    GeneratedAtUtc = (Get-Date).ToUniversalTime().ToString("o")
    StartTimeUtc = $startTime.ToUniversalTime().ToString("o")
    Days = $Days
    TotalEvents = $recordRows.Count
    InvestigationSummary = New-InvestigationSummary -Records $recordRows
    CountsByEventId = @(New-EventCountSummary -Records $recordRows)
    FailedLogonsTopUsers = @($recordRows | Where-Object { $_.Id -eq 4625 -and $_.TargetUserName } | Group-Object TargetUserName | Sort-Object Count -Descending | Select-Object -First 20 Name, Count)
    FailedLogonsTopSources = @($recordRows | Where-Object { $_.Id -eq 4625 -and $_.IpAddress } | Group-Object IpAddress | Sort-Object Count -Descending | Select-Object -First 20 Name, Count)
    PrivilegedLogonsTopUsers = @($recordRows | Where-Object { $_.Id -eq 4672 -and $_.SubjectUserName } | Group-Object SubjectUserName | Sort-Object Count -Descending | Select-Object -First 20 Name, Count)
    ExplicitCredentialTopProcesses = @(New-NameCountSummary -Records @($recordRows | Where-Object { $_.Id -eq 4648 }) -PropertyName "ProcessName")
    ExplicitCredentialTopTargets = @(New-NameCountSummary -Records @($recordRows | Where-Object { $_.Id -eq 4648 }) -PropertyName "TargetServer")
    RdpLogonTopSources = @(New-NameCountSummary -Records @($recordRows | Where-Object { $_.Id -eq 4624 -and $_.LogonType -eq "10" }) -PropertyName "IpAddress")
    NetworkLogonTopSources = @(New-NameCountSummary -Records @($recordRows | Where-Object { $_.Id -eq 4624 -and $_.LogonType -eq "3" }) -PropertyName "IpAddress")
    RecentHighSeverityEvents = @($recordRows | Where-Object { $_.TriageSeverity -eq "High" } | Sort-Object TimeCreated -Descending | Select-Object -First 50 | ForEach-Object { New-EventBrief -Record $_ })
    ServiceInstallations = @($recordRows | Where-Object { $_.Id -eq 7045 } | Sort-Object TimeCreated -Descending | ForEach-Object { New-EventBrief -Record $_ })
    Notes = @(
        "TriageSeverity is a review priority for this report, not proof of malicious activity.",
        "Review failed logons, account/group changes, privileged logons, and service installations first.",
        "CSV contains one row per event with EventLabel, TriageSeverity, WhyItMatters, and raw message evidence."
    )
}

$summary | ConvertTo-Json -Depth 6 | Out-File -FilePath $jsonPath -Encoding UTF8
New-ReadableEventSummary -Summary $summary | Out-File -FilePath $textPath -Encoding UTF8

Write-Host "Event CSV written to: $csvPath"
Write-Host "Summary JSON written to: $jsonPath"
Write-Host "Readable summary written to: $textPath"
Write-Host "Events exported: $($records.Count)"
