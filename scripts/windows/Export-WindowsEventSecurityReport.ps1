<#
.SYNOPSIS
Exports key Windows event log activity into CSV and JSON reports.

.DESCRIPTION
The script reviews common security event IDs such as failed logons, account
lockouts, account changes, group changes, and service installation events.
It does not modify the system.

.EXAMPLE
.\Export-WindowsEventSecurityReport.ps1 -Days 7
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

New-Directory -Path $OutputDirectory
$startTime = (Get-Date).AddDays(-1 * [Math]::Abs($Days))

$securityIds = @(4624, 4625, 4634, 4648, 4672, 4720, 4722, 4725, 4726, 4728, 4732, 4740, 4756)
$systemIds = @(7045)

$records = New-Object System.Collections.Generic.List[object]

foreach ($event in (Read-Events -LogName "Security" -Ids $securityIds -StartTime $startTime)) {
    $data = Get-EventDataMap -Event $event
    $records.Add([ordered]@{
        TimeCreated = $event.TimeCreated
        LogName = "Security"
        Id = $event.Id
        ProviderName = $event.ProviderName
        MachineName = $event.MachineName
        TargetUserName = $data["TargetUserName"]
        TargetDomainName = $data["TargetDomainName"]
        SubjectUserName = $data["SubjectUserName"]
        IpAddress = $data["IpAddress"]
        WorkstationName = $data["WorkstationName"]
        LogonType = $data["LogonType"]
        Status = $data["Status"]
        SubStatus = $data["SubStatus"]
        ServiceName = $null
        Message = ($event.Message -replace "`r?`n", " ")
    }) | Out-Null
}

foreach ($event in (Read-Events -LogName "System" -Ids $systemIds -StartTime $startTime)) {
    $data = Get-EventDataMap -Event $event
    $records.Add([ordered]@{
        TimeCreated = $event.TimeCreated
        LogName = "System"
        Id = $event.Id
        ProviderName = $event.ProviderName
        MachineName = $event.MachineName
        TargetUserName = $null
        TargetDomainName = $null
        SubjectUserName = $null
        IpAddress = $null
        WorkstationName = $null
        LogonType = $null
        Status = $null
        SubStatus = $null
        ServiceName = $data["ServiceName"]
        Message = ($event.Message -replace "`r?`n", " ")
    }) | Out-Null
}

$csvPath = Join-Path -Path $OutputDirectory -ChildPath "events.csv"
$jsonPath = Join-Path -Path $OutputDirectory -ChildPath "summary.json"

$records | Sort-Object TimeCreated -Descending | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

$summary = [ordered]@{
    ComputerName = $env:COMPUTERNAME
    GeneratedAtUtc = (Get-Date).ToUniversalTime().ToString("o")
    StartTime = $startTime
    Days = $Days
    TotalEvents = $records.Count
    CountsByEventId = @($records | Group-Object Id | Sort-Object Name | Select-Object Name, Count)
    FailedLogonsTopUsers = @($records | Where-Object { $_.Id -eq 4625 -and $_.TargetUserName } | Group-Object TargetUserName | Sort-Object Count -Descending | Select-Object -First 20 Name, Count)
    FailedLogonsTopSources = @($records | Where-Object { $_.Id -eq 4625 -and $_.IpAddress } | Group-Object IpAddress | Sort-Object Count -Descending | Select-Object -First 20 Name, Count)
    ServiceInstallations = @($records | Where-Object { $_.Id -eq 7045 } | Select-Object TimeCreated, ServiceName, Message)
}

$summary | ConvertTo-Json -Depth 6 | Out-File -FilePath $jsonPath -Encoding UTF8

Write-Host "Event CSV written to: $csvPath"
Write-Host "Summary JSON written to: $jsonPath"
Write-Host "Events exported: $($records.Count)"
