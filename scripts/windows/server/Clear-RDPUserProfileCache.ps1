<#
.SYNOPSIS
Safely audits and optionally cleans per-user cache folders on RDP/Terminal Server hosts.

.DESCRIPTION
This script enumerates local user profiles, identifies known high-volume cache
locations, and writes a JSON report. It runs in dry-run mode by default.

The script is intentionally conservative for production RDP servers:

- It never deletes whole browser profiles.
- It targets cache, code-cache, GPU-cache, crash dump, and bitmap-cache data.
- It skips loaded profiles by default to avoid touching active RDP sessions.
- It requires -Apply before deleting files.
- It only deletes files older than -MinimumAgeDays.
- Recycle Bin and Temp cleanup are opt-in.

.PARAMETER ProfileRoot
Root directory that contains local user profiles. Default: C:\Users

.PARAMETER MinimumAgeDays
Deletes or reports only files older than this many days. Minimum value: 1.
Default: 14

.PARAMETER ReportPath
Path for the JSON cleanup report. The parent directory is created when needed.
Default: .\reports\rdp-profile-cache-cleanup-COMPUTER-TIMESTAMP.json

.PARAMETER Apply
Deletes eligible files. Without this switch, the script runs in dry-run mode and
only reports candidates.

.PARAMETER IncludeLoadedProfiles
Includes profiles that are currently loaded. By default, loaded profiles are
skipped to avoid active RDP user sessions.

.PARAMETER IncludeRecycleBin
Includes each user's Recycle Bin under C:\$Recycle.Bin when available.

.PARAMETER IncludeTemp
Includes per-user AppData\Local\Temp cleanup.

.PARAMETER ExcludeProfileName
Profile folder names to skip. Defaults include system and public profile names.

.EXAMPLE
.\Clear-RDPUserProfileCache.ps1

Preview cleanup candidates and write a report.

.EXAMPLE
.\Clear-RDPUserProfileCache.ps1 -MinimumAgeDays 30 -IncludeRecycleBin

Preview cache and Recycle Bin cleanup candidates older than 30 days.

.EXAMPLE
.\Clear-RDPUserProfileCache.ps1 -Apply -MinimumAgeDays 30

Delete eligible cache files from unloaded user profiles.

.EXAMPLE
.\Clear-RDPUserProfileCache.ps1 -ProfileRoot D:\Users -MinimumAgeDays 45 -ReportPath .\reports\terminal01-cache.json

Preview cleanup against a non-default profile root and write the report to a
known path.

.EXAMPLE
.\Clear-RDPUserProfileCache.ps1 -MinimumAgeDays 30 -IncludeTemp -IncludeRecycleBin

Preview cache, Temp, and Recycle Bin cleanup candidates.

.EXAMPLE
.\Clear-RDPUserProfileCache.ps1 -Apply -MinimumAgeDays 30 -IncludeLoadedProfiles

Apply cleanup to eligible files even when profiles are loaded. Use only during a
maintenance window after confirming active user impact.

.EXAMPLE
.\Clear-RDPUserProfileCache.ps1 -ExcludeProfileName "Default","Public","admin-template"

Preview cleanup while excluding additional profile names.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
param(
    [string]$ProfileRoot = "C:\Users",
    [int]$MinimumAgeDays = 14,
    [string]$ReportPath = ".\reports\rdp-profile-cache-cleanup-$env:COMPUTERNAME-$(Get-Date -Format 'yyyyMMdd-HHmmss').json",
    [switch]$Apply,
    [switch]$IncludeLoadedProfiles,
    [switch]$IncludeRecycleBin,
    [switch]$IncludeTemp,
    [string[]]$ExcludeProfileName = @("Default", "Default User", "Public", "All Users", ".NET v4.5 Classic")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($MinimumAgeDays -lt 1) {
    throw "MinimumAgeDays must be 1 or greater."
}

$Cutoff = (Get-Date).AddDays(-1 * $MinimumAgeDays)
$Results = New-Object System.Collections.Generic.List[object]

function New-ParentDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)

    $parent = Split-Path -Path $Path -Parent
    if ($parent -and -not (Test-Path -Path $parent)) {
        New-Item -Path $parent -ItemType Directory -Force | Out-Null
    }
}

function Test-ProfilePathUnderRoot {
    param(
        [Parameter(Mandatory = $true)][string]$ProfilePath,
        [Parameter(Mandatory = $true)][string]$RootPath
    )

    $normalizedProfile = $ProfilePath.TrimEnd("\").ToLowerInvariant()
    $normalizedRoot = $RootPath.TrimEnd("\").ToLowerInvariant()

    return $normalizedProfile -eq $normalizedRoot -or $normalizedProfile.StartsWith("$normalizedRoot\")
}

function Get-LocalUserProfiles {
    $profiles = @(Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop | Where-Object {
            -not $_.Special -and
            $_.LocalPath -and
            (Test-ProfilePathUnderRoot -ProfilePath ([string]$_.LocalPath) -RootPath $ProfileRoot) -and
            (Test-Path -LiteralPath $_.LocalPath)
        })

    foreach ($userProfile in $profiles) {
        $name = Split-Path -Path $userProfile.LocalPath -Leaf
        if ($ExcludeProfileName -contains $name) {
            continue
        }

        [ordered]@{
            Name      = $name
            Path      = $userProfile.LocalPath
            Sid       = $userProfile.SID
            Loaded    = [bool]$userProfile.Loaded
            SkipReason = if ($userProfile.Loaded -and -not $IncludeLoadedProfiles) { "Profile is currently loaded. Use -IncludeLoadedProfiles to include it." } else { $null }
        }
    }
}

function Join-ProfilePath {
    param(
        [Parameter(Mandatory = $true)][string]$ProfilePath,
        [Parameter(Mandatory = $true)][string]$RelativePath
    )

    Join-Path -Path $ProfilePath -ChildPath $RelativePath
}

function Get-ExistingTarget {
    param(
        [Parameter(Mandatory = $true)][string]$ProfilePath,
        [Parameter(Mandatory = $true)][string]$RelativePath,
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$SafetyNote
    )

    $path = Join-ProfilePath -ProfilePath $ProfilePath -RelativePath $RelativePath
    if (Test-Path -LiteralPath $path -PathType Container) {
        [ordered]@{
            Category = $Category
            Path     = $path
            SafetyNote = $SafetyNote
        }
    }
}

function Get-WildcardTargets {
    param(
        [Parameter(Mandatory = $true)][string]$ProfilePath,
        [Parameter(Mandatory = $true)][string]$RelativePattern,
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$SafetyNote
    )

    $pattern = Join-ProfilePath -ProfilePath $ProfilePath -RelativePath $RelativePattern
    foreach ($target in @(Get-ChildItem -Path $pattern -Directory -Force -ErrorAction SilentlyContinue)) {
        if ($target.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            continue
        }

        [ordered]@{
            Category = $Category
            Path     = $target.FullName
            SafetyNote = $SafetyNote
        }
    }
}

function Get-CleanupTargetsForProfile {
    param(
        [Parameter(Mandatory = $true)][string]$ProfilePath
    )

    $targets = New-Object System.Collections.Generic.List[object]

    $relativeTargets = @(
        @{
            Category = "Office solution package cache"
            Path = "AppData\Local\Microsoft\Office\SolutionPackages"
            SafetyNote = "Deletes old cached Office solution package files only."
        },
        @{
            Category = "Teams WebView2 cache"
            Path = "AppData\Local\Microsoft\MSTeams\EBWebView\Default\Cache"
            SafetyNote = "Deletes old Teams WebView2 browser cache files only."
        },
        @{
            Category = "Teams WebView2 code cache"
            Path = "AppData\Local\Microsoft\MSTeams\EBWebView\Default\Code Cache"
            SafetyNote = "Deletes old Teams WebView2 code cache files only."
        },
        @{
            Category = "Teams WebView2 GPU cache"
            Path = "AppData\Local\Microsoft\MSTeams\EBWebView\Default\GPUCache"
            SafetyNote = "Deletes old Teams WebView2 GPU cache files only."
        },
        @{
            Category = "Teams WebView2 service worker cache"
            Path = "AppData\Local\Microsoft\MSTeams\EBWebView\Default\Service Worker\CacheStorage"
            SafetyNote = "Deletes old Teams WebView2 service worker cache files only."
        },
        @{
            Category = "Crash dumps"
            Path = "AppData\Local\CrashDumps"
            SafetyNote = "Deletes old local application crash dump files."
        },
        @{
            Category = "Adobe Acrobat WebView2 cache"
            Path = "AppData\Local\Adobe\Acrobat\AVWebview2\DC\EBWebView\Default\Cache"
            SafetyNote = "Deletes old Adobe Acrobat WebView2 cache files only."
        },
        @{
            Category = "Adobe Acrobat WebView2 code cache"
            Path = "AppData\Local\Adobe\Acrobat\AVWebview2\DC\EBWebView\Default\Code Cache"
            SafetyNote = "Deletes old Adobe Acrobat WebView2 code cache files only."
        },
        @{
            Category = "Adobe Acrobat WebView2 GPU cache"
            Path = "AppData\Local\Adobe\Acrobat\AVWebview2\DC\EBWebView\Default\GPUCache"
            SafetyNote = "Deletes old Adobe Acrobat WebView2 GPU cache files only."
        },
        @{
            Category = "Terminal Server Client bitmap cache"
            Path = "AppData\Local\Microsoft\Terminal Server Client\Cache"
            SafetyNote = "Deletes old RDP client bitmap cache files."
        },
        @{
            Category = "Office WEF WebView2 cache"
            Path = "AppData\Local\Microsoft\Office\16.0\Wef\webview2\Default\Cache"
            SafetyNote = "Deletes old Office add-in WebView2 cache files only."
        },
        @{
            Category = "Office WEF WebView2 code cache"
            Path = "AppData\Local\Microsoft\Office\16.0\Wef\webview2\Default\Code Cache"
            SafetyNote = "Deletes old Office add-in WebView2 code cache files only."
        },
        @{
            Category = "Office WEF WebView2 GPU cache"
            Path = "AppData\Local\Microsoft\Office\16.0\Wef\webview2\Default\GPUCache"
            SafetyNote = "Deletes old Office add-in WebView2 GPU cache files only."
        }
    )

    foreach ($item in $relativeTargets) {
        $target = Get-ExistingTarget -ProfilePath $ProfilePath -RelativePath $item.Path -Category $item.Category -SafetyNote $item.SafetyNote
        if ($target) {
            $targets.Add($target) | Out-Null
        }
    }

    $wildcardTargets = @(
        @{
            Category = "Chrome browser cache"
            Pattern = "AppData\Local\Google\Chrome\User Data\*\Cache"
            SafetyNote = "Deletes old Chrome cache files only. User profile data, cookies, history, and bookmarks are not targeted."
        },
        @{
            Category = "Chrome code cache"
            Pattern = "AppData\Local\Google\Chrome\User Data\*\Code Cache"
            SafetyNote = "Deletes old Chrome code cache files only."
        },
        @{
            Category = "Chrome GPU cache"
            Pattern = "AppData\Local\Google\Chrome\User Data\*\GPUCache"
            SafetyNote = "Deletes old Chrome GPU cache files only."
        },
        @{
            Category = "Chrome service worker cache"
            Pattern = "AppData\Local\Google\Chrome\User Data\*\Service Worker\CacheStorage"
            SafetyNote = "Deletes old Chrome service worker cache files only."
        },
        @{
            Category = "Edge browser cache"
            Pattern = "AppData\Local\Microsoft\Edge\User Data\*\Cache"
            SafetyNote = "Deletes old Edge cache files only. User profile data, cookies, history, and bookmarks are not targeted."
        },
        @{
            Category = "Edge code cache"
            Pattern = "AppData\Local\Microsoft\Edge\User Data\*\Code Cache"
            SafetyNote = "Deletes old Edge code cache files only."
        },
        @{
            Category = "Edge GPU cache"
            Pattern = "AppData\Local\Microsoft\Edge\User Data\*\GPUCache"
            SafetyNote = "Deletes old Edge GPU cache files only."
        },
        @{
            Category = "Edge service worker cache"
            Pattern = "AppData\Local\Microsoft\Edge\User Data\*\Service Worker\CacheStorage"
            SafetyNote = "Deletes old Edge service worker cache files only."
        },
        @{
            Category = "Firefox cache"
            Pattern = "AppData\Local\Mozilla\Firefox\Profiles\*\cache2"
            SafetyNote = "Deletes old Firefox cache files only. Browser profile data is not targeted."
        },
        @{
            Category = "Firefox startup cache"
            Pattern = "AppData\Local\Mozilla\Firefox\Profiles\*\startupCache"
            SafetyNote = "Deletes old Firefox startup cache files only."
        },
        @{
            Category = "Firefox thumbnails"
            Pattern = "AppData\Local\Mozilla\Firefox\Profiles\*\thumbnails"
            SafetyNote = "Deletes old Firefox thumbnail cache files only."
        }
    )

    foreach ($item in $wildcardTargets) {
        foreach ($target in @(Get-WildcardTargets -ProfilePath $ProfilePath -RelativePattern $item.Pattern -Category $item.Category -SafetyNote $item.SafetyNote)) {
            $targets.Add($target) | Out-Null
        }
    }

    if ($IncludeTemp) {
        $target = Get-ExistingTarget -ProfilePath $ProfilePath -RelativePath "AppData\Local\Temp" -Category "User temp files" -SafetyNote "Deletes old per-user temp files only."
        if ($target) {
            $targets.Add($target) | Out-Null
        }
    }

    return $targets
}

function Get-SafeFiles {
    param([Parameter(Mandatory = $true)][string]$RootPath)

    $stack = New-Object System.Collections.Generic.Stack[string]
    $stack.Push($RootPath)

    while ($stack.Count -gt 0) {
        $current = $stack.Pop()
        foreach ($item in @(Get-ChildItem -LiteralPath $current -Force -ErrorAction SilentlyContinue)) {
            if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                continue
            }

            if ($item.PSIsContainer) {
                $stack.Push($item.FullName)
            }
            else {
                $item
            }
        }
    }
}

function Get-MeasureSum {
    param(
        [Parameter(Mandatory = $true)][AllowNull()][object]$InputObject,
        [Parameter(Mandatory = $true)][string]$PropertyName,
        [Parameter(Mandatory = $true)][type]$OutputType
    )

    $sum = [double]0
    foreach ($item in @($InputObject)) {
        if ($null -eq $item) {
            continue
        }

        $value = $null
        if ($item -is [System.Collections.IDictionary]) {
            if ($item.Contains($PropertyName)) {
                $value = $item[$PropertyName]
            }
        }
        else {
            $property = $item.PSObject.Properties[$PropertyName]
            if ($property) {
                $value = $property.Value
            }
        }

        if ($null -ne $value) {
            $sum += [double]$value
        }
    }

    return $sum -as $OutputType
}

function Remove-EmptyDirectories {
    param([Parameter(Mandatory = $true)][string]$RootPath)

    $directories = @(Get-ChildItem -LiteralPath $RootPath -Directory -Force -Recurse -ErrorAction SilentlyContinue | Where-Object {
            -not ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint)
        } | Sort-Object FullName -Descending)

    foreach ($directory in $directories) {
        try {
            if (-not @(Get-ChildItem -LiteralPath $directory.FullName -Force -ErrorAction SilentlyContinue)) {
                if ($PSCmdlet.ShouldProcess($directory.FullName, "Remove empty cache directory")) {
                    Remove-Item -LiteralPath $directory.FullName -Force -ErrorAction Stop
                }
            }
        }
        catch {
            Write-Verbose "Could not remove empty directory $($directory.FullName): $($_.Exception.Message)"
        }
    }
}

function Measure-And-CleanTarget {
    param(
        [Parameter(Mandatory = $true)][object]$UserProfile,
        [Parameter(Mandatory = $true)][object]$Target
    )

    $candidateFiles = @(Get-SafeFiles -RootPath $Target.Path | Where-Object { $_.LastWriteTime -lt $Cutoff })
    $candidateBytes = Get-MeasureSum -InputObject $candidateFiles -PropertyName "Length" -OutputType ([int64])
    $deletedFiles = 0
    $deletedBytes = [int64]0
    $failedFiles = 0
    $failureSamples = New-Object System.Collections.Generic.List[string]

    foreach ($file in $candidateFiles) {
        if (-not $Apply) {
            continue
        }

        try {
            if ($PSCmdlet.ShouldProcess($file.FullName, "Delete cache file")) {
                $length = [int64]$file.Length
                Remove-Item -LiteralPath $file.FullName -Force -ErrorAction Stop
                $deletedFiles++
                $deletedBytes += $length
            }
        }
        catch {
            $failedFiles++
            if ($failureSamples.Count -lt 10) {
                $failureSamples.Add("$($file.FullName): $($_.Exception.Message)") | Out-Null
            }
        }
    }

    if ($Apply) {
        Remove-EmptyDirectories -RootPath $Target.Path
    }

    [ordered]@{
        ProfileName    = $UserProfile.Name
        ProfilePath    = $UserProfile.Path
        Category       = $Target.Category
        TargetPath     = $Target.Path
        SafetyNote     = $Target.SafetyNote
        CandidateFiles = $candidateFiles.Count
        CandidateBytes = $candidateBytes
        DeletedFiles   = $deletedFiles
        DeletedBytes   = $deletedBytes
        FailedFiles    = $failedFiles
        FailureSamples = @($failureSamples.ToArray())
    }
}

function Measure-And-CleanRecycleBin {
    param([Parameter(Mandatory = $true)][object]$UserProfile)

    $recycleRoot = "$($env:SystemDrive)\`$Recycle.Bin"
    $recyclePath = Join-Path -Path $recycleRoot -ChildPath $UserProfile.Sid
    if (-not (Test-Path -LiteralPath $recyclePath -PathType Container)) {
        return $null
    }

    $target = [ordered]@{
        Category = "User Recycle Bin"
        Path = $recyclePath
        SafetyNote = "Deletes old files already placed in this user's Recycle Bin."
    }

    Measure-And-CleanTarget -UserProfile $UserProfile -Target $target
}

New-ParentDirectory -Path $ReportPath

$profiles = @(Get-LocalUserProfiles)
foreach ($userProfile in $profiles) {
    if ($userProfile.SkipReason) {
        $Results.Add([ordered]@{
                ProfileName = $userProfile.Name
                ProfilePath = $userProfile.Path
                Sid         = $userProfile.Sid
                Loaded      = $userProfile.Loaded
                Skipped     = $true
                SkipReason  = $userProfile.SkipReason
                Targets     = @()
            }) | Out-Null
        continue
    }

    $targetResults = New-Object System.Collections.Generic.List[object]

    foreach ($target in @(Get-CleanupTargetsForProfile -ProfilePath $userProfile.Path)) {
        $targetResults.Add((Measure-And-CleanTarget -UserProfile $userProfile -Target $target)) | Out-Null
    }

    if ($IncludeRecycleBin) {
        $recycleResult = Measure-And-CleanRecycleBin -UserProfile $userProfile
        if ($recycleResult) {
            $targetResults.Add($recycleResult) | Out-Null
        }
    }

    $Results.Add([ordered]@{
            ProfileName = $userProfile.Name
            ProfilePath = $userProfile.Path
            Sid         = $userProfile.Sid
            Loaded      = $userProfile.Loaded
            Skipped     = $false
            SkipReason  = $null
            Targets     = @($targetResults.ToArray())
        }) | Out-Null
}

$targetRows = @($Results.ToArray() | ForEach-Object { $_["Targets"] } | ForEach-Object { $_ })
$candidateFilesTotal = Get-MeasureSum -InputObject $targetRows -PropertyName "CandidateFiles" -OutputType ([int])
$candidateBytesTotal = Get-MeasureSum -InputObject $targetRows -PropertyName "CandidateBytes" -OutputType ([int64])
$deletedBytesTotal = Get-MeasureSum -InputObject $targetRows -PropertyName "DeletedBytes" -OutputType ([int64])
$failedFilesTotal = Get-MeasureSum -InputObject $targetRows -PropertyName "FailedFiles" -OutputType ([int])
$skippedProfileCount = 0
foreach ($result in $Results.ToArray()) {
    if ([bool]$result["Skipped"]) {
        $skippedProfileCount++
    }
}

$report = [ordered]@{
    ComputerName          = $env:COMPUTERNAME
    GeneratedAtUtc        = (Get-Date).ToUniversalTime().ToString("o")
    Mode                  = if ($Apply) { "Apply" } else { "DryRun" }
    ProfileRoot           = $ProfileRoot
    MinimumAgeDays        = $MinimumAgeDays
    CutoffTime            = $Cutoff
    IncludeLoadedProfiles = [bool]$IncludeLoadedProfiles
    IncludeRecycleBin     = [bool]$IncludeRecycleBin
    IncludeTemp           = [bool]$IncludeTemp
    ProfileCount          = $profiles.Count
    SkippedProfileCount   = $skippedProfileCount
    TargetCount           = $targetRows.Count
    CandidateFiles        = $candidateFilesTotal
    CandidateBytes        = $candidateBytesTotal
    DeletedBytes          = $deletedBytesTotal
    FailedFiles           = $failedFilesTotal
    Profiles              = $Results
}

$report | ConvertTo-Json -Depth 8 | Out-File -FilePath $ReportPath -Encoding utf8

Write-Host "RDP profile cache cleanup report written to: $ReportPath"
Write-Host "Mode: $($report.Mode)"
Write-Host "Profiles found: $($report.ProfileCount)"
Write-Host "Profiles skipped: $($report.SkippedProfileCount)"
Write-Host "Candidate files: $($report.CandidateFiles)"
Write-Host "Candidate bytes: $($report.CandidateBytes)"

if ($Apply) {
    Write-Host "Deleted bytes: $($report.DeletedBytes)"
    if ($failedFilesTotal -gt 0) {
        Write-Warning "Some files could not be deleted. See report for details."
        exit 1
    }
}
else {
    Write-Host "Dry run complete. Re-run with -Apply after reviewing the report."
}
