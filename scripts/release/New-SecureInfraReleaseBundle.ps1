<#
.SYNOPSIS
Creates a public SecureInfra release bundle with local integrity metadata.

.DESCRIPTION
Packages selected public repository files into a release directory and zip
archive. The bundle includes SHA256SUMS.txt and RELEASE-MANIFEST.json for local
integrity checks. Signing is intentionally not implemented here; see
docs/release-integrity.md for optional operator-controlled signing guidance.
#>

[CmdletBinding()]
param(
    [string]$OutputDirectory = "dist",
    [string]$Version,
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-RepositoryRoot {
    return (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
}

function ConvertTo-ReleaseRelativePath {
    param(
        [Parameter(Mandatory = $true)][string]$RootPath,
        [Parameter(Mandatory = $true)][string]$FilePath
    )

    $pathSeparators = [char[]]@(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    )
    $rootFull = [System.IO.Path]::GetFullPath($RootPath).TrimEnd($pathSeparators)
    $fileFull = [System.IO.Path]::GetFullPath($FilePath)

    if (-not $fileFull.StartsWith($rootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "File path is outside the repository root: $FilePath"
    }

    $relativePath = $fileFull.Substring($rootFull.Length).TrimStart($pathSeparators)
    return ($relativePath -replace "\\", "/")
}

function Test-ReleasePathExcluded {
    param([Parameter(Mandatory = $true)][string]$RelativePath)

    $normalizedPath = ($RelativePath -replace "\\", "/")
    $lowerPath = $normalizedPath.ToLowerInvariant()
    $segments = $lowerPath -split "/"
    $excludedSegments = @(
        ".git",
        ".codex",
        ".agents",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        "__pycache__",
        "node_modules",
        "backups",
        ".venv",
        "venv",
        "env",
        "tmp",
        "temp",
        "customer-data",
        "client-data",
        "raw-evidence",
        "private-files",
        "commercial-deliverables",
        "private",
        "customers"
    )

    foreach ($segment in $segments) {
        if ($excludedSegments -contains $segment) {
            return $true
        }
    }

    if ($lowerPath -eq "reports" -or $lowerPath.StartsWith("reports/")) {
        return $true
    }
    if ($lowerPath -eq "secureinfra_ai/reports" -or $lowerPath.StartsWith("secureinfra_ai/reports/")) {
        return $true
    }

    $fileName = [System.IO.Path]::GetFileName($lowerPath)
    $blockedNames = @(
        ".env",
        ".envrc",
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519"
    )
    if ($blockedNames -contains $fileName) {
        return $true
    }

    $blockedExtensions = @(
        ".zip",
        ".7z",
        ".rar",
        ".tar",
        ".tgz",
        ".gz",
        ".bz2",
        ".xz",
        ".pfx",
        ".p12",
        ".pem",
        ".key",
        ".der",
        ".kdbx",
        ".sqlite",
        ".db",
        ".bak",
        ".tmp",
        ".swp",
        ".swo",
        ".pyc"
    )

    foreach ($extension in $blockedExtensions) {
        if ($fileName.EndsWith($extension)) {
            return $true
        }
    }

    if (
        $fileName -like "*.local" -or
        $fileName -like "*.local.*" -or
        $fileName -like "*.secret.*" -or
        $fileName -like "*.token.*" -or
        $fileName -like "*.cred.*" -or
        $fileName -like "*.credential.*" -or
        $fileName -like "*.credentials.*"
    ) {
        return $true
    }

    return $false
}

function Copy-ReleaseFile {
    param(
        [Parameter(Mandatory = $true)][string]$SourcePath,
        [Parameter(Mandatory = $true)][string]$DestinationRoot,
        [Parameter(Mandatory = $true)][string]$RelativePath
    )

    $destinationPath = Join-Path $DestinationRoot ($RelativePath -replace "/", [System.IO.Path]::DirectorySeparatorChar)
    $destinationDirectory = Split-Path -Parent $destinationPath
    if (-not (Test-Path -LiteralPath $destinationDirectory)) {
        New-Item -ItemType Directory -Path $destinationDirectory -Force | Out-Null
    }

    Copy-Item -LiteralPath $SourcePath -Destination $destinationPath -Force
}

$repoRoot = Get-RepositoryRoot

if ([string]::IsNullOrWhiteSpace($Version)) {
    $versionFile = Join-Path $repoRoot "VERSION"
    if (Test-Path -LiteralPath $versionFile) {
        $Version = (Get-Content -LiteralPath $versionFile -Raw).Trim()
    } else {
        $Version = "0.0.0-dev"
    }
}

$versionSafe = ($Version -replace "[^A-Za-z0-9._-]", "-")
$releaseName = "secureinfra-release-$versionSafe"

if ([System.IO.Path]::IsPathRooted($OutputDirectory)) {
    $outputRoot = [System.IO.Path]::GetFullPath($OutputDirectory)
} else {
    $outputRoot = [System.IO.Path]::GetFullPath((Join-Path $repoRoot $OutputDirectory))
}

if (-not (Test-Path -LiteralPath $outputRoot)) {
    New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null
}

$stagingPath = Join-Path $outputRoot $releaseName
$archivePath = Join-Path $outputRoot "$releaseName.zip"

if ((Test-Path -LiteralPath $stagingPath) -or (Test-Path -LiteralPath $archivePath)) {
    if (-not $Force) {
        throw "Release output already exists. Use -Force to replace $stagingPath and $archivePath."
    }
    if (Test-Path -LiteralPath $stagingPath) {
        Remove-Item -LiteralPath $stagingPath -Recurse -Force
    }
    if (Test-Path -LiteralPath $archivePath) {
        Remove-Item -LiteralPath $archivePath -Force
    }
}

New-Item -ItemType Directory -Path $stagingPath -Force | Out-Null

$rootFiles = @(
    "README.md",
    "LICENSE",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "CHANGELOG.md",
    "ROADMAP.md",
    "VERSION",
    "AGENTS.md",
    "Makefile"
)
$publicDirectories = @("docs", "examples", "schemas", "scripts", "SecureInfra_AI")
$selectedFiles = New-Object System.Collections.Generic.List[object]

foreach ($rootFile in $rootFiles) {
    $path = Join-Path $repoRoot $rootFile
    if (Test-Path -LiteralPath $path) {
        $selectedFiles.Add([pscustomobject]@{
            Path = (Get-Item -LiteralPath $path).FullName
            RelativePath = $rootFile
        })
    }
}

foreach ($directory in $publicDirectories) {
    $path = Join-Path $repoRoot $directory
    if (-not (Test-Path -LiteralPath $path)) {
        continue
    }

    Get-ChildItem -LiteralPath $path -File -Recurse -Force | ForEach-Object {
        $relativePath = ConvertTo-ReleaseRelativePath -RootPath $repoRoot -FilePath $_.FullName
        if (-not (Test-ReleasePathExcluded -RelativePath $relativePath)) {
            $selectedFiles.Add([pscustomobject]@{
                Path = $_.FullName
                RelativePath = $relativePath
            })
        }
    }
}

$selectedFiles = $selectedFiles |
    Where-Object { -not (Test-ReleasePathExcluded -RelativePath $_.RelativePath) } |
    Sort-Object -Property RelativePath -Unique

foreach ($file in $selectedFiles) {
    Copy-ReleaseFile -SourcePath $file.Path -DestinationRoot $stagingPath -RelativePath $file.RelativePath
}

$generatedAtUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ", [System.Globalization.CultureInfo]::InvariantCulture)
$manifestFiles = @()

Get-ChildItem -LiteralPath $stagingPath -File -Recurse | ForEach-Object {
    $relativePath = ConvertTo-ReleaseRelativePath -RootPath $stagingPath -FilePath $_.FullName
    $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $manifestFiles += [pscustomobject]@{
        path = $relativePath
        size = $_.Length
        sha256 = $hash
    }
}

$manifestFiles = $manifestFiles | Sort-Object -Property path
$manifest = [ordered]@{
    schema_version = "1.0"
    release_name = $releaseName
    version = $Version
    generated_at_utc = $generatedAtUtc
    file_count = $manifestFiles.Count
    files = $manifestFiles
}

$manifestPath = Join-Path $stagingPath "RELEASE-MANIFEST.json"
$checksumsPath = Join-Path $stagingPath "SHA256SUMS.txt"

$manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
$manifestFiles |
    ForEach-Object { "$($_.sha256)  $($_.path)" } |
    Set-Content -LiteralPath $checksumsPath -Encoding ASCII

if (Get-Command Compress-Archive -ErrorAction SilentlyContinue) {
    Compress-Archive -Path (Join-Path $stagingPath "*") -DestinationPath $archivePath -Force
} else {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::CreateFromDirectory($stagingPath, $archivePath)
}

Write-Host "Release bundle directory: $stagingPath"
Write-Host "Release archive: $archivePath"
Write-Host "Manifest: $manifestPath"
Write-Host "Checksums: $checksumsPath"
