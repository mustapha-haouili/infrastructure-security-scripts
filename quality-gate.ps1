<#
.SYNOPSIS
    Run SecureInfra public repository quality checks.

.DESCRIPTION
    This gate is intended for pre-release and pre-handoff validation of the
    public defensive collector/analyzer repository. It runs repository tests,
    verifies key integration contracts, performs a sample analyzer smoke test,
    and validates the generated normalized-report.json with strict safety
    checks.

    This script does not modify customer data and must not be used to run the
    private commercial reporting pipeline.

.EXAMPLE
    .\quality-gate.ps1 -Fast

.EXAMPLE
    .\quality-gate.ps1

.EXAMPLE
    .\quality-gate.ps1 -SampleOutputDirectory .\reports\quality-gate-smoke -KeepSampleOutput
#>

[CmdletBinding()]
param(
    [switch]$Fast,
    [switch]$SkipGitSafety,
    [string]$Python = "python",
    [string]$SampleOutputDirectory,
    [switch]$KeepSampleOutput
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$CreatedSampleOutput = $false
$SmokeOutputPath = $null

function Write-Section {
    param([Parameter(Mandatory = $true)][string]$Title)
    Write-Host ""
    Write-Host "============================================================"
    Write-Host $Title
    Write-Host "============================================================"
}

function Require-File {
    param([Parameter(Mandatory = $true)][string]$RelativePath)
    $PathToCheck = Join-Path $RepoRoot $RelativePath
    if (-not (Test-Path -LiteralPath $PathToCheck -PathType Leaf)) {
        throw "Required file is missing: $RelativePath"
    }
}

function Require-Directory {
    param([Parameter(Mandatory = $true)][string]$RelativePath)
    $PathToCheck = Join-Path $RepoRoot $RelativePath
    if (-not (Test-Path -LiteralPath $PathToCheck -PathType Container)) {
        throw "Required directory is missing: $RelativePath"
    }
}

function Require-TextMarker {
    param(
        [Parameter(Mandatory = $true)][string]$RelativePath,
        [Parameter(Mandatory = $true)][string]$Needle,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $PathToCheck = Join-Path $RepoRoot $RelativePath
    $Content = Get-Content -LiteralPath $PathToCheck -Raw -Encoding UTF8
    if ($Content -notlike "*$Needle*") {
        throw "Missing expected integration marker in ${Label}: $Needle"
    }
}

function Invoke-CheckedCommand {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )
    Write-Section $Label
    Write-Host ("Running: {0} {1}" -f $Executable, ($Arguments -join " "))
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code ${LASTEXITCODE}: $Label"
    }
}

function Test-PublicIntegrationContracts {
    Write-Section "Check public repository integration contracts"

    Require-File "SecureInfra_AI\scripts\reporting\secureinfra_analyzer.py"
    Require-File "scripts\reporting\validate_schema.py"
    Require-File "scripts\reporting\validate_bundle.py"
    Require-File "scripts\windows\Start-SecureInfraClientCollection.ps1"
    Require-File "scripts\windows\Start-WindowsSecurity.ps1"
    Require-Directory "tests"
    Require-Directory "SecureInfra_AI\schemas"
    Require-Directory "SecureInfra_AI\examples\sample-input"

    Require-TextMarker `
        -RelativePath "TESTING_STRATEGY.md" `
        -Needle "validate_schema.py" `
        -Label "public testing strategy"

    Require-TextMarker `
        -RelativePath "CODEX_WORKFLOW.md" `
        -Needle "Any new script added to this repository must have an explicit caller or a documented manual-only reason" `
        -Label "public Codex workflow"

    Require-TextMarker `
        -RelativePath "scripts\reporting\validate_schema.py" `
        -Needle "validate_normalized_report" `
        -Label "normalized report schema validator"

    Require-TextMarker `
        -RelativePath "scripts\reporting\validate_bundle.py" `
        -Needle "validate_input_bundle" `
        -Label "input bundle validator"

    Require-TextMarker `
        -RelativePath "scripts\windows\Start-SecureInfraClientCollection.ps1" `
        -Needle "Backup" `
        -Label "client collection launcher backup scope"

    Write-Host "Public integration contracts look present."
}

function Invoke-PublicTests {
    if ($Fast) {
        $Args = @(
            "-m", "unittest", "-v",
            "tests.test_validate_schema",
            "tests.test_validate_bundle",
            "tests.test_client_collection_launcher",
            "tests.test_secureinfra_windows_normalizers.SecureInfraWindowsNormalizerTests.test_windows_samples_pass_schema_validation",
            "tests.test_secureinfra_backup_readiness.SecureInfraBackupReadinessTests.test_normalized_output_schema_compatibility",
            "tests.test_secureinfra_ai.SecureInfraAITests.test_multi_bundle_keeps_server_security_finding_ids_unique"
        )
        Invoke-CheckedCommand -Label "Run fast public unit tests" -Executable $Python -Arguments $Args
    }
    else {
        $Args = @("-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py")
        Invoke-CheckedCommand -Label "Run full public unit test suite" -Executable $Python -Arguments $Args
    }
}

function Invoke-SampleAnalyzerSmokeTest {
    Write-Section "Run public analyzer smoke test and schema validation"

    if ([string]::IsNullOrWhiteSpace($SampleOutputDirectory)) {
        $OutputPath = Join-Path ([System.IO.Path]::GetTempPath()) ("secureinfra-public-quality-gate-" + [guid]::NewGuid().ToString("N"))
        $script:CreatedSampleOutput = $true
    }
    elseif ([System.IO.Path]::IsPathRooted($SampleOutputDirectory)) {
        $OutputPath = $SampleOutputDirectory
    }
    else {
        $OutputPath = [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $SampleOutputDirectory))
    }
    $script:SmokeOutputPath = $OutputPath

    if (Test-Path -LiteralPath $OutputPath) {
        Remove-Item -LiteralPath $OutputPath -Recurse -Force
    }
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

    $AnalyzerArgs = @(
        ".\SecureInfra_AI\scripts\reporting\secureinfra_analyzer.py",
        "--input", ".\SecureInfra_AI\examples\sample-input\active-directory\sample-ad-inactive-users.json",
        "--type", "ad-inactive-users",
        "--output", $OutputPath
    )
    Invoke-CheckedCommand -Label "Generate sample normalized report" -Executable $Python -Arguments $AnalyzerArgs

    $ReportPath = Join-Path $OutputPath "normalized-report.json"
    if (-not (Test-Path -LiteralPath $ReportPath -PathType Leaf)) {
        throw "Smoke test did not produce normalized-report.json at $ReportPath"
    }

    $ValidatorArgs = @(
        ".\scripts\reporting\validate_schema.py",
        "--input", $OutputPath,
        "--strict-safety"
    )
    Invoke-CheckedCommand -Label "Validate sample normalized report contract" -Executable $Python -Arguments $ValidatorArgs

    if ($KeepSampleOutput) {
        Write-Host "Keeping sample output at: $OutputPath"
    }
}

function Invoke-SampleBundleValidationSmokeTest {
    Write-Section "Run input bundle validation smoke test"

    $BundleRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("secureinfra-public-bundle-validation-" + [guid]::NewGuid().ToString("N"))
    $BundlePath = Join-Path $BundleRoot "secureinfra-client-collection-QG-SRV01-20260709-120000"

    try {
        New-Item -ItemType Directory -Path (Join-Path $BundlePath "host") -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $BundlePath "logs") -Force | Out-Null

        Set-Content -LiteralPath (Join-Path $BundlePath "client-info.json") -Encoding UTF8 -Value '{"ComputerName":"QG-SRV01","UserDomain":"example"}'
        Set-Content -LiteralPath (Join-Path $BundlePath "collection-summary.json") -Encoding UTF8 -Value '{"CollectionId":"secureinfra-client-QG-SRV01-20260709-120000","GeneratedAtUtc":"2026-07-09T12:00:00Z","SafetyMode":"Audit and dry-run only. No remediation is applied.","ScopeResolved":["Host"]}'
        Set-Content -LiteralPath (Join-Path $BundlePath "manifest.json") -Encoding UTF8 -Value '{"SchemaVersion":"1.0","CollectionId":"secureinfra-client-QG-SRV01-20260709-120000","GeneratedAtUtc":"2026-07-09T12:00:00Z","ScopeResolved":["Host"]}'
        Set-Content -LiteralPath (Join-Path $BundlePath "host\windows-security-audit.json") -Encoding UTF8 -Value '{"ReportMetadata":{"ComputerName":"QG-SRV01","ScriptName":"Invoke-WindowsSecurityAudit.ps1"},"Summary":{"FindingCount":0},"Findings":[]}'
        Set-Content -LiteralPath (Join-Path $BundlePath "logs\windows-security-audit.log") -Encoding UTF8 -Value 'collector log'

        $BundleValidatorArgs = @(
            ".\scripts\reporting\validate_bundle.py",
            "--input", $BundlePath,
            "--strict-safety",
            "--expected-bundle-count", "1"
        )
        Invoke-CheckedCommand -Label "Validate sample client collection bundle" -Executable $Python -Arguments $BundleValidatorArgs
    }
    finally {
        if (Test-Path -LiteralPath $BundleRoot) {
            Remove-Item -LiteralPath $BundleRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-GitSafety {
    if ($SkipGitSafety) {
        Write-Section "Skip git safety checks"
        Write-Host "Git safety checks were skipped by request."
        return
    }

    Write-Section "Check git status for unsafe public repository artifacts"

    $GitCommand = Get-Command git -ErrorAction SilentlyContinue
    if (-not $GitCommand) {
        Write-Host "git is not available; skipping git safety checks."
        return
    }

    Push-Location $RepoRoot
    try {
        & git rev-parse --is-inside-work-tree *> $null
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Not inside a git work tree; skipping git safety checks."
            return
        }

        $StatusLines = & git status --porcelain
        if ($LASTEXITCODE -ne 0) {
            throw "git status failed"
        }

        $ForbiddenPatterns = @(
            "(^|/)customer-projects/",
            "(^|/)downstream-reporting-workspace/",
            "(^|/)03-input-bundles/",
            "(^|/)04-normalized-reports/",
            "(^|/)professional-deliverables/",
            "(^|/)deliverables/",
            "(^|/)reports/",
            "(^|/)output/",
            "\.env($|[ /])",
            "\.zip($|[ /])",
            "\.xlsx($|[ /])"
        )

        $UnsafeLines = @()
        foreach ($Line in $StatusLines) {
            foreach ($Pattern in $ForbiddenPatterns) {
                if ($Line -match $Pattern) {
                    $UnsafeLines += $Line
                    break
                }
            }
        }

        if ($UnsafeLines.Count -gt 0) {
            Write-Host "Unsafe generated/customer-like artifacts appear in git status:" -ForegroundColor Red
            $UnsafeLines | Sort-Object -Unique | ForEach-Object { Write-Host $_ }
            throw "Git status contains artifacts that should not be committed to the public repository."
        }

        Write-Host "Git safety checks passed."
    }
    finally {
        Pop-Location
    }
}

Push-Location $RepoRoot
try {
    Test-PublicIntegrationContracts
    Invoke-PublicTests
    Invoke-SampleBundleValidationSmokeTest
    Invoke-SampleAnalyzerSmokeTest
    Test-GitSafety
    Write-Section "Public quality gate passed"
    Write-Host "SecureInfra public repository quality checks passed."
}
finally {
    Pop-Location
    if ($script:CreatedSampleOutput -and (-not $KeepSampleOutput) -and $script:SmokeOutputPath -and (Test-Path -LiteralPath $script:SmokeOutputPath)) {
        Remove-Item -LiteralPath $script:SmokeOutputPath -Recurse -Force -ErrorAction SilentlyContinue
    }
}
