<#
.SYNOPSIS
Runs an interactive Windows audit, remediation planning, and hardening preview workflow.

.DESCRIPTION
This script is a user-friendly orchestration layer for normal IT administration
workflows. It runs the Windows security audit, creates a remediation plan,
walks the admin through each finding, records decisions in the JSON plan, and
then runs a hardening dry-run preview.

It does not apply changes unless -ApplyApproved is used and the admin types the
final confirmation word after reviewing the dry-run output.

.PARAMETER AuditReportPath
Use an existing JSON audit report instead of running Invoke-WindowsSecurityAudit.ps1.

.PARAMETER PlanPath
Use an existing remediation plan instead of running a new audit or asking for
decisions again. This is the preferred way to apply decisions from a previous
run.

.PARAMETER OutputDirectory
Directory for generated audit, remediation plan, review, and hardening reports.
Default: .\reports

.PARAMETER IncludeHotfixes
Passes -IncludeHotfixes to Invoke-WindowsSecurityAudit.ps1 when a new audit is run.

.PARAMETER ApplyApproved
Allows the script to ask for final apply confirmation after the dry-run preview.
Without this switch, the script only writes decisions and runs a dry-run.

.PARAMETER ReviewDecisions
When used with -PlanPath, re-open the saved remediation plan and ask the admin
to review decisions again before preview/apply.

.PARAMETER NonInteractive
Runs without prompts. All plan items are marked Skipped and only a dry-run
preview is generated. This is useful for validation and scheduled reporting.

.PARAMETER Quiet
Reduces console output from this orchestration script.

.EXAMPLE
.\Start-WindowsSecurityRemediation.ps1

Run audit, create a plan, ask for decisions, and generate a dry-run hardening
preview.

.EXAMPLE
.\Start-WindowsSecurityRemediation.ps1 -ApplyApproved

Resume the latest saved remediation plan when one exists, then preview and ask
for final apply confirmation. If no saved decision plan exists, run the full
interactive workflow.

.EXAMPLE
.\Start-WindowsSecurityRemediation.ps1 -AuditReportPath .\reports\server01-audit.json

Start the interactive workflow from an existing audit report.

.EXAMPLE
.\Start-WindowsSecurityRemediation.ps1 -PlanPath .\reports\server01-remediation-plan.json -ApplyApproved

Preview and apply approved runnable controls from a saved remediation plan.
#>

[CmdletBinding()]
param(
    [string]$AuditReportPath = "",
    [string]$PlanPath = "",
    [string]$OutputDirectory = ".\reports",
    [switch]$IncludeHotfixes,
    [switch]$ApplyApproved,
    [switch]$ReviewDecisions,
    [switch]$NonInteractive,
    [switch]$Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($NonInteractive -and $ApplyApproved) {
    throw "-NonInteractive cannot be combined with -ApplyApproved."
}
if ($NonInteractive -and $ReviewDecisions) {
    throw "-NonInteractive cannot be combined with -ReviewDecisions."
}

$ScriptRoot = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
$AuditScriptPath = Join-Path -Path $ScriptRoot -ChildPath "Invoke-WindowsSecurityAudit.ps1"
$PlanScriptPath = Join-Path -Path $ScriptRoot -ChildPath "New-WindowsRemediationPlan.ps1"
$HardeningScriptPath = Join-Path -Path $ScriptRoot -ChildPath "Set-WindowsBaselineHardening.ps1"

function New-ParentDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)

    $parent = Split-Path -Path $Path -Parent
    if ($parent -and -not (Test-Path -Path $parent)) {
        New-Item -Path $parent -ItemType Directory -Force | Out-Null
    }
}

function Get-ObjectValue {
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($null -eq $InputObject) {
        return $null
    }

    if ($InputObject -is [System.Collections.IDictionary] -and $InputObject.Contains($Name)) {
        return $InputObject[$Name]
    }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($property) {
        return $property.Value
    }

    return $null
}

function Set-ObjectValue {
    param(
        [Parameter(Mandatory = $true)][object]$InputObject,
        [Parameter(Mandatory = $true)][string]$Name,
        [AllowNull()][object]$Value
    )

    if ($InputObject.PSObject.Properties[$Name]) {
        $InputObject.$Name = $Value
    }
    else {
        Add-Member -InputObject $InputObject -NotePropertyName $Name -NotePropertyValue $Value
    }
}

function ConvertTo-PlainText {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return ""
    }

    return ($Value.ToString() -replace "\r?\n", " ").Trim()
}

function ConvertTo-BooleanSafe {
    param([AllowNull()][object]$Value)

    if ($Value -is [bool]) {
        return $Value
    }

    return "$Value" -in @("True", "true", "1", "Yes", "yes")
}

function Escape-MarkdownCell {
    param([AllowNull()][object]$Value)

    $text = ConvertTo-PlainText -Value $Value
    return $text -replace "\|", "\|"
}

function Write-Step {
    param([Parameter(Mandatory = $true)][string]$Message)

    if (-not $Quiet) {
        Write-Host ""
        Write-Host $Message -ForegroundColor Cyan
    }
}

function Write-InfoLine {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [AllowNull()][object]$Value
    )

    Write-Host ("{0}: " -f $Label) -NoNewline -ForegroundColor DarkGray
    Write-Host (ConvertTo-PlainText -Value $Value)
}

function Test-RunnablePlanItem {
    param([Parameter(Mandatory = $true)][object]$PlanItem)

    $controlId = Get-ObjectValue -InputObject $PlanItem -Name "HardeningControlId"
    $controlStatus = Get-ObjectValue -InputObject $PlanItem -Name "HardeningControlStatus"
    return [bool]($controlId -and $controlStatus -in @("Implemented", "ManualApprovalRequired"))
}

function Get-DecisionUser {
    if ($env:USERDOMAIN -and $env:USERNAME) {
        return "$env:USERDOMAIN\$env:USERNAME"
    }
    if ($env:USERNAME) {
        return $env:USERNAME
    }
    return "Unknown"
}

function Show-PlanItemSummary {
    param(
        [Parameter(Mandatory = $true)][object]$PlanItem,
        [int]$Index,
        [int]$Total
    )

    $severity = Get-ObjectValue -InputObject $PlanItem -Name "Severity"
    $titleColor = switch ($severity) {
        "Critical" { "Red" }
        "High" { "Red" }
        "Medium" { "Yellow" }
        "Low" { "Gray" }
        default { "White" }
    }

    Write-Host ""
    Write-Host ("[{0}/{1}] {2} - {3}" -f $Index, $Total, (Get-ObjectValue -InputObject $PlanItem -Name "FindingId"), (Get-ObjectValue -InputObject $PlanItem -Name "Title")) -ForegroundColor $titleColor
    Write-InfoLine -Label "Severity" -Value $severity
    Write-InfoLine -Label "Area" -Value (Get-ObjectValue -InputObject $PlanItem -Name "Area")
    Write-InfoLine -Label "Evidence" -Value (Get-ObjectValue -InputObject $PlanItem -Name "Evidence")
    Write-InfoLine -Label "Suggested fix" -Value (Get-ObjectValue -InputObject $PlanItem -Name "SuggestedFix")
    Write-InfoLine -Label "Fix type" -Value (Get-ObjectValue -InputObject $PlanItem -Name "RemediationType")
    Write-InfoLine -Label "Automation" -Value ("{0} / {1}" -f (Get-ObjectValue -InputObject $PlanItem -Name "HardeningControlId"), (Get-ObjectValue -InputObject $PlanItem -Name "HardeningControlStatus"))

    $cis = Get-ObjectValue -InputObject $PlanItem -Name "CISRecommendation"
    if ($cis) {
        Write-InfoLine -Label "CIS" -Value $cis
    }

    if (-not (Test-RunnablePlanItem -PlanItem $PlanItem)) {
        Write-Host "This item is not ready for automatic apply. You can skip it or record an exception/manual follow-up." -ForegroundColor DarkYellow
        Write-InfoLine -Label "Reason" -Value (Get-ObjectValue -InputObject $PlanItem -Name "ReadinessReason")
    }
    elseif ((Get-ObjectValue -InputObject $PlanItem -Name "HardeningControlStatus") -eq "ManualApprovalRequired") {
        Write-Host "This item can run only after a real operational decision. Confirm ownership before approving." -ForegroundColor DarkYellow
        Write-InfoLine -Label "Exception guidance" -Value (Get-ObjectValue -InputObject $PlanItem -Name "ExceptionGuidance")
    }
}

function Show-PlanItemDetails {
    param([Parameter(Mandatory = $true)][object]$PlanItem)

    Write-Host ""
    Write-Host "Details" -ForegroundColor Cyan
    Write-InfoLine -Label "Why it matters" -Value (Get-ObjectValue -InputObject $PlanItem -Name "WhyItMatters")
    Write-InfoLine -Label "Recommendation" -Value (Get-ObjectValue -InputObject $PlanItem -Name "Recommendation")
    Write-InfoLine -Label "Risk level" -Value (Get-ObjectValue -InputObject $PlanItem -Name "RiskLevel")
    Write-InfoLine -Label "Requires admin" -Value (Get-ObjectValue -InputObject $PlanItem -Name "RequiresAdmin")
    Write-InfoLine -Label "Auto-fix eligible" -Value (Get-ObjectValue -InputObject $PlanItem -Name "AutoFixEligible")
    Write-InfoLine -Label "Readiness" -Value (Get-ObjectValue -InputObject $PlanItem -Name "ReadinessReason")
    Write-InfoLine -Label "Exception guidance" -Value (Get-ObjectValue -InputObject $PlanItem -Name "ExceptionGuidance")
    Write-InfoLine -Label "Wazuh Win11 check" -Value (Get-ObjectValue -InputObject $PlanItem -Name "WazuhWin11EnterpriseCheckId")
    Write-InfoLine -Label "Wazuh Win2019 check" -Value (Get-ObjectValue -InputObject $PlanItem -Name "WazuhWin2019CheckId")
}

function Set-PlanItemDecision {
    param(
        [Parameter(Mandatory = $true)][object]$PlanItem,
        [Parameter(Mandatory = $true)][string]$ApprovalStatus,
        [string]$Note = ""
    )

    $now = (Get-Date).ToUniversalTime().ToString("o")
    $decisionUser = Get-DecisionUser

    Set-ObjectValue -InputObject $PlanItem -Name "ApprovalStatus" -Value $ApprovalStatus
    Set-ObjectValue -InputObject $PlanItem -Name "DecisionBy" -Value $decisionUser
    Set-ObjectValue -InputObject $PlanItem -Name "DecisionAtUtc" -Value $now
    Set-ObjectValue -InputObject $PlanItem -Name "DecisionNote" -Value $Note

    if ($ApprovalStatus -eq "Approved") {
        Set-ObjectValue -InputObject $PlanItem -Name "ApprovedBy" -Value $decisionUser
        Set-ObjectValue -InputObject $PlanItem -Name "ApprovedAtUtc" -Value $now
        Set-ObjectValue -InputObject $PlanItem -Name "ApprovalNote" -Value $Note
    }
    else {
        Set-ObjectValue -InputObject $PlanItem -Name "ApprovedBy" -Value ""
        Set-ObjectValue -InputObject $PlanItem -Name "ApprovedAtUtc" -Value ""
        Set-ObjectValue -InputObject $PlanItem -Name "ApprovalNote" -Value $Note
    }
}

function Read-PlanItemDecision {
    param([Parameter(Mandatory = $true)][object]$PlanItem)

    $canApprove = Test-RunnablePlanItem -PlanItem $PlanItem
    while ($true) {
        if ($canApprove) {
            $choice = Read-Host "Choose [A]pprove fix, [S]kip, [E]xception, [D]etails, [Q]uit"
        }
        else {
            $choice = Read-Host "Choose [S]kip, [E]xception/manual follow-up, [D]etails, [Q]uit"
        }

        if (-not $choice) {
            $choice = "S"
        }

        switch ($choice.Trim().ToUpperInvariant()) {
            "A" {
                if (-not $canApprove) {
                    Write-Host "This item is not runnable by the hardening script yet." -ForegroundColor Yellow
                    continue
                }

                $note = Read-Host "Approval note (optional)"
                Set-PlanItemDecision -PlanItem $PlanItem -ApprovalStatus "Approved" -Note $note
                return "Approved"
            }
            "S" {
                $note = Read-Host "Skip note (optional)"
                Set-PlanItemDecision -PlanItem $PlanItem -ApprovalStatus "Skipped" -Note $note
                return "Skipped"
            }
            "E" {
                $note = Read-Host "Exception or manual follow-up note"
                if (-not $note) {
                    $note = "Exception or manual follow-up recorded without additional note."
                }
                Set-PlanItemDecision -PlanItem $PlanItem -ApprovalStatus "Exception" -Note $note
                return "Exception"
            }
            "D" {
                Show-PlanItemDetails -PlanItem $PlanItem
                continue
            }
            "Q" {
                return "Quit"
            }
            default {
                Write-Host "Please choose one of the listed options." -ForegroundColor Yellow
            }
        }
    }
}

function Update-PlanDecisionSummary {
    param([Parameter(Mandatory = $true)][object]$Plan)

    $items = @(Get-ObjectValue -InputObject $Plan -Name "PlanItems")
    $statusCounts = [ordered]@{}
    foreach ($item in @($items)) {
        $status = Get-ObjectValue -InputObject $item -Name "ApprovalStatus"
        if (-not $status) {
            $status = "NotApproved"
        }
        if (-not $statusCounts.Contains($status)) {
            $statusCounts[$status] = 0
        }
        $statusCounts[$status]++
    }

    $approvedCount = @($items | Where-Object { (Get-ObjectValue -InputObject $_ -Name "ApprovalStatus") -eq "Approved" }).Count
    $runnableApprovedCount = @($items | Where-Object { (Get-ObjectValue -InputObject $_ -Name "ApprovalStatus") -eq "Approved" -and (Test-RunnablePlanItem -PlanItem $_) }).Count
    $decisionSummary = [ordered]@{
        UpdatedAtUtc          = (Get-Date).ToUniversalTime().ToString("o")
        UpdatedBy             = Get-DecisionUser
        TotalItems            = $items.Count
        ApprovedCount         = $approvedCount
        RunnableApprovedCount = $runnableApprovedCount
        StatusCounts          = $statusCounts
    }

    Set-ObjectValue -InputObject $Plan -Name "DecisionSummary" -Value $decisionSummary
    $summary = Get-ObjectValue -InputObject $Plan -Name "Summary"
    if ($summary) {
        Set-ObjectValue -InputObject $summary -Name "ApprovedCount" -Value $approvedCount
    }
}

function Save-Plan {
    param(
        [Parameter(Mandatory = $true)][object]$Plan,
        [Parameter(Mandatory = $true)][string]$Path
    )

    Update-PlanDecisionSummary -Plan $Plan
    New-ParentDirectory -Path $Path
    $Plan | ConvertTo-Json -Depth 14 | Out-File -FilePath $Path -Encoding utf8
}

function ConvertTo-DecisionCsvRows {
    param([Parameter(Mandatory = $true)][object[]]$PlanItems)

    foreach ($item in @($PlanItems)) {
        [pscustomobject]@{
            PlanItemId             = Get-ObjectValue -InputObject $item -Name "PlanItemId"
            ApprovalStatus         = Get-ObjectValue -InputObject $item -Name "ApprovalStatus"
            DecisionBy             = Get-ObjectValue -InputObject $item -Name "DecisionBy"
            DecisionAtUtc          = Get-ObjectValue -InputObject $item -Name "DecisionAtUtc"
            DecisionNote           = Get-ObjectValue -InputObject $item -Name "DecisionNote"
            FindingId              = Get-ObjectValue -InputObject $item -Name "FindingId"
            Severity               = Get-ObjectValue -InputObject $item -Name "Severity"
            Area                   = Get-ObjectValue -InputObject $item -Name "Area"
            RemediationType        = Get-ObjectValue -InputObject $item -Name "RemediationType"
            HardeningControlId     = Get-ObjectValue -InputObject $item -Name "HardeningControlId"
            HardeningControlStatus = Get-ObjectValue -InputObject $item -Name "HardeningControlStatus"
            Title                  = Get-ObjectValue -InputObject $item -Name "Title"
            SuggestedFix           = Get-ObjectValue -InputObject $item -Name "SuggestedFix"
            Evidence               = Get-ObjectValue -InputObject $item -Name "Evidence"
        }
    }
}

function Write-DecisionMarkdown {
    param(
        [Parameter(Mandatory = $true)][object]$Plan,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $metadata = Get-ObjectValue -InputObject $Plan -Name "ReportMetadata"
    $decisionSummary = Get-ObjectValue -InputObject $Plan -Name "DecisionSummary"
    $items = @(Get-ObjectValue -InputObject $Plan -Name "PlanItems")
    $headers = @("PlanItemId", "ApprovalStatus", "Severity", "FindingId", "HardeningControlId", "HardeningControlStatus", "Title", "DecisionNote")
    $lines = New-Object System.Collections.Generic.List[string]

    $lines.Add("# Windows Remediation Decisions") | Out-Null
    $lines.Add("") | Out-Null
    $lines.Add("Source audit report: ``$(Get-ObjectValue -InputObject $metadata -Name "SourceAuditReportName")``") | Out-Null
    $lines.Add("Computer: ``$(Get-ObjectValue -InputObject $metadata -Name "ComputerName")``") | Out-Null
    $lines.Add("Updated by: ``$(Get-ObjectValue -InputObject $decisionSummary -Name "UpdatedBy")``") | Out-Null
    $lines.Add("Updated at UTC: ``$(Get-ObjectValue -InputObject $decisionSummary -Name "UpdatedAtUtc")``") | Out-Null
    $lines.Add("") | Out-Null
    $lines.Add("## Summary") | Out-Null
    $lines.Add("") | Out-Null
    $lines.Add("- Total items: $(Get-ObjectValue -InputObject $decisionSummary -Name "TotalItems")") | Out-Null
    $lines.Add("- Approved items: $(Get-ObjectValue -InputObject $decisionSummary -Name "ApprovedCount")") | Out-Null
    $lines.Add("- Runnable approved items: $(Get-ObjectValue -InputObject $decisionSummary -Name "RunnableApprovedCount")") | Out-Null
    $lines.Add("") | Out-Null
    $lines.Add("## Decisions") | Out-Null
    $lines.Add("") | Out-Null
    $lines.Add("|" + (($headers | ForEach-Object { Escape-MarkdownCell -Value $_ }) -join "|") + "|") | Out-Null
    $lines.Add("|" + (($headers | ForEach-Object { "---" }) -join "|") + "|") | Out-Null

    foreach ($item in @($items)) {
        $cells = foreach ($header in $headers) {
            Escape-MarkdownCell -Value (Get-ObjectValue -InputObject $item -Name $header)
        }
        $lines.Add("|" + ($cells -join "|") + "|") | Out-Null
    }

    New-ParentDirectory -Path $Path
    $lines | Set-Content -Path $Path -Encoding UTF8
}

function Write-ReviewCopies {
    param(
        [Parameter(Mandatory = $true)][object]$Plan,
        [Parameter(Mandatory = $true)][string]$PlanPath
    )

    $csvPath = [System.IO.Path]::ChangeExtension($PlanPath, ".csv")
    $markdownPath = [System.IO.Path]::ChangeExtension($PlanPath, ".md")
    $items = @(Get-ObjectValue -InputObject $Plan -Name "PlanItems")

    ConvertTo-DecisionCsvRows -PlanItems $items | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-DecisionMarkdown -Plan $Plan -Path $markdownPath
}

function Get-DefaultPathFromAudit {
    param(
        [Parameter(Mandatory = $true)][string]$ResolvedAuditReportPath,
        [Parameter(Mandatory = $true)][string]$Prefix
    )

    $auditItem = Get-Item -Path $ResolvedAuditReportPath
    if ($auditItem.BaseName -like "windows-security-audit-*") {
        $name = $auditItem.BaseName -replace "^windows-security-audit-", "$Prefix-"
        return Join-Path -Path $resolvedOutputDirectory -ChildPath "$name.json"
    }

    return Join-Path -Path $resolvedOutputDirectory -ChildPath "$Prefix-$env:COMPUTERNAME-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
}

function Get-DefaultPathFromPlan {
    param(
        [Parameter(Mandatory = $true)][string]$ResolvedPlanPath,
        [Parameter(Mandatory = $true)][string]$Prefix
    )

    $planItem = Get-Item -Path $ResolvedPlanPath
    if ($planItem.BaseName -like "windows-remediation-plan-*") {
        $name = $planItem.BaseName -replace "^windows-remediation-plan-", "$Prefix-"
        return Join-Path -Path $resolvedOutputDirectory -ChildPath "$name.json"
    }

    return Join-Path -Path $resolvedOutputDirectory -ChildPath "$Prefix-$env:COMPUTERNAME-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
}

function Test-PlanHasAdminDecisions {
    param([Parameter(Mandatory = $true)][object]$Plan)

    if (Get-ObjectValue -InputObject $Plan -Name "DecisionSummary") {
        return $true
    }

    $items = @(Get-ObjectValue -InputObject $Plan -Name "PlanItems")
    foreach ($item in @($items)) {
        $status = Get-ObjectValue -InputObject $item -Name "ApprovalStatus"
        if ($status -and "$status" -ne "NotApproved") {
            return $true
        }
    }

    return $false
}

function Find-LatestDecisionPlan {
    param([Parameter(Mandatory = $true)][string]$Directory)

    $patterns = @(
        "windows-remediation-plan-$env:COMPUTERNAME-*.json",
        "windows-remediation-plan-*.json"
    )

    foreach ($pattern in $patterns) {
        $candidates = @(Get-ChildItem -Path $Directory -Filter $pattern -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
        foreach ($candidate in @($candidates)) {
            try {
                $candidatePlan = Get-Content -Path $candidate.FullName -Raw | ConvertFrom-Json
                if (Test-PlanHasAdminDecisions -Plan $candidatePlan) {
                    return $candidate.FullName
                }
            }
            catch {
                continue
            }
        }
    }

    return $null
}

function Invoke-HardeningPreview {
    param(
        [Parameter(Mandatory = $true)][string]$PlanPath,
        [Parameter(Mandatory = $true)][string]$ReportPath
    )

    & $HardeningScriptPath -PlanPath $PlanPath -ReportPath $ReportPath
}

function Get-RunnableApprovedCount {
    param([Parameter(Mandatory = $true)][object]$Plan)

    $items = @(Get-ObjectValue -InputObject $Plan -Name "PlanItems")
    return @($items | Where-Object {
            (Get-ObjectValue -InputObject $_ -Name "ApprovalStatus") -eq "Approved" -and (Test-RunnablePlanItem -PlanItem $_)
        }).Count
}

function Show-ApprovedApplySummary {
    param([Parameter(Mandatory = $true)][object]$Plan)

    $items = @(Get-ObjectValue -InputObject $Plan -Name "PlanItems")
    $approvedRunnable = @($items | Where-Object {
            (Get-ObjectValue -InputObject $_ -Name "ApprovalStatus") -eq "Approved" -and (Test-RunnablePlanItem -PlanItem $_)
        })
    $approvedBlocked = @($items | Where-Object {
            (Get-ObjectValue -InputObject $_ -Name "ApprovalStatus") -eq "Approved" -and -not (Test-RunnablePlanItem -PlanItem $_)
        })

    Write-Host ""
    Write-Host "Approved runnable controls" -ForegroundColor Cyan
    if ($approvedRunnable.Count -eq 0) {
        Write-Host "None"
    }
    else {
        foreach ($item in @($approvedRunnable)) {
            Write-Host ("- {0} -> {1}" -f (Get-ObjectValue -InputObject $item -Name "FindingId"), (Get-ObjectValue -InputObject $item -Name "HardeningControlId")) -ForegroundColor Yellow
            Write-Host ("  {0}" -f (Get-ObjectValue -InputObject $item -Name "Title"))
            Write-Host ("  Fix: {0}" -f (Get-ObjectValue -InputObject $item -Name "SuggestedFix"))
        }
    }

    if ($approvedBlocked.Count -gt 0) {
        Write-Host ""
        Write-Host "Approved but not runnable" -ForegroundColor DarkYellow
        foreach ($item in @($approvedBlocked)) {
            Write-Host ("- {0} -> {1} ({2})" -f (Get-ObjectValue -InputObject $item -Name "FindingId"), (Get-ObjectValue -InputObject $item -Name "HardeningControlId"), (Get-ObjectValue -InputObject $item -Name "HardeningControlStatus"))
            Write-Host ("  Reason: {0}" -f (Get-ObjectValue -InputObject $item -Name "ReadinessReason"))
        }
    }
}

foreach ($path in @($AuditScriptPath, $PlanScriptPath, $HardeningScriptPath)) {
    if (-not (Test-Path -Path $path)) {
        throw "Required script not found: $path"
    }
}

if (-not (Test-Path -Path $OutputDirectory)) {
    New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
}
$resolvedOutputDirectory = (Resolve-Path -Path $OutputDirectory).Path

$usingSavedPlan = $false
$reviewSavedPlanDecisions = $false
$resolvedAuditReportPath = $null

if ($PlanPath) {
    $planPath = (Resolve-Path -Path $PlanPath).Path
    $usingSavedPlan = $true
    $reviewSavedPlanDecisions = [bool]$ReviewDecisions
}
elseif ($ApplyApproved -and -not $AuditReportPath) {
    $latestPlanPath = Find-LatestDecisionPlan -Directory $resolvedOutputDirectory
    if ($latestPlanPath) {
        $planPath = $latestPlanPath
        $usingSavedPlan = $true
        $reviewSavedPlanDecisions = $false
    }
}

if ($usingSavedPlan) {
    Write-Step "Step 1: Saved remediation plan"
    $plan = Get-Content -Path $planPath -Raw | ConvertFrom-Json
    $metadata = Get-ObjectValue -InputObject $plan -Name "ReportMetadata"
    $sourceAuditReport = Get-ObjectValue -InputObject $metadata -Name "SourceAuditReport"
    if ($sourceAuditReport -and (Test-Path -Path $sourceAuditReport)) {
        $resolvedAuditReportPath = (Resolve-Path -Path $sourceAuditReport).Path
        Write-Host "Source audit report: $resolvedAuditReportPath"
    }
    Write-Host "Using saved remediation plan: $planPath"
    if ($ApplyApproved -and -not $PlanPath) {
        Write-Host "Auto-selected latest saved decision plan. Use -PlanPath to choose a specific plan." -ForegroundColor DarkYellow
    }
    $planItems = @(Get-ObjectValue -InputObject $plan -Name "PlanItems")
    Write-Host "Plan items: $($planItems.Count)"
}
else {
    Write-Step "Step 1: Windows security audit"
    if ($AuditReportPath) {
        $resolvedAuditReportPath = (Resolve-Path -Path $AuditReportPath).Path
        Write-Host "Using existing audit report: $resolvedAuditReportPath"
    }
    else {
        $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $resolvedAuditReportPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "windows-security-audit-$env:COMPUTERNAME-$timestamp.json"
        $auditArgs = @{
            OutputPath = $resolvedAuditReportPath
            Quiet      = $true
        }
        if ($IncludeHotfixes) {
            $auditArgs["IncludeHotfixes"] = $true
        }
        & $AuditScriptPath @auditArgs
        Write-Host "Audit report: $resolvedAuditReportPath"
    }

    Write-Step "Step 2: Remediation plan"
    $planPath = Get-DefaultPathFromAudit -ResolvedAuditReportPath $resolvedAuditReportPath -Prefix "windows-remediation-plan"
    & $PlanScriptPath -AuditReportPath $resolvedAuditReportPath -OutputPath $planPath -IncludeMarkdown -IncludeCsv -Quiet
    $plan = Get-Content -Path $planPath -Raw | ConvertFrom-Json
    $planItems = @(Get-ObjectValue -InputObject $plan -Name "PlanItems")
    Write-Host "Remediation plan: $planPath"
    Write-Host "Plan items: $($planItems.Count)"
}

if ($planItems.Count -eq 0) {
    Write-Host "No findings were present in the audit report. Nothing to approve." -ForegroundColor Green
    Save-Plan -Plan $plan -Path $planPath
    Write-ReviewCopies -Plan $plan -PlanPath $planPath
    return
}

if ($usingSavedPlan -and -not $reviewSavedPlanDecisions) {
    Write-Step "Step 2: Saved admin decisions"
    Update-PlanDecisionSummary -Plan $plan
    $decisionSummary = Get-ObjectValue -InputObject $plan -Name "DecisionSummary"
    Write-InfoLine -Label "Approved items" -Value (Get-ObjectValue -InputObject $decisionSummary -Name "ApprovedCount")
    Write-InfoLine -Label "Runnable approved items" -Value (Get-ObjectValue -InputObject $decisionSummary -Name "RunnableApprovedCount")
}
else {
    Write-Step "Step 3: Admin decisions"
}

if ($usingSavedPlan -and -not $reviewSavedPlanDecisions) {
    Save-Plan -Plan $plan -Path $planPath
    Write-ReviewCopies -Plan $plan -PlanPath $planPath
}
elseif ($NonInteractive) {
    foreach ($item in @($planItems)) {
        Set-PlanItemDecision -PlanItem $item -ApprovalStatus "Skipped" -Note "Skipped by -NonInteractive."
    }
    Save-Plan -Plan $plan -Path $planPath
    Write-ReviewCopies -Plan $plan -PlanPath $planPath
}
else {
    $index = 1
    foreach ($item in @($planItems)) {
        Show-PlanItemSummary -PlanItem $item -Index $index -Total $planItems.Count
        $decision = Read-PlanItemDecision -PlanItem $item
        if ($decision -eq "Quit") {
            Write-Host "Stopping review. Decisions already made in this session will be saved." -ForegroundColor Yellow
            break
        }
        $index++
    }

    Save-Plan -Plan $plan -Path $planPath
    Write-ReviewCopies -Plan $plan -PlanPath $planPath
}

$decisionSummary = Get-ObjectValue -InputObject $plan -Name "DecisionSummary"
Write-Host ""
Write-Host "Decision summary" -ForegroundColor Cyan
Write-InfoLine -Label "Approved items" -Value (Get-ObjectValue -InputObject $decisionSummary -Name "ApprovedCount")
Write-InfoLine -Label "Runnable approved items" -Value (Get-ObjectValue -InputObject $decisionSummary -Name "RunnableApprovedCount")
Write-Host "Updated plan: $planPath"
Show-ApprovedApplySummary -Plan $plan

Write-Step "Step 4: Hardening dry-run preview"
$previewReportPath = Get-DefaultPathFromPlan -ResolvedPlanPath $planPath -Prefix "windows-hardening-preview"
Invoke-HardeningPreview -PlanPath $planPath -ReportPath $previewReportPath
Write-Host "Hardening preview report: $previewReportPath"

$runnableApprovedCount = Get-RunnableApprovedCount -Plan $plan
if ($runnableApprovedCount -eq 0) {
    Write-Host "No approved runnable controls were selected, so there is nothing to apply." -ForegroundColor Yellow
    return
}

if (-not $ApplyApproved) {
    Write-Host "Dry-run complete. To apply these saved decisions, run:" -ForegroundColor Yellow
    Write-Host ".\scripts\windows\host\Start-WindowsSecurityRemediation.ps1 -PlanPath `"$planPath`" -ApplyApproved" -ForegroundColor Yellow
    return
}

Write-Step "Step 5: Final apply confirmation"
Show-ApprovedApplySummary -Plan $plan
Write-Host "Approved runnable controls: $runnableApprovedCount" -ForegroundColor Yellow
Write-Host "Type APPLY to apply the approved runnable controls now. Press Enter to stop without applying."
$confirmation = Read-Host "Final confirmation"
if ($confirmation -ne "APPLY") {
    Write-Host "Apply cancelled. No changes were made." -ForegroundColor Yellow
    return
}

$applyReportPath = Get-DefaultPathFromPlan -ResolvedPlanPath $planPath -Prefix "windows-hardening-apply"
& $HardeningScriptPath -PlanPath $planPath -ReportPath $applyReportPath -Apply
Write-Host "Apply report: $applyReportPath" -ForegroundColor Green
