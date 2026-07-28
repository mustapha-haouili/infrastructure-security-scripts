<#
.SYNOPSIS
Provides read-only, SID-based Windows built-in group discovery helpers.

.DESCRIPTION
This helper is dot-sourced by the local Administrators and Remote Desktop
collectors. Member servers and workstations use Microsoft.PowerShell.LocalAccounts
when available and fall back to the WinNT provider. Domain controllers use the
Active Directory provider because they do not have a local SAM database.

All group discovery is anchored to a well-known SID so localized Windows group
names do not affect collection. The helper does not change group membership.
#>

function Get-SecureInfraComputerDomainRole {
    try {
        if ($null -ne (Get-Command -Name "Get-CimInstance" -ErrorAction SilentlyContinue)) {
            return (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).DomainRole
        }
        if ($null -ne (Get-Command -Name "Get-WmiObject" -ErrorAction SilentlyContinue)) {
            return (Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop).DomainRole
        }
    }
    catch { }

    return $null
}

function Test-SecureInfraDomainController {
    $domainRole = Get-SecureInfraComputerDomainRole
    if ($null -ne $domainRole) {
        return [int]$domainRole -in @(4, 5)
    }

    try {
        return $null -ne (Get-Service -Name "NTDS" -ErrorAction Stop)
    }
    catch {
        return $false
    }
}

function Get-SecureInfraLocalizedBuiltinGroupName {
    param([Parameter(Mandatory = $true)][string]$Sid)

    try {
        $sidObject = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $Sid
        $account = $sidObject.Translate([System.Security.Principal.NTAccount])
        $accountName = "$($account.Value)"
        if ($accountName -match "^[^\\]+\\(.+)$") {
            return $Matches[1]
        }
        return $accountName
    }
    catch {
        return $null
    }
}

function Resolve-SecureInfraAccountNameFromSid {
    param([AllowNull()][object]$Sid)

    $sidText = "$Sid"
    if ([string]::IsNullOrWhiteSpace($sidText)) {
        return $null
    }

    try {
        $sidObject = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $sidText
        return "$($sidObject.Translate([System.Security.Principal.NTAccount]).Value)"
    }
    catch {
        return $null
    }
}

function Get-SecureInfraWinNtProperty {
    param(
        [Parameter(Mandatory = $true)][object]$DirectoryObject,
        [Parameter(Mandatory = $true)][string]$Name
    )

    try {
        return $DirectoryObject.GetType().InvokeMember(
            $Name,
            [System.Reflection.BindingFlags]::GetProperty,
            $null,
            $DirectoryObject,
            $null
        )
    }
    catch {
        return $null
    }
}

function Get-SecureInfraBuiltinGroup {
    param(
        [Parameter(Mandatory = $true)][string]$Sid,
        [Parameter(Mandatory = $true)][string]$EnglishFallbackName,
        [Parameter(Mandatory = $true)][bool]$IsDomainController
    )

    if ($IsDomainController) {
        if (
            $null -eq (Get-Command -Name "Get-ADGroup" -ErrorAction SilentlyContinue) -or
            $null -eq (Get-Command -Name "Get-ADGroupMember" -ErrorAction SilentlyContinue)
        ) {
            return $null
        }

        try {
            $directoryObject = Get-ADGroup -Identity $Sid -Properties SID -ErrorAction Stop
            return [pscustomobject][ordered]@{
                Name         = "$($directoryObject.Name)"
                SID          = "$($directoryObject.SID)"
                Provider     = "ActiveDirectory"
                SourceObject = $directoryObject
            }
        }
        catch {
            return $null
        }
    }

    $localGroupCommand = Get-Command -Name "Get-LocalGroup" -ErrorAction SilentlyContinue
    $localMemberCommand = Get-Command -Name "Get-LocalGroupMember" -ErrorAction SilentlyContinue
    if ($null -ne $localGroupCommand -and $null -ne $localMemberCommand) {
        $localGroup = $null
        try {
            $localGroup = Get-LocalGroup -SID $Sid -ErrorAction Stop
        }
        catch { }

        if ($null -eq $localGroup) {
            $localizedName = Get-SecureInfraLocalizedBuiltinGroupName -Sid $Sid
            foreach ($candidateName in @($localizedName, $EnglishFallbackName) | Select-Object -Unique) {
                if ([string]::IsNullOrWhiteSpace("$candidateName")) {
                    continue
                }
                try {
                    $localGroup = Get-LocalGroup -Name $candidateName -ErrorAction Stop
                    break
                }
                catch { }
            }
        }

        if ($null -ne $localGroup) {
            return [pscustomobject][ordered]@{
                Name         = "$($localGroup.Name)"
                SID          = "$($localGroup.SID)"
                Provider     = "LocalAccounts"
                SourceObject = $localGroup
            }
        }
    }

    $winNtGroupName = Get-SecureInfraLocalizedBuiltinGroupName -Sid $Sid
    if ([string]::IsNullOrWhiteSpace("$winNtGroupName")) {
        $winNtGroupName = $EnglishFallbackName
    }
    try {
        $winNtGroup = [ADSI]"WinNT://$env:COMPUTERNAME/$winNtGroupName,group"
        $resolvedName = "$($winNtGroup.Name)"
        if ([string]::IsNullOrWhiteSpace($resolvedName)) {
            return $null
        }
        return [pscustomobject][ordered]@{
            Name         = $resolvedName
            SID          = $Sid
            Provider     = "WinNT"
            SourceObject = $winNtGroup
        }
    }
    catch {
        return $null
    }
}

function Get-SecureInfraBuiltinGroupMembers {
    param([Parameter(Mandatory = $true)][object]$Group)

    if ($Group.Provider -eq "ActiveDirectory") {
        foreach ($directoryMember in @(Get-ADGroupMember -Identity $Group.SourceObject -ErrorAction Stop)) {
            $sidText = "$($directoryMember.SID)"
            $displayName = Resolve-SecureInfraAccountNameFromSid -Sid $directoryMember.SID
            if ([string]::IsNullOrWhiteSpace("$displayName")) {
                $displayName = "$($directoryMember.SamAccountName)"
            }
            if ([string]::IsNullOrWhiteSpace("$displayName")) {
                $displayName = "$($directoryMember.Name)"
            }
            if ([string]::IsNullOrWhiteSpace("$displayName")) {
                $displayName = $sidText
            }

            $objectClass = switch ("$($directoryMember.ObjectClass)".ToLowerInvariant()) {
                "user" { "User" }
                "group" { "Group" }
                "computer" { "Computer" }
                default { "$($directoryMember.ObjectClass)" }
            }
            [pscustomobject][ordered]@{
                Name            = $displayName
                ObjectClass     = $objectClass
                PrincipalSource = "ActiveDirectory"
                SID             = $sidText
            }
        }
        return
    }

    if ($Group.Provider -eq "LocalAccounts") {
        foreach ($localMember in @(Get-LocalGroupMember -Group $Group.SourceObject -ErrorAction Stop)) {
            [pscustomobject][ordered]@{
                Name            = "$($localMember.Name)"
                ObjectClass     = "$($localMember.ObjectClass)"
                PrincipalSource = "$($localMember.PrincipalSource)"
                SID             = "$($localMember.SID)"
            }
        }
        return
    }

    if ($Group.Provider -eq "WinNT") {
        foreach ($winNtMember in @($Group.SourceObject.psbase.Invoke("Members"))) {
            $memberName = "$(Get-SecureInfraWinNtProperty -DirectoryObject $winNtMember -Name "Name")"
            $memberClass = "$(Get-SecureInfraWinNtProperty -DirectoryObject $winNtMember -Name "Class")"
            $memberPath = "$(Get-SecureInfraWinNtProperty -DirectoryObject $winNtMember -Name "ADsPath")"
            $pathValue = $memberPath -replace "^WinNT://", ""
            $pathParts = @($pathValue -split "/")
            $authority = if ($pathParts.Count -gt 1) { $pathParts[0] } else { "" }
            $displayName = if ([string]::IsNullOrWhiteSpace($authority)) {
                $memberName
            }
            else {
                "$authority\$memberName"
            }
            $principalSource = if ($authority.Equals($env:COMPUTERNAME, [System.StringComparison]::OrdinalIgnoreCase)) {
                "Local"
            }
            else {
                "ActiveDirectory"
            }
            [pscustomobject][ordered]@{
                Name            = $displayName
                ObjectClass     = $memberClass
                PrincipalSource = $principalSource
                SID             = ""
            }
        }
        return
    }

    throw "Unsupported built-in group provider: $($Group.Provider)"
}
