# Windows Workstation Scripts

Windows workstation scripts live here.

Use this folder for endpoint posture checks such as Defender, firewall, RDP,
LLMNR/NBNS, local admins, service risk, scheduled task, pending reboot, and
certificate audits.

Current workstation scope collection includes
`Get-WindowsWorkstationSecurityInventory.ps1` for Defender, BitLocker,
firewall, LLMNR, PowerShell logging, Remote Assistance, and local user evidence.
It also uses cross-host scripts from `../host/` for local administrator
inventory and RDP exposure evidence.

Planned scripts are tracked in [../../../docs/windows-roadmap.md](../../../docs/windows-roadmap.md).
