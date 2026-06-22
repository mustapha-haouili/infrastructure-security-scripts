# Windows Host Scripts

Cross-host Windows scripts live here.

Use this folder for scripts that apply to both Windows Server and Windows
workstations, such as local host audits, local administrator inventory, RDP
exposure checks, hardening workflows, remediation plan generation, and event
security reporting.

Implemented cross-host collection scripts:

- `Get-WindowsLocalAdminInventory.ps1`
- `Get-WindowsRDPExposureAudit.ps1`

The root of `scripts/windows/` contains the main launcher. Implementation
scripts stay in the category folders.

Planned scripts are tracked in [../../../docs/windows-roadmap.md](../../../docs/windows-roadmap.md).
