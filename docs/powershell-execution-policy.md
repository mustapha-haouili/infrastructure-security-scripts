# PowerShell Execution Policy Notes

For one temporary PowerShell session, use:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Then run a script:

```powershell
.\scripts\windows\Invoke-WindowsSecurityAudit.ps1
```

Execution policy is not a security boundary. It is a safety feature that controls how PowerShell loads scripts. Keep production policy aligned with your company standard.
