<#
.SYNOPSIS
    Atliso-BitLockerProtectionFix.ps1

.DESCRIPTION
    Detects and fixes an OS volume that is BitLocker encrypted but NOT protected:
    "BitLocker waiting for activation", "Protection Off", "Key Protectors: None Found",
    or a suspension that never resumed.

    It never decrypts the drive. Depending on the state it:
      - Suspended (TPM protector present)  -> Resume-BitLocker
      - No TPM protector / no protectors   -> add recovery password (optional), add TPM protector, Resume-BitLocker

    Intune Remediations compatible:
      Detect mode     exit 0 = healthy or out of scope, exit 1 = issue found
      Remediate mode  exit 0 = fixed or nothing to do,  exit 1 = still broken or blocked

.NOTES
    Licence : MIT
    Version : 1.0.0
    Author  : Atliso (atliso.com)
    Requires: Windows PowerShell 5.1, elevated or SYSTEM, BitLocker and TrustedPlatformModule modules (built in).
    Log     : %LOCALAPPDATA%\Atliso\BitLockerProtectionFix.log
              As SYSTEM: C:\Windows\System32\config\systemprofile\AppData\Local\Atliso\
    Guide   : https://atliso.com/blog/bitlocker-waiting-for-activation-protection-off-fix
#>

#region CONFIG ---------------------------------------------------------------
$Mode                         = 'Detect'           # 'Detect' or 'Remediate'
$WhatIf                       = $true              # $true = log only. Set $false in the Intune remediation copy (Intune cannot pass parameters).
$MountPoint                   = $env:SystemDrive   # normally C:
$AddRecoveryPasswordIfMissing = $true              # add a 48-digit recovery password protector if none exists
$BackupToEntra                = $false             # run BackupToAAD-BitLockerKeyProtector after fixing (Entra joined devices only)
$SkipIfRebootPending          = $true              # treat "Protection Off (n reboots left)" as expected while an update reboot is pending
$ToolName                     = 'BitLockerProtectionFix'
#endregion -------------------------------------------------------------------

# --- Relaunch in 64-bit PowerShell if started from a 32-bit host -------------
if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    $native = Join-Path $env:WINDIR 'SysNative\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path $native) {
        & $native -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath
        exit $LASTEXITCODE
    }
}

$ErrorActionPreference = 'Stop'

# --- Logging ------------------------------------------------------------------
$LogDir  = Join-Path $env:LOCALAPPDATA 'Atliso'
$LogFile = Join-Path $LogDir ($ToolName + '.log')
try {
    if (-not (Test-Path $LogDir)) { New-Item -Path $LogDir -ItemType Directory -Force | Out-Null }
} catch { }

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR')][string]$Level = 'INFO'
    )
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    try { Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue } catch { }
    Write-Host $line
}

# --- Helpers ------------------------------------------------------------------
function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-PendingReboot {
    # Common servicing reboot markers (community practice, not documented on Microsoft Learn).
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    )
    foreach ($k in $keys) { if (Test-Path $k) { return $true } }
    return $false
}

function Get-FvePolicy {
    # BitLocker policy values written by GPO or the Intune BitLocker CSP.
    # 0 = do not allow, 1 = require, 2 = allow. $null = not configured.
    $path   = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
    $result = @{ UseAdvancedStartup = $null; UseTPM = $null; UseTPMPIN = $null; UseTPMKey = $null; UseTPMKeyPIN = $null }
    if (Test-Path $path) {
        $props = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
        foreach ($name in @($result.Keys)) {
            if ($null -ne $props.$name) { $result[$name] = [int]$props.$name }
        }
    }
    return $result
}

function Test-TpmOnlyAllowed {
    param([hashtable]$Policy)
    if ($Policy.UseAdvancedStartup -ne 1) { return $true }    # startup auth policy not enabled
    if ($Policy.UseTPM -eq 0)             { return $false }   # TPM-only explicitly not allowed
    foreach ($n in @('UseTPMPIN','UseTPMKey','UseTPMKeyPIN')) {
        if ($Policy[$n] -eq 1) { return $false }              # PIN or startup key required
    }
    return $true
}

function Get-SuspendCount {
    param([string]$Drive)
    # Win32_EncryptableVolume.GetSuspendCount: reboots left before protection resumes.
    # Returns ERROR_NOT_SUPPORTED if the volume is not suspended, so $null here means unknown or not suspended.
    try {
        $vol = Get-CimInstance -Namespace 'root/CIMV2/Security/MicrosoftVolumeEncryption' `
                               -ClassName Win32_EncryptableVolume -Filter ("DriveLetter='{0}'" -f $Drive)
        if ($null -eq $vol) { return $null }
        $r = Invoke-CimMethod -InputObject $vol -MethodName GetSuspendCount
        if ($r.ReturnValue -eq 0) { return [int]$r.SuspendCount }
    } catch { }
    return $null
}

function Get-ProtectionState {
    param([string]$Drive)
    $v     = Get-BitLockerVolume -MountPoint $Drive
    $types = @($v.KeyProtector | Where-Object { $_ } | ForEach-Object { [string]$_.KeyProtectorType })
    $s = [ordered]@{
        VolumeStatus     = [string]$v.VolumeStatus
        ProtectionStatus = [string]$v.ProtectionStatus
        Protectors       = $types
        HasTpm           = (@($types | Where-Object { $_ -like 'Tpm*' }).Count -gt 0)
        HasRecovery      = ($types -contains 'RecoveryPassword')
        SuspendCount     = $null
        Diagnosis        = 'Unknown'
    }
    if ($s.VolumeStatus -eq 'FullyDecrypted') {
        $s.Diagnosis = 'NotEncrypted'
    } elseif ($s.VolumeStatus -ne 'FullyEncrypted') {
        $s.Diagnosis = 'InProgress'
    } elseif ($s.ProtectionStatus -eq 'On') {
        $s.Diagnosis = 'Healthy'
    } elseif ($types.Count -eq 0) {
        $s.Diagnosis = 'NoProtectors'
    } elseif (-not $s.HasTpm) {
        $s.Diagnosis = 'NoTpmProtector'
    } else {
        $s.Diagnosis    = 'Suspended'
        $s.SuspendCount = Get-SuspendCount -Drive $Drive
    }
    return $s
}

function Format-State {
    param($s)
    return ('Diagnosis={0} VolumeStatus={1} ProtectionStatus={2} Protectors=[{3}] SuspendCount={4}' -f `
        $s.Diagnosis, $s.VolumeStatus, $s.ProtectionStatus, ($s.Protectors -join ','), $s.SuspendCount)
}

# --- Main ---------------------------------------------------------------------
Write-Log ('===== {0} start. Mode={1} WhatIf={2} User={3} =====' -f $ToolName, $Mode, $WhatIf, [Environment]::UserName)

if (-not (Test-IsAdmin)) {
    Write-Log 'Not running elevated or as SYSTEM. BitLocker cmdlets need admin rights.' 'ERROR'
    Write-Output 'ERROR: not elevated'
    exit 1
}

try {
    $state = Get-ProtectionState -Drive $MountPoint
} catch {
    Write-Log ('Get-BitLockerVolume failed: {0}' -f $_.Exception.Message) 'ERROR'
    Write-Output 'ERROR: could not read BitLocker state'
    exit 1
}
Write-Log (Format-State $state)

$rebootPending = Test-PendingReboot
$issue = $false
switch ($state.Diagnosis) {
    'Healthy'        { $issue = $false }
    'NotEncrypted'   { $issue = $false; Write-Log 'Volume is not encrypted. Out of scope for this tool (check your encryption policy).' 'WARN' }
    'InProgress'     { $issue = $false; Write-Log 'Conversion in progress. Leaving alone.' }
    'NoProtectors'   { $issue = $true }
    'NoTpmProtector' { $issue = $true }
    'Suspended' {
        if ($SkipIfRebootPending -and $rebootPending -and ($state.SuspendCount -gt 0)) {
            $issue = $false
            Write-Log ('Suspended with {0} reboot(s) left and a reboot is pending. Expected after updates, not flagging.' -f $state.SuspendCount) 'WARN'
        } else {
            $issue = $true
        }
    }
    default          { $issue = $true }
}

# --- Detect mode --------------------------------------------------------------
if ($Mode -eq 'Detect') {
    if ($issue) {
        Write-Log ('ISSUE: volume {0} is encrypted but not protected ({1}).' -f $MountPoint, $state.Diagnosis) 'WARN'
        Write-Output ('NonCompliant: {0}' -f (Format-State $state))
        exit 1
    }
    Write-Output ('Compliant: {0}' -f (Format-State $state))
    exit 0
}

# --- Remediate mode -----------------------------------------------------------
if (-not $issue) {
    Write-Log 'Nothing to remediate.'
    Write-Output ('Compliant: {0}' -f (Format-State $state))
    exit 0
}

try {
    if ($state.Diagnosis -eq 'Suspended') {
        if ($rebootPending -and ($state.SuspendCount -gt 0)) {
            Write-Log 'Reboot pending with a reboot-count suspension. Resume-BitLocker is likely to fail with "Data of this type is not supported" (0x8007065E). Reboot first.' 'WARN'
        }
        if ($WhatIf) {
            Write-Log ('WHATIF: would run Resume-BitLocker -MountPoint {0}' -f $MountPoint)
        } else {
            Write-Log ('Running Resume-BitLocker -MountPoint {0}' -f $MountPoint)
            Resume-BitLocker -MountPoint $MountPoint | Out-Null
        }
    } else {
        $tpm = $null
        try { $tpm = Get-Tpm } catch { Write-Log ('Get-Tpm failed: {0}' -f $_.Exception.Message) 'ERROR' }
        if ($null -eq $tpm -or -not $tpm.TpmPresent -or -not $tpm.TpmReady) {
            Write-Log 'TPM not present or not ready. Cannot add a TPM protector. Fix the TPM (firmware or vTPM) first.' 'ERROR'
            Write-Output 'ERROR: TPM not ready'
            exit 1
        }

        $policy = Get-FvePolicy
        Write-Log ('FVE policy: UseAdvancedStartup={0} UseTPM={1} UseTPMPIN={2} UseTPMKey={3} UseTPMKeyPIN={4}' -f `
            $policy.UseAdvancedStartup, $policy.UseTPM, $policy.UseTPMPIN, $policy.UseTPMKey, $policy.UseTPMKeyPIN)
        if (-not (Test-TpmOnlyAllowed -Policy $policy)) {
            Write-Log 'Policy requires a startup PIN or startup key, or disallows TPM-only. A TPM-only protector would conflict. Fix the BitLocker policy (set Compatible TPM startup PIN/key to Blocked for silent encryption) or add TPM+PIN interactively.' 'ERROR'
            Write-Output 'BLOCKED: policy requires PIN or startup key'
            exit 1
        }

        if (-not $state.HasRecovery -and $AddRecoveryPasswordIfMissing) {
            if ($WhatIf) {
                Write-Log 'WHATIF: would add a RecoveryPassword protector'
            } else {
                Write-Log 'Adding RecoveryPassword protector (password is not written to the log).'
                # WarningAction suppresses the console warning that prints the new recovery password.
                Add-BitLockerKeyProtector -MountPoint $MountPoint -RecoveryPasswordProtector -WarningAction SilentlyContinue | Out-Null
            }
        }

        if (-not $state.HasTpm) {
            if ($WhatIf) {
                Write-Log 'WHATIF: would add a TPM protector'
            } else {
                Write-Log 'Adding TPM protector.'
                Add-BitLockerKeyProtector -MountPoint $MountPoint -TpmProtector -WarningAction SilentlyContinue | Out-Null
            }
        }

        if ($WhatIf) {
            Write-Log ('WHATIF: would run Resume-BitLocker -MountPoint {0}' -f $MountPoint)
        } else {
            Write-Log ('Running Resume-BitLocker -MountPoint {0}' -f $MountPoint)
            Resume-BitLocker -MountPoint $MountPoint | Out-Null
        }
    }

    if ($BackupToEntra -and -not $WhatIf) {
        $v = Get-BitLockerVolume -MountPoint $MountPoint
        foreach ($kp in @($v.KeyProtector | Where-Object { [string]$_.KeyProtectorType -eq 'RecoveryPassword' })) {
            try {
                BackupToAAD-BitLockerKeyProtector -MountPoint $MountPoint -KeyProtectorId $kp.KeyProtectorId | Out-Null
                Write-Log ('Backed up recovery password protector {0} to Entra ID.' -f $kp.KeyProtectorId)
            } catch {
                Write-Log ('BackupToAAD failed for {0}: {1}' -f $kp.KeyProtectorId, $_.Exception.Message) 'WARN'
            }
        }
    }
} catch {
    Write-Log ('Remediation failed: {0}' -f $_.Exception.Message) 'ERROR'
}

# --- Re-check -----------------------------------------------------------------
try {
    $after = Get-ProtectionState -Drive $MountPoint
    Write-Log ('After: {0}' -f (Format-State $after))
    if ($after.Diagnosis -eq 'Healthy') {
        Write-Log 'Protection is On. Reboot before checking Intune "Require BitLocker" compliance.'
        Write-Output ('Remediated: {0}' -f (Format-State $after))
        exit 0
    }
    if ($WhatIf) { Write-Log 'WhatIf mode: no changes made, so the issue remains.' 'WARN' }
    Write-Output ('StillNonCompliant: {0}' -f (Format-State $after))
    exit 1
} catch {
    Write-Log ('Re-check failed: {0}' -f $_.Exception.Message) 'ERROR'
    exit 1
}
