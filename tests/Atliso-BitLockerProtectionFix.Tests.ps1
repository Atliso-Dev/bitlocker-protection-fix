# Pester 5+. BitLocker, the TPM and the registry are mocked, so nothing on the test machine changes:
#   Invoke-Pester ./tests
# Needs an elevated Windows session (the script checks for admin first), which GitHub's Windows runners are.

BeforeAll {
  $script:Source = Get-Content (Join-Path $PSScriptRoot '..\Atliso-BitLockerProtectionFix.ps1') -Raw

  # Same rewrite Atliso Pro uses for its detection and remediation copies (Intune can't pass parameters).
  $script:ModeRe   = [regex]::new("^(\`$Mode\s*=\s*)'[A-Za-z]+'", 'Multiline')
  $script:WhatIfRe = [regex]::new('^(\$WhatIf\s*=\s*)\$(true|false)', 'Multiline')
  function script:New-Copy([string]$Mode, [bool]$WhatIf) {
    $text = $script:ModeRe.Replace($script:Source, "`${1}'$Mode'", 1)
    $text = $script:WhatIfRe.Replace($text, "`${1}`$$($WhatIf.ToString().ToLower())", 1)
    $path = Join-Path $TestDrive "fix-$Mode-$WhatIf.ps1"
    Set-Content -Path $path -Value $text
    $path
  }

  foreach ($c in 'Get-BitLockerVolume', 'Resume-BitLocker', 'Add-BitLockerKeyProtector', 'BackupToAAD-BitLockerKeyProtector', 'Get-Tpm', 'Get-CimInstance', 'Invoke-CimMethod') {
    if (-not (Get-Command $c -ErrorAction SilentlyContinue)) { New-Item -Path "function:global:$c" -Value { param($MountPoint, $KeyProtectorId, [switch]$TpmProtector, [switch]$RecoveryPasswordProtector, $Namespace, $ClassName, $Filter, $InputObject, $MethodName) } | Out-Null }
  }

  # Volume states, in order: the first call sees $Before, every later call (the re-check) sees $After.
  function script:Set-Volume($Before, $After = $Before) {
    $global:AtlisoStates = @($Before, $After)
    $global:AtlisoCalls = 0
    Mock Get-BitLockerVolume {
      $s = $global:AtlisoStates[[Math]::Min($global:AtlisoCalls, 1)]
      $global:AtlisoCalls++
      [pscustomobject]@{ VolumeStatus = $s[0]; ProtectionStatus = $s[1]; KeyProtector = @($s[2] | ForEach-Object { [pscustomobject]@{ KeyProtectorType = $_; KeyProtectorId = '{0}' } }) }
    }
  }

  function script:Invoke-Fix([string]$Mode, [bool]$WhatIf = $true) {
    $out = & (New-Copy $Mode $WhatIf) *>&1 | Out-String
    [pscustomobject]@{ Exit = $LASTEXITCODE; Output = $out }
  }
}

Describe 'Atliso-BitLockerProtectionFix' {

  BeforeEach {
    $env:LOCALAPPDATA = Join-Path $TestDrive 'appdata'   # the script logs here
    $global:AtlisoRebootPending = $false
    $global:AtlisoFve = $null
    Mock Test-Path { $global:AtlisoRebootPending } -ParameterFilter { "$Path" -like '*RebootPending' -or "$Path" -like '*RebootRequired' }
    Mock Test-Path { $null -ne $global:AtlisoFve } -ParameterFilter { "$Path" -like '*Policies\Microsoft\FVE' }
    Mock Get-ItemProperty { [pscustomobject]$global:AtlisoFve } -ParameterFilter { "$Path" -like '*Policies\Microsoft\FVE' }
    Mock Get-CimInstance { [pscustomobject]@{ DriveLetter = 'C:' } }
    Mock Invoke-CimMethod { [pscustomobject]@{ ReturnValue = 0; SuspendCount = 1 } } -RemoveParameterType InputObject
    Mock Get-Tpm { [pscustomobject]@{ TpmPresent = $true; TpmReady = $true } }
    Mock Resume-BitLocker { }
    Mock Add-BitLockerKeyProtector { }
    Mock BackupToAAD-BitLockerKeyProtector { }
  }

  Context 'Atliso Pro contract' {
    It 'has exactly one $Mode and one $WhatIf line that Pro can rewrite, defaulting to Detect and WhatIf' {
      $script:ModeRe.Matches($script:Source).Count | Should -Be 1
      $script:WhatIfRe.Matches($script:Source).Count | Should -Be 1
      $script:Source | Should -Match "(?m)^\`$Mode\s*=\s*'Detect'"
      $script:Source | Should -Match '(?m)^\$WhatIf\s*=\s*\$true'
    }
  }

  Context 'Detect' {
    It 'encrypted and protected: Compliant, exit 0' {
      Set-Volume @('FullyEncrypted', 'On', @('Tpm', 'RecoveryPassword'))
      $r = Invoke-Fix Detect
      $r.Exit | Should -Be 0
      $r.Output | Should -Match 'Compliant: Diagnosis=Healthy'
    }

    It 'encrypted, protection off, TPM protector present: Suspended, exit 1' {
      Set-Volume @('FullyEncrypted', 'Off', @('Tpm', 'RecoveryPassword'))
      $r = Invoke-Fix Detect
      $r.Exit | Should -Be 1
      $r.Output | Should -Match 'NonCompliant: Diagnosis=Suspended'
    }

    It 'suspended for a pending update reboot is expected, not flagged' {
      $global:AtlisoRebootPending = $true
      Set-Volume @('FullyEncrypted', 'Off', @('Tpm', 'RecoveryPassword'))
      $r = Invoke-Fix Detect
      $r.Exit | Should -Be 0
      $r.Output | Should -Match 'Expected after updates'
    }

    It 'encrypted with no TPM protector (waiting for activation): NoTpmProtector, exit 1' {
      Set-Volume @('FullyEncrypted', 'Off', @('RecoveryPassword'))
      $r = Invoke-Fix Detect
      $r.Exit | Should -Be 1
      $r.Output | Should -Match 'Diagnosis=NoTpmProtector'
    }

    It 'not encrypted is out of scope: exit 0' {
      Set-Volume @('FullyDecrypted', 'Off', @())
      (Invoke-Fix Detect).Exit | Should -Be 0
    }
  }

  Context 'Remediate' {
    It 'adds the missing TPM protector and resumes, never decrypts: Remediated, exit 0' {
      Set-Volume @('FullyEncrypted', 'Off', @('RecoveryPassword')) @('FullyEncrypted', 'On', @('Tpm', 'RecoveryPassword'))
      $r = Invoke-Fix Remediate $false
      $r.Exit | Should -Be 0
      $r.Output | Should -Match 'Remediated: Diagnosis=Healthy'
      Should -Invoke Add-BitLockerKeyProtector -Times 1 -Exactly -ParameterFilter { $TpmProtector }
      Should -Invoke Add-BitLockerKeyProtector -Times 0 -ParameterFilter { $RecoveryPasswordProtector }
      Should -Invoke Resume-BitLocker -Times 1 -Exactly
    }

    It 'no protectors at all: adds a recovery password and a TPM protector' {
      Set-Volume @('FullyEncrypted', 'Off', @()) @('FullyEncrypted', 'On', @('Tpm', 'RecoveryPassword'))
      (Invoke-Fix Remediate $false).Exit | Should -Be 0
      Should -Invoke Add-BitLockerKeyProtector -Times 1 -Exactly -ParameterFilter { $RecoveryPasswordProtector }
      Should -Invoke Add-BitLockerKeyProtector -Times 1 -Exactly -ParameterFilter { $TpmProtector }
    }

    It 'suspended: only resumes' {
      Set-Volume @('FullyEncrypted', 'Off', @('Tpm', 'RecoveryPassword')) @('FullyEncrypted', 'On', @('Tpm', 'RecoveryPassword'))
      (Invoke-Fix Remediate $false).Exit | Should -Be 0
      Should -Invoke Resume-BitLocker -Times 1 -Exactly
      Should -Invoke Add-BitLockerKeyProtector -Times 0
    }

    It 'policy requires a startup PIN: blocked, adds nothing, exit 1' {
      $global:AtlisoFve = @{ UseAdvancedStartup = 1; UseTPMPIN = 1 }
      Set-Volume @('FullyEncrypted', 'Off', @('RecoveryPassword'))
      $r = Invoke-Fix Remediate $false
      $r.Exit | Should -Be 1
      $r.Output | Should -Match 'BLOCKED: policy requires PIN or startup key'
      Should -Invoke Add-BitLockerKeyProtector -Times 0
      Should -Invoke Resume-BitLocker -Times 0
    }

    It 'TPM not ready: exit 1 before touching the volume' {
      Mock Get-Tpm { [pscustomobject]@{ TpmPresent = $true; TpmReady = $false } }
      Set-Volume @('FullyEncrypted', 'Off', @('RecoveryPassword'))
      $r = Invoke-Fix Remediate $false
      $r.Exit | Should -Be 1
      $r.Output | Should -Match 'TPM not ready'
      Should -Invoke Add-BitLockerKeyProtector -Times 0
    }

    It 'WhatIf: changes nothing and stays non-compliant, exit 1' {
      Set-Volume @('FullyEncrypted', 'Off', @('RecoveryPassword'))
      $r = Invoke-Fix Remediate $true
      $r.Exit | Should -Be 1
      $r.Output | Should -Match 'StillNonCompliant'
      Should -Invoke Add-BitLockerKeyProtector -Times 0
      Should -Invoke Resume-BitLocker -Times 0
    }
  }
}
