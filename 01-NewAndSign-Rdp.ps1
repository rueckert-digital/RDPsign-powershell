#requires -RunAsAdministrator
<#
.SYNOPSIS
Idempotently creates/reuses an exportable Code Signing certificate, exports CER + PFX,
copies an existing input RDP file to an output RDP file, updates host/user,
removes any old signature, signs the output RDP file, and verifies the signature.

.DESCRIPTION
Run this on the signing machine.

Default behavior:
- Input RDP:  %USERPROFILE%\Desktop\DEFAULT.RDP
- Output RDP: %USERPROFILE%\Desktop\RDP <HostName>.RDP
- FriendlyName: RDP <HostName>
- CER/PFX/state files are written next to the output artifacts.

Important:
- The input RDP file must already exist.
- This script never creates a new RDP file from scratch.
- The output RDP file is overwritten every run.
- The output RDP file is freshly signed every run.
- Script #2 should install/trust the .cer on the opening/remote client.

.EXECUTION

.\01-NewAndSign-Rdp.ps1 -HostName "HOST_OR_IP"

Further Parameters:

 -UserName "DOMAIN\user"
 -UserName "\user"
 -InputRdpPath "$env:USERPROFILE\Desktop\DEFAULT.RDP"
 -OutputRdpPath "$env:USERPROFILE\Desktop\RDP SHRIMPS.RDP"
 -FriendlyName "RDP SHRIMPS"

#>

param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$HostName,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$UserName = "$env:USERDOMAIN\$env:USERNAME",

    [Parameter(Mandatory = $false)]
    [string]$FriendlyName,

    [Parameter(Mandatory = $false)]
    [string]$InputRdpPath = "$env:USERPROFILE\Desktop\DEFAULT.RDP",

    [Parameter(Mandatory = $false)]
    [string]$OutputDirectory = "$env:USERPROFILE\Desktop",

    [Parameter(Mandatory = $false)]
    [string]$OutputRdpPath,

    [Parameter(Mandatory = $false)]
    [string]$CerPath,

    [Parameter(Mandatory = $false)]
    [string]$PfxPath,

    [Parameter(Mandatory = $false)]
    [string]$StatePath,

    [Parameter(Mandatory = $false)]
    [securestring]$PfxPassword,

    [Parameter(Mandatory = $false)]
    [int]$ValidYears = 3,

    [Parameter(Mandatory = $false)]
    [int]$MinRemainingDays = 30,

    [Parameter(Mandatory = $false)]
    [switch]$ForceNewCert
)

$ErrorActionPreference = "Stop"

function Assert-NoControlChars {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Value
    )

    if ($Value -match "[`r`n]") {
        throw "$Name must not contain CR/LF characters."
    }
}

function ConvertTo-SafeFileName {
    param([Parameter(Mandatory = $true)][string]$Value)

    $invalid = [System.IO.Path]::GetInvalidFileNameChars()
    $chars = $Value.ToCharArray() | ForEach-Object {
        if ($invalid -contains $_) { "_" } else { $_ }
    }

    return (-join $chars).Trim()
}

function Get-CleanThumbprint {
    param([Parameter(Mandatory = $true)][string]$Thumbprint)
    return ($Thumbprint -replace "\s", "").ToUpperInvariant()
}

function Get-CertSha256Hash {
    param([Parameter(Mandatory = $true)]$Certificate)

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha256.ComputeHash($Certificate.RawData)
        return (($hash | ForEach-Object { $_.ToString("X2") }) -join "")
    } finally {
        $sha256.Dispose()
    }
}

function Test-CodeSigningEku {
    param([Parameter(Mandatory = $true)]$Certificate)

    $codeSigningOid = "1.3.6.1.5.5.7.3.3"

    $ekuOids = @(
        $Certificate.EnhancedKeyUsageList | ForEach-Object {
            if ($_.ObjectId.Value) {
                $_.ObjectId.Value
            } else {
                [string]$_.ObjectId
            }
        }
    )

    return ($ekuOids -contains $codeSigningOid)
}

function Test-RdpSigningCert {
    param(
        [Parameter(Mandatory = $true)]$Certificate,
        [Parameter(Mandatory = $true)][string]$Subject,
        [Parameter(Mandatory = $true)][string]$FriendlyName,
        [Parameter(Mandatory = $true)][int]$MinRemainingDays
    )

    if (-not $Certificate) { return $false }
    if (-not $Certificate.HasPrivateKey) { return $false }
    if ($Certificate.NotAfter -le (Get-Date).AddDays($MinRemainingDays)) { return $false }
    if ($Certificate.Subject -ne $Subject) { return $false }
    if ($Certificate.FriendlyName -ne $FriendlyName) { return $false }
    if (-not (Test-CodeSigningEku -Certificate $Certificate)) { return $false }

    return $true
}

function Get-CertByThumbprint {
    param([Parameter(Mandatory = $true)][string]$Thumbprint)

    $clean = Get-CleanThumbprint $Thumbprint

    Get-ChildItem -Path Cert:\LocalMachine\My |
        Where-Object { (Get-CleanThumbprint $_.Thumbprint) -eq $clean } |
        Select-Object -First 1
}

function Get-ExistingRdpSigningCert {
    param(
        [Parameter(Mandatory = $true)][string]$Subject,
        [Parameter(Mandatory = $true)][string]$FriendlyName,
        [Parameter(Mandatory = $true)][string]$StatePath,
        [Parameter(Mandatory = $true)][int]$MinRemainingDays
    )

    if (Test-Path -LiteralPath $StatePath) {
        $stateThumb = (Get-Content -LiteralPath $StatePath -Raw).Trim()
        if ($stateThumb) {
            $stateCert = Get-CertByThumbprint -Thumbprint $stateThumb
            if (Test-RdpSigningCert -Certificate $stateCert -Subject $Subject -FriendlyName $FriendlyName -MinRemainingDays $MinRemainingDays) {
                return $stateCert
            }
        }
    }

    Get-ChildItem -Path Cert:\LocalMachine\My -CodeSigningCert |
        Where-Object {
            Test-RdpSigningCert -Certificate $_ -Subject $Subject -FriendlyName $FriendlyName -MinRemainingDays $MinRemainingDays
        } |
        Sort-Object NotAfter -Descending |
        Select-Object -First 1
}

function New-RdpSigningCert {
    param(
        [Parameter(Mandatory = $true)][string]$Subject,
        [Parameter(Mandatory = $true)][string]$FriendlyName,
        [Parameter(Mandatory = $true)][int]$ValidYears
    )

    New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject $Subject `
        -FriendlyName $FriendlyName `
        -CertStoreLocation "Cert:\LocalMachine\My" `
        -KeyAlgorithm RSA `
        -KeyLength 3072 `
        -HashAlgorithm SHA256 `
        -KeyUsage DigitalSignature `
        -KeyExportPolicy Exportable `
        -NotAfter (Get-Date).AddYears($ValidYears)
}

function Export-RdpSigningArtifacts {
    param(
        [Parameter(Mandatory = $true)]$Certificate,
        [Parameter(Mandatory = $true)][string]$CerPath,
        [Parameter(Mandatory = $true)][string]$PfxPath,
        [Parameter(Mandatory = $true)][securestring]$PfxPassword
    )

    Export-Certificate `
        -Cert $Certificate `
        -FilePath $CerPath `
        -Force | Out-Null

    Export-PfxCertificate `
        -Cert $Certificate `
        -FilePath $PfxPath `
        -Password $PfxPassword `
        -Force | Out-Null
}

function Set-RdpStringSetting {
    param(
        [Parameter(Mandatory = $true)][string[]]$Lines,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $false)][switch]$OnlyIfExists
    )

    $prefix = "$($Name):s:"
    $newLine = "$($Name):s:$Value"
    $found = $false
    $result = New-Object System.Collections.Generic.List[string]

    foreach ($line in $Lines) {
        if ($line.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            if (-not $found) {
                $result.Add($newLine)
                $found = $true
            }
        } else {
            $result.Add($line)
        }
    }

    if (-not $found -and -not $OnlyIfExists) {
        $result.Add($newLine)
    }

    return $result.ToArray()
}

function Remove-RdpSignatureFromLines {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Lines
    )

    return @(
        $Lines | Where-Object {
            $_ -notmatch "^(signature|signscope):s:"
        }
    )
}

function Remove-RdpSignature {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RdpPath
    )

    if (-not (Test-Path -LiteralPath $RdpPath)) {
        throw "Output RDP file not found before signing: $RdpPath"
    }

    $lines = [System.IO.File]::ReadAllLines($RdpPath)
    $cleanLines = Remove-RdpSignatureFromLines -Lines $lines

    [System.IO.File]::WriteAllLines(
        $RdpPath,
        [string[]]$cleanLines,
        [System.Text.Encoding]::Unicode
    )
}

function Update-RdpFileFromExistingInput {
    param(
        [Parameter(Mandatory = $true)][string]$InputRdpPath,
        [Parameter(Mandatory = $true)][string]$OutputRdpPath,
        [Parameter(Mandatory = $true)][string]$HostName,
        [Parameter(Mandatory = $true)][string]$UserName
    )

    if (-not (Test-Path -LiteralPath $InputRdpPath)) {
        throw "Input RDP file does not exist: $InputRdpPath"
    }

    $outputParent = Split-Path -Parent $OutputRdpPath
    if ($outputParent -and -not (Test-Path -LiteralPath $outputParent)) {
        New-Item -Path $outputParent -ItemType Directory -Force | Out-Null
    }

    $lines = [System.IO.File]::ReadAllLines($InputRdpPath)

    # Any change invalidates old signatures. Remove before writing/signing output.
    $lines = Remove-RdpSignatureFromLines -Lines $lines

    $lines = Set-RdpStringSetting -Lines $lines -Name "full address" -Value $HostName
    $lines = Set-RdpStringSetting -Lines $lines -Name "username" -Value $UserName

    # If present, sync this too to avoid stale target data.
    $lines = Set-RdpStringSetting -Lines $lines -Name "alternate full address" -Value $HostName -OnlyIfExists

    [System.IO.File]::WriteAllLines(
        $OutputRdpPath,
        [string[]]$lines,
        [System.Text.Encoding]::Unicode
    )
}

function Get-RdpSignPath {
    $candidates = @(
        "$env:windir\Sysnative\rdpsign.exe",
        "$env:windir\System32\rdpsign.exe"
    )

    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }

    return "rdpsign.exe"
}

function Invoke-RdpSign {
    param(
        [Parameter(Mandatory = $true)]$Certificate,
        [Parameter(Mandatory = $true)][string]$RdpPath
    )

    if (-not (Test-Path -LiteralPath $RdpPath)) {
        throw "RDP file to sign not found: $RdpPath"
    }

    $rdpSignPath = Get-RdpSignPath

    $sha1Thumb = Get-CleanThumbprint $Certificate.Thumbprint
    $sha256Thumb = Get-CertSha256Hash -Certificate $Certificate

    # Try SHA1 store thumbprint first, then SHA256 cert hash.
    # The verification below proves the actual signer.
    $candidates = @($sha1Thumb, $sha256Thumb) | Select-Object -Unique
    $errors = New-Object System.Collections.Generic.List[string]

    foreach ($candidate in $candidates) {
        $output = & $rdpSignPath /v /sha256 $candidate $RdpPath 2>&1
        $exitCode = $LASTEXITCODE

        if ($exitCode -eq 0) {
            return [pscustomobject]@{
                RdpSignPath    = $rdpSignPath
                ThumbprintUsed = $candidate
                Output         = ($output -join [Environment]::NewLine)
            }
        }

        $errors.Add("Candidate=$candidate ExitCode=$exitCode Output=$($output -join ' ')")
    }

    throw "rdpsign.exe failed for all thumbprint candidates. $($errors -join ' | ')"
}

function Test-RdpSignature {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RdpPath,

        [Parameter(Mandatory = $true)]
        $ExpectedCertificate
    )

    if (-not (Test-Path -LiteralPath $RdpPath)) {
        throw "RDP file not found: $RdpPath"
    }

    $lines = Get-Content -LiteralPath $RdpPath

    $signatureLines = @(
        $lines | Where-Object {
            $_.StartsWith("signature:s:", [System.StringComparison]::OrdinalIgnoreCase)
        }
    )

    $signScopeLines = @(
        $lines | Where-Object {
            $_.StartsWith("signscope:s:", [System.StringComparison]::OrdinalIgnoreCase)
        }
    )

    if ($signatureLines.Count -ne 1) {
        throw "Expected exactly one signature:s: line, found $($signatureLines.Count)."
    }

    if ($signScopeLines.Count -lt 1) {
        throw "Expected at least one signscope:s: line, found none."
    }

    $signatureValue = $signatureLines[0].Substring("signature:s:".Length).Trim()

    if ([string]::IsNullOrWhiteSpace($signatureValue)) {
        throw "signature:s: line exists, but signature value is empty."
    }

    # Remove whitespace defensively. Console wrapping is visual, but this also protects
    # against accidental copied line breaks or formatting damage.
    $signatureValueClean = [regex]::Replace($signatureValue, "\s+", "")

    try {
        $signatureBytes = [Convert]::FromBase64String($signatureValueClean)
    } catch {
        throw "signature:s: value is not valid Base64. Details: $($_.Exception.Message)"
    }

    if ($signatureBytes.Length -lt 256) {
        throw "signature:s: decoded successfully, but payload is suspiciously small: $($signatureBytes.Length) bytes."
    }

    return [pscustomobject]@{
        SignaturePresent       = $true
        SignScopePresent       = $true
        SignatureBase64Check   = "OK"
        SignaturePayloadBytes  = $signatureBytes.Length
        ExpectedCertSubject    = $ExpectedCertificate.Subject
        ExpectedThumbprint     = Get-CleanThumbprint $ExpectedCertificate.Thumbprint
        ChainTrustCheckedHere  = $false
        ChainTrustReason       = "RDP signature is not validated as SignedCms here. Script #2 installs Root/TrustedPublisher/RDP publisher trust on the opening client."
    }
}

Assert-NoControlChars -Name "HostName" -Value $HostName
Assert-NoControlChars -Name "UserName" -Value $UserName

if ([string]::IsNullOrWhiteSpace($FriendlyName)) {
    $FriendlyName = "RDP $HostName"
}

Assert-NoControlChars -Name "FriendlyName" -Value $FriendlyName

if (-not (Test-Path -LiteralPath $InputRdpPath)) {
    throw "Input RDP file does not exist: $InputRdpPath"
}

if (-not (Test-Path -LiteralPath $OutputDirectory)) {
    New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
}

$safeName = ConvertTo-SafeFileName $FriendlyName

if ([string]::IsNullOrWhiteSpace($OutputRdpPath)) {
    $OutputRdpPath = Join-Path $OutputDirectory "$safeName.RDP"
}

if ([string]::IsNullOrWhiteSpace($CerPath)) {
    $CerPath = Join-Path $OutputDirectory "$safeName.cer"
}

if ([string]::IsNullOrWhiteSpace($PfxPath)) {
    $PfxPath = Join-Path $OutputDirectory "$safeName.pfx"
}

if ([string]::IsNullOrWhiteSpace($StatePath)) {
    $StatePath = Join-Path $OutputDirectory "$safeName.thumbprint.txt"
}

if (-not $PfxPassword) {
    $PfxPassword = Read-Host "PFX password" -AsSecureString
}

$subject = "CN=$FriendlyName"
$cert = $null
$createdNewCert = $false

if (-not $ForceNewCert) {
    $cert = Get-ExistingRdpSigningCert `
        -Subject $subject `
        -FriendlyName $FriendlyName `
        -StatePath $StatePath `
        -MinRemainingDays $MinRemainingDays
}

if (-not $cert) {
    Write-Host "Creating exportable Code Signing certificate: $subject" -ForegroundColor Yellow
    $cert = New-RdpSigningCert -Subject $subject -FriendlyName $FriendlyName -ValidYears $ValidYears
    $createdNewCert = $true
} else {
    Write-Host "Reusing certificate: $($cert.Thumbprint)" -ForegroundColor Green
}

try {
    Export-RdpSigningArtifacts `
        -Certificate $cert `
        -CerPath $CerPath `
        -PfxPath $PfxPath `
        -PfxPassword $PfxPassword
} catch {
    if (-not $createdNewCert -and -not $ForceNewCert) {
        Write-Warning "Existing certificate could not be exported as PFX. Creating a new exportable certificate."

        $cert = New-RdpSigningCert -Subject $subject -FriendlyName $FriendlyName -ValidYears $ValidYears
        $createdNewCert = $true

        Export-RdpSigningArtifacts `
            -Certificate $cert `
            -CerPath $CerPath `
            -PfxPath $PfxPath `
            -PfxPassword $PfxPassword
    } else {
        throw
    }
}

$thumb = Get-CleanThumbprint $cert.Thumbprint
Set-Content -LiteralPath $StatePath -Value $thumb -Encoding ASCII

# Always rebuild output RDP from the existing input RDP.
Update-RdpFileFromExistingInput `
    -InputRdpPath $InputRdpPath `
    -OutputRdpPath $OutputRdpPath `
    -HostName $HostName `
    -UserName $UserName

# Force fresh signing on every run.
Remove-RdpSignature -RdpPath $OutputRdpPath

$signResult = Invoke-RdpSign -Certificate $cert -RdpPath $OutputRdpPath
$verifyResult = Test-RdpSignature -RdpPath $OutputRdpPath -ExpectedCertificate $cert

$OutPath = "$env:USERPROFILE\Desktop\RDP-TLS-$env:COMPUTERNAME.cer"

$listener = Get-CimInstance `
  -Namespace "root\cimv2\terminalservices" `
  -ClassName "Win32_TSGeneralSetting" `
  -Filter "TerminalName='RDP-tcp'"

$thumb = ($listener.SSLCertificateSHA1Hash -replace "\s","").ToUpperInvariant()

$cert = @(
  Get-ChildItem "Cert:\LocalMachine\Remote Desktop" -ErrorAction SilentlyContinue
  Get-ChildItem "Cert:\LocalMachine\My" -ErrorAction SilentlyContinue
) | Where-Object {
  ($_.Thumbprint -replace "\s","").ToUpperInvariant() -eq $thumb
} | Select-Object -First 1

if (-not $cert) {
  throw "RDP TLS certificate not found. Listener thumbprint: $thumb"
}

Export-Certificate -Cert $cert -FilePath $OutPath -Force | Out-Null

$cert | Format-List Subject, Issuer, Thumbprint, NotBefore, NotAfter
Write-Host "Exported: $OutPath"

Write-Host ""
Write-Host "Script #1 completed successfully." -ForegroundColor Green
Write-Host ""

[pscustomobject]@{
    HostName             = $HostName
    UserName             = $UserName
    FriendlyName         = $FriendlyName
    Subject              = $cert.Subject
    SHA1Thumbprint       = $thumb
    SHA256CertHash       = Get-CertSha256Hash -Certificate $cert
    CreatedNewCert       = $createdNewCert
    CertStore            = "Cert:\LocalMachine\My"
    InputRdpPath         = $InputRdpPath
    OutputRdpPath        = $OutputRdpPath
    CerPath              = $CerPath
    PfxPath              = $PfxPath
    StatePath            = $StatePath
    RdpSignThumbUsed     = $signResult.ThumbprintUsed
    SignatureCheck       = $verifyResult.SignatureBase64Check
    SignaturePayloadBytes = $verifyResult.SignaturePayloadBytes
    SignerThumbprint     = $verifyResult.ExpectedThumbprint
    ChainTrustChecked    = $verifyResult.ChainTrustCheckedHere
    Idempotence          = "Reuses state thumbprint or matching cert; overwrites CER/PFX/output RDP; never creates input RDP; removes old signature; freshly signs and verifies every run."
} | Format-List
