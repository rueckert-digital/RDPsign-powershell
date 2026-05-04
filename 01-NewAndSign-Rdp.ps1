#requires -RunAsAdministrator
<#
.SYNOPSIS
Creates/reuses an RDP file publisher signing certificate, exports artifacts, signs an RDP file, and exports the remote TLS certificate.

.DESCRIPTION
Agent map: this is Script #1 in the workflow. Run it on the signing/remote machine.
It never creates the input RDP template. It copies an existing DEFAULT.RDP-style file,
normalizes host/user fields, removes stale RDP signature fields, signs the output file,
and performs a lightweight signature-structure check.

Outputs are intentionally split:
- signed .RDP file: copy to the target/opening machine
- .CER publisher certificate: copy to the target/opening machine for trust
- .PFX publisher certificate: private-key backup/transport only; do not install on trust-only clients
- RDP-TLS-<computer>.cer: optional remote computer TLS trust certificate

.PARAMETER HostName
Remote computer name or IP written into full address:s:<value>.

.PARAMETER UserName
Username written into username:s:<value>. Use DOMAIN\user for domain users or \user / .\user for local users.

.PARAMETER FriendlyName
Certificate friendly name and default artifact name prefix. Default: RDP <HostName>.

.PARAMETER InputRdpPath
Existing RDP template path. Default: %USERPROFILE%\Desktop\DEFAULT.RDP. Must already exist.

.PARAMETER OutputDirectory
Default output folder for RDP/CER/PFX/state artifacts.

.PARAMETER OutputRdpPath
Signed output RDP path. Default: <OutputDirectory>\RDP <HostName>.RDP.

.PARAMETER CerPath
Public publisher certificate export path.

.PARAMETER PfxPath
Publisher certificate + private key export path. Sensitive.

.PARAMETER StatePath
Stores the selected signing certificate thumbprint for idempotent reuse.

.PARAMETER PfxPassword
SecureString password for .PFX export. Prompted if omitted.

.PARAMETER ValidYears
Validity period for newly created signing certificates.

.PARAMETER MinRemainingDays
Minimum remaining validity required before an existing certificate is reused.

.PARAMETER ForceNewCert
Forces creation of a new exportable Code Signing certificate.

.EXAMPLE
.\01-NewAndSign-Rdp.ps1 -HostName "HOST_OR_IP"

.EXAMPLE
.\01-NewAndSign-Rdp.ps1 `
  -HostName "SHRIMPS" `
  -UserName "\alex" `
  -InputRdpPath "$env:USERPROFILE\Desktop\DEFAULT.RDP" `
  -OutputRdpPath "$env:USERPROFILE\Desktop\RDP SHRIMPS.RDP"

.OUTPUTS
PSCustomObject with artifact paths, selected certificate thumbprints, and signature check status.

.NOTES
AI/agent safety: keep the execution phases in order: validate -> select cert -> export -> rebuild RDP -> sign -> verify -> export TLS cert.
Any RDP content change after signing invalidates the signature.
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

# * Guardrail: prevent RDP setting injection via newline characters.
function Assert-NoControlChars {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Value
    )

    if ($Value -match "[`r`n]") {
        throw "$Name must not contain CR/LF characters."
    }
}

# * Artifact naming: keep generated filenames Windows-safe.
function ConvertTo-SafeFileName {
    param([Parameter(Mandatory = $true)][string]$Value)

    $invalid = [System.IO.Path]::GetInvalidFileNameChars()
    $chars = $Value.ToCharArray() | ForEach-Object {
        if ($invalid -contains $_) { "_" } else { $_ }
    }

    return (-join $chars).Trim()
}

# * Thumbprints are compared without spaces and in invariant uppercase.
function Get-CleanThumbprint {
    param([Parameter(Mandatory = $true)][string]$Thumbprint)
    return ($Thumbprint -replace "\s", "").ToUpperInvariant()
}

# * Some rdpsign builds accept SHA1 store thumbprints; this also computes SHA256 cert hash fallback.
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

# * Certificate selector: Code Signing EKU = 1.3.6.1.5.5.7.3.3.
function Test-CodeSigningEku {
    param([Parameter(Mandatory = $true)]$Certificate)

    $codeSigningOid = "1.3.6.1.5.5.7.3.3"
    $ekuOids = @(
        $Certificate.EnhancedKeyUsageList | ForEach-Object {
            if ($_.ObjectId.Value) { $_.ObjectId.Value } else { [string]$_.ObjectId }
        }
    )

    return ($ekuOids -contains $codeSigningOid)
}

# * Idempotency predicate: a reusable signing cert must match identity, EKU, key, and lifetime.
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

# * Prefer state-file thumbprint, then fall back to matching LocalMachine\My cert.
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

# * Creates exportable key because .PFX backup/transport is a required artifact.
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

# * Public .CER is for clients; .PFX is sensitive private-key material.
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

# * RDP mutator: replace duplicate string settings with one canonical line.
function Set-RdpStringSetting {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]]$Lines,

        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $false)][switch]$OnlyIfExists
    )

    $prefix = "$($Name):s:"
    $newLine = "$($Name):s:$Value"
    $found = $false
    $result = New-Object System.Collections.Generic.List[string]

    foreach ($line in $Lines) {
        if ($line -and $line.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
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

# * Old signature fields must be removed before rewriting and signing.
function Remove-RdpSignatureFromLines {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]]$Lines
    )

    return @(
        $Lines | Where-Object {
            -not ($_ -and ($_ -match "^(signature|signscope):s:"))
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

# * Build output from an existing template only; never invent DEFAULT.RDP.
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
    $lines = Remove-RdpSignatureFromLines -Lines $lines
    $lines = Set-RdpStringSetting -Lines $lines -Name "full address" -Value $HostName
    $lines = Set-RdpStringSetting -Lines $lines -Name "username" -Value $UserName
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

# * Sign with rdpsign.exe; try SHA1 then SHA256 certificate hash for build compatibility.
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

# * Lightweight check: RDP signatures are not parsed as SignedCms here.
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
    $signatureLines = @($lines | Where-Object { $_ -and $_.StartsWith("signature:s:", [System.StringComparison]::OrdinalIgnoreCase) })
    $signScopeLines = @($lines | Where-Object { $_ -and $_.StartsWith("signscope:s:", [System.StringComparison]::OrdinalIgnoreCase) })

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
        ChainTrustReason       = "Script #2 installs Root/TrustedPublisher/RDP publisher trust on the opening client."
    }
}

# * Optional helper artifact: export the actual RDP listener TLS certificate for Script #2.
function Export-RemoteDesktopTlsCertificate {
    param(
        [Parameter(Mandatory = $true)][string]$OutPath
    )

    $listener = Get-CimInstance `
        -Namespace "root\cimv2\terminalservices" `
        -ClassName "Win32_TSGeneralSetting" `
        -Filter "TerminalName='RDP-tcp'"

    $rdpTlsThumb = ($listener.SSLCertificateSHA1Hash -replace "\s", "").ToUpperInvariant()

    $rdpTlsCert = @(
        Get-ChildItem "Cert:\LocalMachine\Remote Desktop" -ErrorAction SilentlyContinue
        Get-ChildItem "Cert:\LocalMachine\My" -ErrorAction SilentlyContinue
    ) | Where-Object {
        ($_.Thumbprint -replace "\s", "").ToUpperInvariant() -eq $rdpTlsThumb
    } | Select-Object -First 1

    if (-not $rdpTlsCert) {
        throw "RDP TLS certificate not found. Listener thumbprint: $rdpTlsThumb"
    }

    Export-Certificate -Cert $rdpTlsCert -FilePath $OutPath -Force | Out-Null

    return [pscustomobject]@{
        Path        = $OutPath
        Subject     = $rdpTlsCert.Subject
        Issuer      = $rdpTlsCert.Issuer
        Thumbprint  = Get-CleanThumbprint $rdpTlsCert.Thumbprint
        NotBefore   = $rdpTlsCert.NotBefore
        NotAfter    = $rdpTlsCert.NotAfter
    }
}

# * Phase 1: validate inputs and derive artifact paths.
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

# * Phase 2: create or reuse the RDP publisher signing certificate.
$subject = "CN=$FriendlyName"
$signingCert = $null
$createdNewCert = $false

if (-not $ForceNewCert) {
    $signingCert = Get-ExistingRdpSigningCert `
        -Subject $subject `
        -FriendlyName $FriendlyName `
        -StatePath $StatePath `
        -MinRemainingDays $MinRemainingDays
}

if (-not $signingCert) {
    Write-Host "Creating exportable Code Signing certificate: $subject" -ForegroundColor Yellow
    $signingCert = New-RdpSigningCert -Subject $subject -FriendlyName $FriendlyName -ValidYears $ValidYears
    $createdNewCert = $true
} else {
    Write-Host "Reusing certificate: $($signingCert.Thumbprint)" -ForegroundColor Green
}

# * Phase 3: export publisher trust artifacts.
try {
    Export-RdpSigningArtifacts `
        -Certificate $signingCert `
        -CerPath $CerPath `
        -PfxPath $PfxPath `
        -PfxPassword $PfxPassword
} catch {
    if (-not $createdNewCert -and -not $ForceNewCert) {
        Write-Warning "Existing certificate could not be exported as PFX. Creating a new exportable certificate."

        $signingCert = New-RdpSigningCert -Subject $subject -FriendlyName $FriendlyName -ValidYears $ValidYears
        $createdNewCert = $true

        Export-RdpSigningArtifacts `
            -Certificate $signingCert `
            -CerPath $CerPath `
            -PfxPath $PfxPath `
            -PfxPassword $PfxPassword
    } else {
        throw
    }
}

$signingThumb = Get-CleanThumbprint $signingCert.Thumbprint
Set-Content -LiteralPath $StatePath -Value $signingThumb -Encoding ASCII

# * Phase 4: rebuild output RDP, force fresh signature, then verify signature structure.
Update-RdpFileFromExistingInput `
    -InputRdpPath $InputRdpPath `
    -OutputRdpPath $OutputRdpPath `
    -HostName $HostName `
    -UserName $UserName

Remove-RdpSignature -RdpPath $OutputRdpPath

$signResult = Invoke-RdpSign -Certificate $signingCert -RdpPath $OutputRdpPath
$verifyResult = Test-RdpSignature -RdpPath $OutputRdpPath -ExpectedCertificate $signingCert

# * Phase 5: export remote computer TLS certificate for optional identity trust.
$remoteDesktopTlsPath = "$env:USERPROFILE\Desktop\RDP-TLS-$env:COMPUTERNAME.cer"
$remoteDesktopTls = Export-RemoteDesktopTlsCertificate -OutPath $remoteDesktopTlsPath

Write-Host "Exported: $($remoteDesktopTls.Path)"
Write-Host ""
Write-Host "Script #1 completed successfully." -ForegroundColor Green
Write-Host ""

[pscustomobject]@{
    HostName                    = $HostName
    UserName                    = $UserName
    FriendlyName                = $FriendlyName
    Subject                     = $signingCert.Subject
    SHA1Thumbprint              = $signingThumb
    SHA256CertHash              = Get-CertSha256Hash -Certificate $signingCert
    CreatedNewCert              = $createdNewCert
    CertStore                   = "Cert:\LocalMachine\My"
    InputRdpPath                = $InputRdpPath
    OutputRdpPath               = $OutputRdpPath
    CerPath                     = $CerPath
    PfxPath                     = $PfxPath
    StatePath                   = $StatePath
    RdpSignThumbUsed            = $signResult.ThumbprintUsed
    SignatureCheck              = $verifyResult.SignatureBase64Check
    SignaturePayloadBytes       = $verifyResult.SignaturePayloadBytes
    SignerThumbprint            = $verifyResult.ExpectedThumbprint
    RemoteDesktopTlsCertPath    = $remoteDesktopTls.Path
    RemoteDesktopTlsSubject     = $remoteDesktopTls.Subject
    RemoteDesktopTlsThumbprint  = $remoteDesktopTls.Thumbprint
    ChainTrustChecked           = $verifyResult.ChainTrustCheckedHere
    Idempotence                 = "Reuses state thumbprint or matching cert; overwrites CER/PFX/output RDP; never creates input RDP; removes old signature; freshly signs and verifies every run."
} | Format-List
