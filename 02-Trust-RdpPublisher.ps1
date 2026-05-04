<#
.SYNOPSIS
Installs trust for a signed RDP file on the target/opening machine.

.DESCRIPTION
Manual user action before running:
- Copy the signed .rdp file from Script #1 to this machine.
- Copy the public .cer file from Script #1 to this machine.
- Do NOT copy/import the .pfx unless this machine should also sign RDP files.

This script:
- Requires an existing .rdp file and .cer file.
- Imports the .cer idempotently into Root and TrustedPublisher.
- Adds the certificate SHA1 thumbprint to the trusted .rdp publisher policy.
- Checks that the .rdp contains signscope:s: and signature:s:.
- Checks that signature:s: is valid Base64 and plausible.
- Optionally runs rdpsign /l if a matching private key exists locally.
- Does NOT modify the .rdp file.
- Does NOT sign the .rdp file.

.EXECUTION
.\02-Install-RdpPublisherTrust.ps1 `
  -RdpPath "$env:USERPROFILE\Desktop\RDP SHRIMPS.rdp" `
  -CerPath "$env:USERPROFILE\Desktop\RDP SHRIMPS.cer" `
  -RemoteDesktopCerPath "$env:USERPROFILE\Desktop\RDP-TLS-SHRIMPS.cer" `
  -ExpectedHostName "SHRIMPS" `
  -ExpectedUserName "\alex" `
  -RunRdpSignListTest
#>

param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$RdpPath,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$CerPath,

    [Parameter(Mandatory = $false)]
    [ValidateSet("LocalMachine", "CurrentUser")]
    [string]$Scope = "LocalMachine",

    [Parameter(Mandatory = $false)]
    [string]$ExpectedHostName,

    [Parameter(Mandatory = $false)]
    [string]$ExpectedUserName,

    [Parameter(Mandatory = $false)]
    [switch]$RunRdpSignListTest,

    [Parameter(Mandatory = $false)]
    [string]$RemoteDesktopCerPath,

    [Parameter(Mandatory = $false)]
    [switch]$SkipGpUpdate
)

$ErrorActionPreference = "Stop"

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-NoControlChars {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value
    )

    if ($Value -match "[`r`n]") {
        throw "$Name must not contain CR/LF characters."
    }
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

function Get-RdpStringSetting {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]]$Lines,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )

    if (-not $Lines -or $Lines.Count -eq 0) {
        return $null
    }

    $prefix = "$($Name):s:"

    $line = $Lines |
        Where-Object {
            $_ -and $_.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)
        } |
        Select-Object -First 1

    if (-not $line) {
        return $null
    }

    return $line.Substring($prefix.Length)
}

function Import-CertIfMissing {
    param(
        [Parameter(Mandatory = $true)][string]$CerPath,
        [Parameter(Mandatory = $true)][string]$StorePath,
        [Parameter(Mandatory = $true)][string]$Thumbprint
    )

    $existing = Get-ChildItem -Path $StorePath -ErrorAction Stop |
        Where-Object { (Get-CleanThumbprint $_.Thumbprint) -eq $Thumbprint } |
        Select-Object -First 1

    if ($existing) {
        return [pscustomobject]@{
            Store      = $StorePath
            Action     = "AlreadyPresent"
            Subject    = $existing.Subject
            Thumbprint = Get-CleanThumbprint $existing.Thumbprint
        }
    }

    $imported = Import-Certificate -FilePath $CerPath -CertStoreLocation $StorePath

    return [pscustomobject]@{
        Store      = $StorePath
        Action     = "Imported"
        Subject    = $imported.Subject
        Thumbprint = Get-CleanThumbprint $imported.Thumbprint
    }
}

function Add-TrustedRdpPublisherThumbprint {
    param(
        [Parameter(Mandatory = $true)][string]$Thumbprint,
        [Parameter(Mandatory = $true)][string]$Scope
    )

    $policyPath = if ($Scope -eq "LocalMachine") {
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    } else {
        "HKCU:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    }

    New-Item -Path $policyPath -Force | Out-Null

    $existingRaw = (Get-ItemProperty -Path $policyPath -Name "TrustedCertThumbprints" -ErrorAction SilentlyContinue).TrustedCertThumbprints

    $existing = @()
    if ($existingRaw) {
        $existing = @(
            $existingRaw -split "[,; ]+" |
                Where-Object { $_ } |
                ForEach-Object { Get-CleanThumbprint $_ }
        )
    }

    $clean = Get-CleanThumbprint $Thumbprint

    if ($existing -notcontains $clean) {
        $existing += $clean
    }

    $newValue = (($existing | Select-Object -Unique) -join ";")

    New-ItemProperty `
        -Path $policyPath `
        -Name "TrustedCertThumbprints" `
        -Value $newValue `
        -PropertyType String `
        -Force | Out-Null

    return [pscustomobject]@{
        PolicyPath = $policyPath
        Name       = "TrustedCertThumbprints"
        Value      = $newValue
    }
}

function Test-RdpSignedStructure {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RdpPath
    )

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
        throw "signature:s: line exists, but value is empty."
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
        SignaturePresent      = $true
        SignScopePresent      = $true
        SignatureBase64Check  = "OK"
        SignaturePayloadBytes = $signatureBytes.Length
        SignScopeCount        = $signScopeLines.Count
    }
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

function Find-LocalCertWithPrivateKey {
    param(
        [Parameter(Mandatory = $true)][string]$Thumbprint
    )

    $clean = Get-CleanThumbprint $Thumbprint

    $stores = @(
        "Cert:\LocalMachine\My",
        "Cert:\CurrentUser\My"
    )

    foreach ($store in $stores) {
        $cert = Get-ChildItem -Path $store -ErrorAction SilentlyContinue |
            Where-Object {
                (Get-CleanThumbprint $_.Thumbprint) -eq $clean -and
                $_.HasPrivateKey
            } |
            Select-Object -First 1

        if ($cert) {
            return [pscustomobject]@{
                Store       = $store
                Certificate = $cert
            }
        }
    }

    return $null
}

function Invoke-RdpSignListTestIfPossible {
    param(
        [Parameter(Mandatory = $true)]$CerCertificate,
        [Parameter(Mandatory = $true)][string]$RdpPath
    )

    $privateKeyCert = Find-LocalCertWithPrivateKey -Thumbprint $CerCertificate.Thumbprint

    if (-not $privateKeyCert) {
        return [pscustomobject]@{
            Status = "Skipped"
            Reason = "No matching certificate with private key found in LocalMachine\My or CurrentUser\My. This is expected on a trust-only target machine."
            RdpSignPath = $null
            ThumbprintUsed = $null
            Output = $null
        }
    }

    $rdpSignPath = Get-RdpSignPath

    $sha1Thumb = Get-CleanThumbprint $CerCertificate.Thumbprint
    $sha256Hash = Get-CertSha256Hash -Certificate $CerCertificate
    $candidates = @($sha1Thumb, $sha256Hash) | Select-Object -Unique

    $errors = New-Object System.Collections.Generic.List[string]

    foreach ($candidate in $candidates) {
        $output = & $rdpSignPath /v /sha256 $candidate /l $RdpPath 2>&1
        $exitCode = $LASTEXITCODE

        if ($exitCode -eq 0) {
            return [pscustomobject]@{
                Status = "OK"
                Reason = "rdpsign /l completed successfully without replacing the RDP file."
                RdpSignPath = $rdpSignPath
                ThumbprintUsed = $candidate
                Output = ($output -join [Environment]::NewLine)
            }
        }

        $errors.Add("Candidate=$candidate ExitCode=$exitCode Output=$($output -join ' ')")
    }

    return [pscustomobject]@{
        Status = "Failed"
        Reason = "Matching private key exists, but rdpsign /l failed."
        RdpSignPath = $rdpSignPath
        ThumbprintUsed = $null
        Output = ($errors -join " | ")
    }
}

function Install-RemoteDesktopServerCertificateTrust {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RemoteDesktopCerPath,

        [Parameter(Mandatory = $true)]
        [string]$Scope
    )

    if (-not (Test-Path -LiteralPath $RemoteDesktopCerPath)) {
        throw "Remote Desktop TLS CER file not found: $RemoteDesktopCerPath"
    }

    if ($RemoteDesktopCerPath -match "\.pfx$") {
        throw "Use public .cer only. Do not import a PFX/private key on the client for trust."
    }

    $rdpTlsCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($RemoteDesktopCerPath)
    $rdpTlsThumb = Get-CleanThumbprint $rdpTlsCert.Thumbprint

    $rootStore = if ($Scope -eq "LocalMachine") {
        "Cert:\LocalMachine\Root"
    } else {
        "Cert:\CurrentUser\Root"
    }

    $result = Import-CertIfMissing `
        -CerPath $RemoteDesktopCerPath `
        -StorePath $rootStore `
        -Thumbprint $rdpTlsThumb

    return [pscustomobject]@{
        RemoteDesktopCerPath = $RemoteDesktopCerPath
        RemoteDesktopSubject = $rdpTlsCert.Subject
        RemoteDesktopIssuer  = $rdpTlsCert.Issuer
        RemoteDesktopThumb   = $rdpTlsThumb
        Store                = $rootStore
        Action               = $result.Action
    }
}

if (-not (Test-Path -LiteralPath $RdpPath)) {
    throw "RDP file not found: $RdpPath"
}

if (-not (Test-Path -LiteralPath $CerPath)) {
    throw "CER file not found: $CerPath"
}

if ($CerPath -match "\.pfx$") {
    throw "Script #2 expects a public .cer file, not a .pfx. Do not install private keys on trust-only target machines."
}

if ($Scope -eq "LocalMachine" -and -not (Test-IsAdministrator)) {
    throw "Scope LocalMachine requires elevated PowerShell. Run as Administrator or use -Scope CurrentUser."
}

if ($ExpectedHostName) {
    Assert-NoControlChars -Name "ExpectedHostName" -Value $ExpectedHostName
}

if ($ExpectedUserName) {
    Assert-NoControlChars -Name "ExpectedUserName" -Value $ExpectedUserName
}

$cerCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CerPath)
$thumb = Get-CleanThumbprint $cerCert.Thumbprint

$rdpLines = [System.IO.File]::ReadAllLines($RdpPath)

if (-not $rdpLines -or $rdpLines.Count -eq 0) {
    throw "RDP file is empty or could not be read: $RdpPath"
}

$actualHostName = Get-RdpStringSetting -Lines $rdpLines -Name "full address"
$actualUserName = Get-RdpStringSetting -Lines $rdpLines -Name "username"

if ($ExpectedHostName -and $actualHostName -ne $ExpectedHostName) {
    throw "RDP host mismatch. Expected='$ExpectedHostName' Actual='$actualHostName'. Re-run Script #1; do not edit the RDP after signing."
}

if ($ExpectedUserName -and $actualUserName -ne $ExpectedUserName) {
    throw "RDP username mismatch. Expected='$ExpectedUserName' Actual='$actualUserName'. Re-run Script #1; do not edit the RDP after signing."
}

$rootStore = if ($Scope -eq "LocalMachine") {
    "Cert:\LocalMachine\Root"
} else {
    "Cert:\CurrentUser\Root"
}

$publisherStore = if ($Scope -eq "LocalMachine") {
    "Cert:\LocalMachine\TrustedPublisher"
} else {
    "Cert:\CurrentUser\TrustedPublisher"
}

$remoteDesktopTrust = $null

if ($RemoteDesktopCerPath) {
    $remoteDesktopTrust = Install-RemoteDesktopServerCertificateTrust `
        -RemoteDesktopCerPath $RemoteDesktopCerPath `
        -Scope $Scope
}

$signatureCheck = Test-RdpSignedStructure -RdpPath $RdpPath

$rootImport = Import-CertIfMissing `
    -CerPath $CerPath `
    -StorePath $rootStore `
    -Thumbprint $thumb

$publisherImport = Import-CertIfMissing `
    -CerPath $CerPath `
    -StorePath $publisherStore `
    -Thumbprint $thumb

$policy = Add-TrustedRdpPublisherThumbprint `
    -Thumbprint $thumb `
    -Scope $Scope

if (-not $SkipGpUpdate -and $Scope -eq "LocalMachine") {
    gpupdate /force | Out-Null
}

$rdpSignListTest = if ($RunRdpSignListTest) {
    Invoke-RdpSignListTestIfPossible -CerCertificate $cerCert -RdpPath $RdpPath
} else {
    [pscustomobject]@{
        Status = "NotRequested"
        Reason = "Use -RunRdpSignListTest to run rdpsign /l if a matching private key exists locally."
        RdpSignPath = $null
        ThumbprintUsed = $null
        Output = $null
    }
}

if ($rdpSignListTest.Status -eq "Failed") {
    throw "rdpsign /l failed. $($rdpSignListTest.Output)"
}

Write-Host ""
Write-Host "Script #2 completed successfully." -ForegroundColor Green
Write-Host ""

[pscustomobject]@{
    Scope                  = $Scope
    RdpPath                = $RdpPath
    CerPath                = $CerPath
    RdpHostName            = $actualHostName
    RdpUserName            = $actualUserName
    CertSubject            = $cerCert.Subject
    CertIssuer             = $cerCert.Issuer
    CertSHA1Thumbprint     = $thumb
    CertSHA256Hash         = Get-CertSha256Hash -Certificate $cerCert
    RootStore              = $rootStore
    RootStoreAction        = $rootImport.Action
    TrustedPublisherStore  = $publisherStore
    PublisherStoreAction   = $publisherImport.Action
    PolicyPath             = $policy.PolicyPath
    PolicyName             = $policy.Name
    PolicyValue            = $policy.Value
    SignatureBase64Check   = $signatureCheck.SignatureBase64Check
    SignaturePayloadBytes  = $signatureCheck.SignaturePayloadBytes
    SignScopeCount         = $signatureCheck.SignScopeCount
    RdpSignListTest        = $rdpSignListTest.Status
    RdpSignListTestReason  = $rdpSignListTest.Reason
    RdpSignListThumbUsed   = $rdpSignListTest.ThumbprintUsed
    RemoteDesktopTlsCertPath   = if ($remoteDesktopTrust) { $remoteDesktopTrust.RemoteDesktopCerPath } else { $null }
    RemoteDesktopTlsSubject    = if ($remoteDesktopTrust) { $remoteDesktopTrust.RemoteDesktopSubject } else { $null }
    RemoteDesktopTlsThumbprint = if ($remoteDesktopTrust) { $remoteDesktopTrust.RemoteDesktopThumb } else { $null }
    RemoteDesktopTlsTrustStore = if ($remoteDesktopTrust) { $remoteDesktopTrust.Store } else { $null }
    RemoteDesktopTlsAction     = if ($remoteDesktopTrust) { $remoteDesktopTrust.Action } else { "NotRequested" }
    Idempotence            = "Imports cert only if missing; appends thumbprint only if missing; leaves RDP unchanged; rdpsign /l is optional and skipped unless matching private key exists."
} | Format-List
