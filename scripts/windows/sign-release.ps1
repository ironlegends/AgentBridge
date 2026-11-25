#requires -Version 7.2
<#
.SYNOPSIS
  Initialize or sign an Agent Bridge release with a local, user-scoped CNG key.
.DESCRIPTION
  Windows / PowerShell 7.2+. No network access, private-key export, replacement,
  implicit key generation during signing, or overwrite of release outputs.

  Initialize creates agent-bridge-release-v1 in the Microsoft Software Key Storage
  Provider only if neither the named key nor the public PEM exists. A failed
  public-file publication can be recovered explicitly with -RecoverPublicKey;
  recovery exports ONLY SubjectPublicKeyInfo, never private key material.

  Sign requires the existing matching key and licenses/agent-bridge-release-public.pem.
  It produces SHA256SUMS (UTF-8, no BOM, LF) and SHA256SUMS.sig (binary DER)
  in a NEW output directory. This DER signature is compatible with:
    openssl dgst -sha256 -verify licenses/agent-bridge-release-public.pem -signature RELEASE/SHA256SUMS.sig RELEASE/SHA256SUMS
.EXAMPLE
  pwsh -NoProfile -File scripts/windows/sign-release.ps1 -Mode Initialize
.EXAMPLE
  pwsh -NoProfile -File scripts/windows/sign-release.ps1 -Mode Initialize -RecoverPublicKey
.EXAMPLE
  # Run from a PowerShell 7 prompt so -ArchivePaths receives a real string array:
  & ./scripts/windows/sign-release.ps1 -Mode Sign -ArchivePaths @('C:\releases\agent-bridge-win.zip', 'C:\releases\agent-bridge-linux.tar.gz') -OutputDirectory 'C:\releases\checksums'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Initialize', 'Sign')]
    [string] $Mode,

    [string[]] $ArchivePaths,

    [string] $OutputDirectory,

    [switch] $RecoverPublicKey
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $IsWindows) {
    throw 'This signer requires Windows CNG and a Windows user profile.'
}

$KeyName = 'agent-bridge-release-v1'
$Provider = [System.Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider
$Root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$LicenseDirectory = Join-Path $Root 'licenses'
$PublicPath = Join-Path $LicenseDirectory 'agent-bridge-release-public.pem'
$Utf8 = [Text.UTF8Encoding]::new($false, $true)
$Lf = [string][char]10

function Get-Sha256Hex {
    param([Parameter(Mandatory)][byte[]] $Bytes)

    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        return [BitConverter]::ToString($hasher.ComputeHash($Bytes)).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $hasher.Dispose()
    }
}

function Get-FileSha256Hex {
    param([Parameter(Mandatory)][string] $Path)

    # FileShare.Read denies writers/deleters while the bytes are being hashed.
    $stream = [IO.FileStream]::new(
        $Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read
    )
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        return [BitConverter]::ToString($hasher.ComputeHash($stream)).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $hasher.Dispose()
        $stream.Dispose()
    }
}

function Write-CreateNewBytes {
    param(
        [Parameter(Mandatory)][string] $Path,
        [Parameter(Mandatory)][byte[]] $Bytes
    )

    $stream = [IO.FileStream]::new(
        $Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None
    )
    try {
        $stream.Write($Bytes, 0, $Bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
}

function Assert-KeyPolicy {
    param([Parameter(Mandatory)][Security.Cryptography.CngKey] $Key)

    if ($Key.IsEphemeral -or $Key.IsMachineKey -or
        -not [string]::Equals($Key.KeyName, $KeyName, [StringComparison]::Ordinal) -or
        -not [string]::Equals($Key.Provider.Provider, $Provider.Provider, [StringComparison]::Ordinal) -or
        -not [string]::Equals(
            $Key.Algorithm.Algorithm,
            [Security.Cryptography.CngAlgorithm]::ECDsaP256.Algorithm,
            [StringComparison]::Ordinal
        ) -or
        $Key.KeySize -ne 256 -or
        $Key.KeyUsage -ne [Security.Cryptography.CngKeyUsages]::Signing -or
        $Key.ExportPolicy -ne [Security.Cryptography.CngExportPolicies]::None) {
        throw 'CNG key identity, algorithm, user scope, Signing-only usage, or non-exportability policy mismatch.'
    }
}

function Open-ReleaseKey {
    if (-not [Security.Cryptography.CngKey]::Exists(
        $KeyName, $Provider, [Security.Cryptography.CngKeyOpenOptions]::None
    )) {
        throw 'Release key absent in the current Windows user profile. Signing will not initialize a key.'
    }

    $key = [Security.Cryptography.CngKey]::Open(
        $KeyName, $Provider, [Security.Cryptography.CngKeyOpenOptions]::None
    )
    try {
        Assert-KeyPolicy -Key $key
        return $key
    }
    catch {
        $key.Dispose()
        throw
    }
}

function ConvertTo-PublicPem {
    param([Parameter(Mandatory)][byte[]] $Spki)

    $base64 = [Convert]::ToBase64String($Spki)
    $lines = [Collections.Generic.List[string]]::new()
    for ($index = 0; $index -lt $base64.Length; $index += 64) {
        $length = [Math]::Min(64, $base64.Length - $index)
        $lines.Add($base64.Substring($index, $length))
    }
    return '-----BEGIN PUBLIC KEY-----' + $Lf +
        ($lines -join $Lf) + $Lf + '-----END PUBLIC KEY-----' + $Lf
}

function Read-PublicSpki {
    if (-not [IO.File]::Exists($PublicPath)) {
        throw "Expected release public PEM is missing: $PublicPath"
    }

    $info = [IO.FileInfo]::new($PublicPath)
    $info.Refresh()
    if (($info.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Release public PEM must be a regular file, not a reparse point.'
    }

    $pem = $Utf8.GetString([IO.File]::ReadAllBytes($PublicPath))
    $match = [regex]::Match(
        $pem,
        '\A-----BEGIN PUBLIC KEY-----\r?\n(?<body>(?:[A-Za-z0-9+/=]+\r?\n)+)-----END PUBLIC KEY-----(?:\r?\n)?\z',
        [Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    if (-not $match.Success) {
        throw 'Release public PEM must contain exactly one unmodified PUBLIC KEY block.'
    }

    $base64 = [regex]::Replace($match.Groups['body'].Value, '\s', '')
    [byte[]] $spki = [Convert]::FromBase64String($base64)
    if (-not [string]::Equals([Convert]::ToBase64String($spki), $base64, [StringComparison]::Ordinal)) {
        throw 'Noncanonical base64 in release public PEM.'
    }
    return ,$spki
}

function New-PublicVerifier {
    param([Parameter(Mandatory)][byte[]] $Spki)

    $verifier = [Security.Cryptography.ECDsa]::Create()
    try {
        [int] $read = 0
        $verifier.ImportSubjectPublicKeyInfo($Spki, [ref] $read)
        if ($read -ne $Spki.Length -or $verifier.KeySize -ne 256) {
            throw 'Release SPKI is not exactly one ECDSA P-256 public key.'
        }
        return $verifier
    }
    catch {
        $verifier.Dispose()
        throw
    }
}

function Assert-PublicMatchesKey {
    param(
        [Parameter(Mandatory)][Security.Cryptography.ECDsa] $Signer,
        [Parameter(Mandatory)][byte[]] $ExpectedSpki
    )

    [byte[]] $actualSpki = $Signer.ExportSubjectPublicKeyInfo()
    $expectedFingerprint = Get-Sha256Hex -Bytes $ExpectedSpki
    $actualFingerprint = Get-Sha256Hex -Bytes $actualSpki
    if (-not [string]::Equals($expectedFingerprint, $actualFingerprint, [StringComparison]::Ordinal)) {
        throw 'Release key SPKI SHA-256 fingerprint does not match licenses/agent-bridge-release-public.pem.'
    }
    return $expectedFingerprint
}

function Publish-NewPublicPem {
    param([Parameter(Mandatory)][byte[]] $Spki)

    if (-not [IO.Directory]::Exists($LicenseDirectory)) {
        throw "Existing licenses directory required: $LicenseDirectory"
    }

    $temporary = Join-Path $LicenseDirectory (
        '.agent-bridge-release-' + [Guid]::NewGuid().ToString('N') + '.tmp'
    )
    try {
        Write-CreateNewBytes -Path $temporary -Bytes $Utf8.GetBytes((ConvertTo-PublicPem -Spki $Spki))
        # Same-directory rename is atomic. File.Move without overwrite refuses a race.
        [IO.File]::Move($temporary, $PublicPath)
    }
    finally {
        if ([IO.File]::Exists($temporary)) {
            [IO.File]::Delete($temporary)
        }
    }
}

function Assert-ReleaseFiles {
    param(
        [Parameter(Mandatory)][string] $Directory,
        [Parameter(Mandatory)][string] $ManifestHash,
        [Parameter(Mandatory)][string] $SignatureHash,
        [Parameter(Mandatory)][Security.Cryptography.ECDsa] $Verifier
    )

    [byte[]] $manifest = [IO.File]::ReadAllBytes((Join-Path $Directory 'SHA256SUMS'))
    [byte[]] $signature = [IO.File]::ReadAllBytes((Join-Path $Directory 'SHA256SUMS.sig'))
    if ((Get-Sha256Hex -Bytes $manifest) -cne $ManifestHash -or
        (Get-Sha256Hex -Bytes $signature) -cne $SignatureHash) {
        throw 'Published release files differ from the checked bytes.'
    }

    if (-not $Verifier.VerifyData(
        $manifest, $signature,
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.DSASignatureFormat]::Rfc3279DerSequence
    )) {
        throw 'DER ECDSA SHA-256 signature verification failed.'
    }
}

if ($Mode -eq 'Initialize') {
    if ($PSBoundParameters.ContainsKey('ArchivePaths') -or
        $PSBoundParameters.ContainsKey('OutputDirectory')) {
        throw 'Initialize accepts no archives or output directory.'
    }

    if (Test-Path -LiteralPath $PublicPath) {
        throw 'Public PEM already exists. Initialization and replacement are forbidden.'
    }

    $exists = [Security.Cryptography.CngKey]::Exists(
        $KeyName, $Provider, [Security.Cryptography.CngKeyOpenOptions]::None
    )
    if ($RecoverPublicKey) {
        if (-not $exists) {
            throw 'Recovery requires an existing named CNG key. No key will be created.'
        }
        $key = Open-ReleaseKey
    }
    else {
        if ($exists) {
            throw 'Named CNG key already exists. Use -Mode Initialize -RecoverPublicKey only if the PEM is missing.'
        }

        $parameters = [Security.Cryptography.CngKeyCreationParameters]::new()
        $parameters.Provider = $Provider
        $parameters.KeyCreationOptions = [Security.Cryptography.CngKeyCreationOptions]::None
        $parameters.KeyUsage = [Security.Cryptography.CngKeyUsages]::Signing
        $parameters.ExportPolicy = [Security.Cryptography.CngExportPolicies]::None
        # No OverwriteExistingKey flag: concurrent creation must fail, not rotate.
        $key = [Security.Cryptography.CngKey]::Create(
            [Security.Cryptography.CngAlgorithm]::ECDsaP256,
            $KeyName, $parameters
        )
    }

    $signer = $null
    $verifier = $null
    try {
        Assert-KeyPolicy -Key $key
        $signer = [Security.Cryptography.ECDsaCng]::new($key)
        [byte[]] $spki = $signer.ExportSubjectPublicKeyInfo()
        $verifier = New-PublicVerifier -Spki $spki

        Publish-NewPublicPem -Spki $spki
        $fingerprint = Assert-PublicMatchesKey -Signer $signer -ExpectedSpki (Read-PublicSpki)

        [pscustomobject]@{
            mode = if ($RecoverPublicKey) { 'RecoverPublicKey' } else { 'Initialize' }
            key_name = $KeyName
            provider = $Provider.Provider
            public_pem = $PublicPath
            public_spki_sha256 = $fingerprint
            private_key_exported = $false
        }
    }
    finally {
        if ($null -ne $verifier) { $verifier.Dispose() }
        if ($null -ne $signer) { $signer.Dispose() }
        $key.Dispose()
    }
    return
}

if ($PSBoundParameters.ContainsKey('RecoverPublicKey')) {
    throw '-RecoverPublicKey is only available with -Mode Initialize.'
}
if ($null -eq $ArchivePaths -or $ArchivePaths.Count -eq 0 -or
    [string]::IsNullOrWhiteSpace($OutputDirectory)) {
    throw 'Sign requires -ArchivePaths (one or more explicit files) and -OutputDirectory (a new directory).'
}

$outputPath = [IO.Path]::GetFullPath(
    $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
)
$parentPath = [IO.Path]::GetDirectoryName($outputPath)
if ([string]::IsNullOrEmpty($parentPath) -or -not [IO.Directory]::Exists($parentPath)) {
    throw 'The parent directory of -OutputDirectory must already exist.'
}
if ([IO.File]::Exists($outputPath) -or [IO.Directory]::Exists($outputPath) -or
    (Test-Path -LiteralPath $outputPath)) {
    throw 'Output directory already exists; refusing to replace or merge release files.'
}

$filesByName = [Collections.Generic.Dictionary[string, string]]::new(
    [StringComparer]::Ordinal
)
$seenNames = [Collections.Generic.HashSet[string]]::new(
    [StringComparer]::OrdinalIgnoreCase
)
foreach ($archive in $ArchivePaths) {
    if ([string]::IsNullOrWhiteSpace($archive)) {
        throw 'Archive paths must be explicit, nonempty literal file paths.'
    }

    $resolved = Resolve-Path -LiteralPath $archive -ErrorAction Stop
    if ($resolved.Provider.Name -ne 'FileSystem') {
        throw "Not a filesystem archive: $archive"
    }

    $file = [IO.FileInfo]::new($resolved.ProviderPath)
    $file.Refresh()
    if (-not $file.Exists -or
        ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Archive must be an existing regular file (not a symlink): $archive"
    }

    $simpleName = $file.Name
    if ([string]::IsNullOrEmpty($simpleName) -or $simpleName -match '[\r\n]' -or
        -not $seenNames.Add($simpleName)) {
        throw "Archive basenames must be unique, including case, and contain no newlines: $simpleName"
    }
    $filesByName.Add($simpleName, $file.FullName)
}

$names = [Collections.Generic.List[string]]::new()
foreach ($name in $filesByName.Keys) { $names.Add($name) }
$names.Sort([StringComparer]::Ordinal)

$lines = [Collections.Generic.List[string]]::new()
foreach ($name in $names) {
    $digest = Get-FileSha256Hex -Path $filesByName[$name]
    $lines.Add($digest + '  ' + $name)
}
[byte[]] $manifestBytes = $Utf8.GetBytes(($lines -join $Lf) + $Lf)
$manifestHash = Get-Sha256Hex -Bytes $manifestBytes

$key = Open-ReleaseKey
$signer = $null
$verifier = $null
$staging = $null
try {
    $signer = [Security.Cryptography.ECDsaCng]::new($key)
    [byte[]] $expectedSpki = Read-PublicSpki
    $fingerprint = Assert-PublicMatchesKey -Signer $signer -ExpectedSpki $expectedSpki
    $verifier = New-PublicVerifier -Spki $expectedSpki

    # RFC 3279 DER (not .NET's default P1363 r||s encoding): OpenSSL-compatible.
    [byte[]] $signature = $signer.SignData(
        $manifestBytes,
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.DSASignatureFormat]::Rfc3279DerSequence
    )
    if (-not $verifier.VerifyData(
        $manifestBytes, $signature,
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.DSASignatureFormat]::Rfc3279DerSequence
    )) {
        throw 'Signature failed independent verification against the expected PEM.'
    }
    $signatureHash = Get-Sha256Hex -Bytes $signature

    # Publish neither file until both have been written and cryptographically
    # checked in a fresh same-volume staging directory.
    $staging = Join-Path $parentPath (
        '.agent-bridge-sign-' + [Guid]::NewGuid().ToString('N') + '.staging'
    )
    if (Test-Path -LiteralPath $staging) {
        throw 'Unexpected staging-path collision.'
    }
    [void][IO.Directory]::CreateDirectory($staging)
    Write-CreateNewBytes -Path (Join-Path $staging 'SHA256SUMS') -Bytes $manifestBytes
    Write-CreateNewBytes -Path (Join-Path $staging 'SHA256SUMS.sig') -Bytes $signature
    Assert-ReleaseFiles -Directory $staging -ManifestHash $manifestHash -SignatureHash $signatureHash -Verifier $verifier

    # Reopen the named key and re-read the expected PEM before publication;
    # neither may have been swapped during hashing/signing.
    [byte[]] $latestSpki = Read-PublicSpki
    if ((Get-Sha256Hex -Bytes $latestSpki) -cne $fingerprint) {
        throw 'Expected public PEM changed during signing.'
    }
    $freshKey = Open-ReleaseKey
    $freshSigner = $null
    try {
        $freshSigner = [Security.Cryptography.ECDsaCng]::new($freshKey)
        [void](Assert-PublicMatchesKey -Signer $freshSigner -ExpectedSpki $latestSpki)
    }
    finally {
        if ($null -ne $freshSigner) { $freshSigner.Dispose() }
        $freshKey.Dispose()
    }

    # Directory.Move to a destination that must NOT exist publishes both at once.
    [IO.Directory]::Move($staging, $outputPath)
    $staging = $null
    Assert-ReleaseFiles -Directory $outputPath -ManifestHash $manifestHash -SignatureHash $signatureHash -Verifier $verifier

    [pscustomobject]@{
        mode = 'Sign'
        archive_count = $names.Count
        output_directory = $outputPath
        manifest = Join-Path $outputPath 'SHA256SUMS'
        signature = Join-Path $outputPath 'SHA256SUMS.sig'
        signature_format = 'ECDSA P-256 SHA-256 DER'
        public_spki_sha256 = $fingerprint
        manifest_sha256 = $manifestHash
        verified = $true
    }
}
finally {
    if ($null -ne $staging -and [IO.Directory]::Exists($staging)) {
        # Only files owned by this staging operation are removed; never recurse
        # into a caller-controlled destination.
        foreach ($name in @('SHA256SUMS', 'SHA256SUMS.sig')) {
            try { [IO.File]::Delete((Join-Path $staging $name)) } catch {}
        }
        try { [IO.Directory]::Delete($staging) } catch {}
    }
    if ($null -ne $verifier) { $verifier.Dispose() }
    if ($null -ne $signer) { $signer.Dispose() }
    $key.Dispose()
}
