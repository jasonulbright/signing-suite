#Requires -Version 5.1
<#
.SYNOPSIS
    Signs or verifies files without the window, for build pipelines and scheduled jobs.

.DESCRIPTION
    Searches the given files and folders for every signable format, signs each file with the chosen identity, and writes
    one result object per file. The exit code is 1 when any file failed and 0 otherwise, so a pipeline step fails when
    signing fails. -WhatIf lists what would be signed.

.PARAMETER Path
    Files or folders. Folders are searched recursively.

.PARAMETER CertificateThumbprint
    Thumbprint of a code-signing certificate in CurrentUser\My or LocalMachine\My.

.PARAMETER ArtifactSigningMetadata
    metadata.json for Azure Artifact Signing. The client library is found automatically unless -DlibPath is given.

.PARAMETER DlibPath
    Digest signing library for signtool /dlib. With -ArtifactSigningMetadata, overrides the detected Artifact Signing library.

.PARAMETER DlibMetadata
    Metadata file passed to the digest signing library with /dmdf.

.PARAMETER CertificateFile
    Public certificate (.cer) for a digest signing library that does not supply one.

.PARAMETER Verify
    Checks signatures instead of signing.

.EXAMPLE
    powershell.exe -NoProfile -File .\Invoke-SigningSuite.ps1 -Path .\out -CertificateThumbprint 0123456789ABCDEF0123456789ABCDEF01234567 -TimestampMode Rfc3161 -TimestampServer http://timestamp.digicert.com

.EXAMPLE
    pwsh -NoProfile -File .\Invoke-SigningSuite.ps1 -Path .\out\App.msix -ArtifactSigningMetadata .\metadata.json -TimestampMode Rfc3161 -TimestampServer http://timestamp.acs.microsoft.com

.NOTES
    ScriptName : Invoke-SigningSuite.ps1
    Version    : 2026.09.15.0001
#>
[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Store')]
param(
    [Parameter(Mandatory, Position = 0)]
    [string[]]$Path,

    [Parameter(Mandatory, ParameterSetName = 'Store')]
    [string]$CertificateThumbprint,

    [Parameter(Mandatory, ParameterSetName = 'ArtifactSigning')]
    [string]$ArtifactSigningMetadata,

    [Parameter(ParameterSetName = 'ArtifactSigning')]
    [Parameter(Mandatory, ParameterSetName = 'Dlib')]
    [string]$DlibPath,

    [Parameter(ParameterSetName = 'Dlib')]
    [string]$DlibMetadata,

    [Parameter(ParameterSetName = 'Dlib')]
    [string]$CertificateFile,

    [Parameter(Mandatory, ParameterSetName = 'Verify')]
    [switch]$Verify,

    [ValidateSet('Auto', 'PowerShell', 'SignTool')]
    [string]$Engine = 'Auto',

    [string]$SignToolPath,

    [ValidateSet('SHA256', 'SHA384', 'SHA512')]
    [string]$DigestAlgorithm = 'SHA256',

    [ValidateSet('None', 'Rfc3161', 'Authenticode')]
    [string]$TimestampMode = 'None',

    [string]$TimestampServer,

    [switch]$DualSign,

    [switch]$SkipValid,

    [switch]$ClearOfficeSignatures,

    [string]$Description,

    [string]$DescriptionUrl
)

$ErrorActionPreference = 'Stop'
Import-Module -Name Microsoft.PowerShell.Security
Import-Module -Name (Join-Path $PSScriptRoot 'Module\SigningSuite\SigningSuite.psd1') -Force

$tool = Find-SignTool -ConfiguredPath $SignToolPath
$toolPath = if ($tool) { $tool.Path } else { '' }

if ($Verify) {
    $unreadable = 0
    $results = @(Find-SignableFile -Path $Path -UnreadableCount ([ref]$unreadable) | ForEach-Object { Test-FileSignature -LiteralPath $_ -SignToolPath $toolPath })
    if ($unreadable -gt 0) {
        Write-Warning "$unreadable path(s) could not be read (access denied, missing, or path too long)."
    }
    $results
    if (@($results | Where-Object { $_.State -in 'Invalid', 'Unknown' }).Count -gt 0) {
        exit 1
    }
    exit 0
}

$batch = @{
    Path                  = $Path
    Engine                = $Engine
    SignToolPath          = $toolPath
    DigestAlgorithm       = $DigestAlgorithm
    TimestampMode         = $TimestampMode
    TimestampServer       = $TimestampServer
    DualSign              = $DualSign
    SkipValid             = $SkipValid
    ClearOfficeSignatures = $ClearOfficeSignatures
    Description           = $Description
    DescriptionUrl        = $DescriptionUrl
    WhatIf                = $WhatIfPreference
}

switch ($PSCmdlet.ParameterSetName) {
    'Store' {
        $normalized = ($CertificateThumbprint -replace '\s', '').ToUpperInvariant()
        $certificate = Get-SigningCertificate -StoreLocation CurrentUser, LocalMachine | Where-Object Thumbprint -eq $normalized | Select-Object -First 1
        if (-not $certificate) {
            throw "No valid code-signing certificate with thumbprint $normalized and a private key is in CurrentUser\My or LocalMachine\My."
        }
        $batch.Source = 'Store'
        $batch.Certificate = $certificate
    }
    'ArtifactSigning' {
        $batch.Source = 'ArtifactSigning'
        $batch.DlibPath = if ($DlibPath) { $DlibPath } else { [string](Find-ArtifactSigningDlib) }
        $batch.MetadataPath = $ArtifactSigningMetadata
    }
    'Dlib' {
        $batch.Source = 'Dlib'
        $batch.DlibPath = $DlibPath
        $batch.MetadataPath = $DlibMetadata
        $batch.CertificateFile = $CertificateFile
    }
}

$results = @(Invoke-SigningBatch @batch)
$results
if (@($results | Where-Object Status -eq 'Failed').Count -gt 0) {
    exit 1
}
exit 0
