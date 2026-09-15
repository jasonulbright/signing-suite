function Invoke-SigningBatch {
    <#
    .SYNOPSIS
        Finds signable files under the given paths and signs each one, choosing the engine per file.
    .DESCRIPTION
        The headless counterpart of the window's Sign button: files that cannot be signed are reported with the reason,
        files with a valid signature can be left alone, and -WhatIf lists what would be signed without changing anything.
    .OUTPUTS
        One object per file with Path, Name, Format, Engine, Status (Signed, Failed, Skipped, WhatIf), Detail, Passes,
        SignatureState, Signer, SignerThumbprint, Timestamped.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string[]]$Path,

        [ValidateSet('Store', 'ArtifactSigning', 'Dlib')]
        [string]$Source = 'Store',

        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [string]$DlibPath,

        [string]$MetadataPath,

        [string]$CertificateFile,

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

        [string]$DescriptionUrl,

        [int]$TimeoutSeconds = 300
    )

    switch ($Source) {
        'Store' {
            if (-not $Certificate) {
                throw 'Signing from the certificate store needs a certificate.'
            }
        }
        'ArtifactSigning' {
            if (-not $DlibPath -or -not [System.IO.File]::Exists($DlibPath)) {
                throw 'Artifact Signing needs Azure.CodeSigning.Dlib.dll; install the Artifact Signing Client Tools or pass its path.'
            }
            if (-not $MetadataPath -or -not [System.IO.File]::Exists($MetadataPath)) {
                throw 'Artifact Signing needs an existing metadata.json.'
            }
        }
        'Dlib' {
            if (-not $DlibPath -or -not [System.IO.File]::Exists($DlibPath)) {
                throw 'Digest signing needs an existing library path.'
            }
        }
    }
    if ($TimestampMode -ne 'None' -and $TimestampServer -notmatch '^https?://\S+$') {
        throw 'A timestamp needs a server URL that starts with http:// or https://.'
    }

    $signToolAvailable = [bool]$SignToolPath -and [System.IO.File]::Exists($SignToolPath)
    $offClearSig = $null
    if ($ClearOfficeSignatures) {
        $sip = Get-OfficeSipStatus | Where-Object { $_.Is64Bit -eq [Environment]::Is64BitProcess } | Select-Object -First 1
        if ($sip) {
            $offClearSig = $sip.OffClearSigPath
        }
    }

    $unreadable = 0
    $files = @(Find-SignableFile -Path $Path -UnreadableCount ([ref]$unreadable))
    if ($unreadable -gt 0) {
        Write-Warning "$unreadable path(s) could not be read (access denied, missing, or path too long)."
    }

    foreach ($file in $files) {
        $info = Get-SignableFileInfo -LiteralPath $file
        $result = [ordered]@{
            Path             = $info.Path
            Name             = $info.Name
            Format           = $info.Format
            Engine           = $null
            Status           = $info.Status
            Detail           = $info.Detail
            Passes           = 0
            SignatureState   = $info.SignatureState
            Signer           = $info.Signer
            SignerThumbprint = $info.SignerThumbprint
            Timestamped      = [bool]$info.Timestamped
        }

        if ($info.Status -eq 'Skipped') {
            [pscustomobject]$result
            continue
        }
        if ($SkipValid -and $info.SignatureState -eq 'Valid') {
            $result.Status = 'Skipped'
            $result.Detail = "Already has a valid signature from $($info.Signer)."
            [pscustomobject]$result
            continue
        }

        $provider = Get-FormatProvider -Id $info.ProviderId
        $choice = Resolve-SigningEngine -Provider $provider -Requested $Engine -SignToolAvailable $signToolAvailable -Source $Source -TimestampMode $TimestampMode
        if (-not $choice.Engine) {
            $result.Status = 'Failed'
            $result.Detail = "Not signed: $($choice.Reason)"
            [pscustomobject]$result
            continue
        }
        $result.Engine = $choice.Engine

        if (-not $PSCmdlet.ShouldProcess($file, "Sign with the $($choice.Engine) engine")) {
            $result.Status = 'WhatIf'
            [pscustomobject]$result
            continue
        }

        $parameters = @{
            LiteralPath           = $file
            Engine                = $choice.Engine
            DigestAlgorithm       = $DigestAlgorithm
            TimestampMode         = $TimestampMode
            TimestampServer       = $TimestampServer
            DualSign              = $DualSign
            ClearOfficeSignatures = $ClearOfficeSignatures
            OffClearSigPath       = $offClearSig
            Description           = $Description
            DescriptionUrl        = $DescriptionUrl
            SignToolPath          = $SignToolPath
            TimeoutSeconds        = $TimeoutSeconds
        }
        if ($Source -eq 'Store') {
            $parameters.Certificate = $Certificate
        }
        else {
            $parameters.DlibPath = $DlibPath
            $parameters.MetadataPath = $MetadataPath
            if ($Source -eq 'Dlib' -and $CertificateFile) {
                $parameters.CertificateFile = $CertificateFile
            }
        }

        try {
            $signed = Invoke-FileSigning @parameters
            $result.Status = $signed.Status
            $result.Detail = $signed.Detail
            $result.Passes = $signed.Passes
            if ($signed.SignatureState) {
                $result.SignatureState = $signed.SignatureState
                $result.Signer = $signed.Signer
                $result.SignerThumbprint = $signed.SignerThumbprint
                $result.Timestamped = $signed.Timestamped
            }
        }
        catch {
            $result.Status = 'Failed'
            $result.Detail = $_.Exception.Message
        }
        [pscustomobject]$result
    }
}
