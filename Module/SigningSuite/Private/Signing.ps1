function Get-OfficeSipStatus {
    <#
    .SYNOPSIS
        Reports Office SIP registration in the 64-bit and 32-bit registry views, with the DLL folders.
    #>
    [CmdletBinding()]
    param()

    $views = [System.Collections.Generic.List[Microsoft.Win32.RegistryView]]::new()
    $views.Add([Microsoft.Win32.RegistryView]::Registry32)
    if ([Environment]::Is64BitOperatingSystem) {
        $views.Add([Microsoft.Win32.RegistryView]::Registry64)
    }

    foreach ($view in $views) {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
        try {
            $result = [ordered]@{
                Is64Bit        = $view -eq [Microsoft.Win32.RegistryView]::Registry64
                OpenXml        = $false
                Legacy         = $false
                OpenXmlDll     = $null
                LegacyDll      = $null
                OffClearSigPath = $null
            }
            foreach ($kind in 'OpenXml', 'Legacy') {
                $braced = '{' + $script:OfficeSipGuids[$kind].ToUpperInvariant() + '}'
                $key = $base.OpenSubKey("SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllIsMyFileType2\$braced")
                if ($key) {
                    try {
                        $result[$kind] = $true
                        $result["${kind}Dll"] = [Environment]::ExpandEnvironmentVariables([string]$key.GetValue('Dll'))
                    }
                    finally {
                        $key.Close()
                    }
                }
            }
            foreach ($dll in $result.LegacyDll, $result.OpenXmlDll) {
                if ($dll -and -not $result.OffClearSigPath) {
                    $candidate = Join-Path ([System.IO.Path]::GetDirectoryName($dll)) 'offclearsig.exe'
                    if ([System.IO.File]::Exists($candidate)) {
                        $result.OffClearSigPath = $candidate
                    }
                }
            }
            [pscustomobject]$result
        }
        finally {
            $base.Close()
        }
    }
}

function Clear-OfficeVbaSignature {
    <#
    .SYNOPSIS
        Removes every VBA signature from an Office file with offclearsig.exe from the Office SIP package.
    .DESCRIPTION
        Call only for files the Office SIP recognizes; offclearsig.exe crashes on other file types.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$LiteralPath,

        [Parameter(Mandatory)]
        [string]$OffClearSigPath,

        [int]$TimeoutSeconds = 120
    )

    if (-not $PSCmdlet.ShouldProcess($LiteralPath, 'Remove VBA signatures')) {
        return
    }
    $run = Invoke-ExternalProcess -FilePath $OffClearSigPath -ArgumentList @($LiteralPath) -TimeoutSeconds $TimeoutSeconds
    $message = (($run.Output + "`n" + $run.Error) -split "`r?`n" | Where-Object { $_ -match '^\s*Error:' } | ForEach-Object { $_.Trim() }) -join ' '
    [pscustomobject]@{
        Success  = $run.ExitCode -eq 0
        ExitCode = $run.ExitCode
        TimedOut = $run.TimedOut
        Message  = if ($run.TimedOut) { 'offclearsig.exe timed out.' } elseif ($message) { $message } elseif ($run.ExitCode -ne 0) { "offclearsig.exe exited with code $($run.ExitCode)." } else { '' }
    }
}

function New-SigningResult {
    param(
        [string]$Path,
        [string]$Status,
        [string]$Detail,
        [int]$Passes = 0,
        [object]$Signature
    )

    [pscustomobject]@{
        Path             = $Path
        Status           = $Status
        Detail           = $Detail
        Passes           = $Passes
        SignatureState   = if ($Signature) { $Signature.State } else { '' }
        Signer           = if ($Signature) { $Signature.Signer } else { $null }
        SignerThumbprint = if ($Signature) { $Signature.Thumbprint } else { $null }
        Timestamped      = if ($Signature) { [bool]$Signature.Timestamped } else { $false }
    }
}

function Invoke-FileSigning {
    <#
    .SYNOPSIS
        Signs one file with the PowerShell engine (Set-AuthenticodeSignature), the SignTool engine (signtool.exe), or,
        for Access databases, the Access engine (MSACCESS.EXE /sign).
    .OUTPUTS
        Object with Path, Status (Signed, Failed, Skipped), Detail, Passes, SignatureState, Signer, SignerThumbprint, Timestamped.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$LiteralPath,

        [ValidateSet('PowerShell', 'SignTool', 'Access')]
        [string]$Engine = 'PowerShell',

        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [ValidateSet('CurrentUser', 'LocalMachine')]
        [string]$StoreLocation = 'CurrentUser',

        [string]$SignToolPath,

        [string]$AccessPath,

        [string]$DlibPath,

        [string]$MetadataPath,

        [string]$CertificateFile,

        [ValidateSet('SHA256', 'SHA384', 'SHA512')]
        [string]$DigestAlgorithm = 'SHA256',

        [ValidateSet('None', 'Rfc3161', 'Authenticode')]
        [string]$TimestampMode = 'None',

        [string]$TimestampServer,

        [ValidateRange(0, 10)]
        [int]$TimestampRetryCount = 3,

        [ValidateRange(0, 60)]
        [int]$TimestampRetryDelaySeconds = 3,

        [switch]$DualSign,

        [switch]$ClearOfficeSignatures,

        [string]$OffClearSigPath,

        [string]$Description,

        [string]$DescriptionUrl,

        [ValidateSet('Signer', 'NotRoot', 'All')]
        [string]$IncludeChain = 'NotRoot',

        [int]$TimeoutSeconds = 300
    )

    $provider = Get-FormatProvider -Extension ([System.IO.Path]::GetExtension($LiteralPath))
    if (-not $provider) {
        return New-SigningResult -Path $LiteralPath -Status 'Skipped' -Detail 'Not a signable file type.'
    }
    if ($provider.Engines -notcontains $Engine) {
        return New-SigningResult -Path $LiteralPath -Status 'Failed' -Detail "$($provider.Name) files need the $($provider.Engines -join ' or ') engine."
    }
    if (-not [System.IO.File]::Exists($LiteralPath)) {
        return New-SigningResult -Path $LiteralPath -Status 'Failed' -Detail 'The file no longer exists.'
    }
    if ([System.IO.FileInfo]::new($LiteralPath).IsReadOnly) {
        return New-SigningResult -Path $LiteralPath -Status 'Failed' -Detail 'The file is read-only.'
    }
    if ($TimestampMode -ne 'None' -and -not $TimestampServer) {
        return New-SigningResult -Path $LiteralPath -Status 'Failed' -Detail 'A timestamp was requested without a timestamp server.'
    }

    if ($Engine -eq 'Access') {
        $access = @{
            LiteralPath                = $LiteralPath
            AccessPath                 = $AccessPath
            Certificate                = $Certificate
            DigestAlgorithm            = $DigestAlgorithm
            TimestampMode              = $TimestampMode
            TimestampServer            = $TimestampServer
            TimestampRetryCount        = $TimestampRetryCount
            TimestampRetryDelaySeconds = $TimestampRetryDelaySeconds
            # Access reports a failure in a dialog and waits, so the wait is shorter than for signtool.
            TimeoutSeconds             = [Math]::Min($TimeoutSeconds, 90)
        }
        return Invoke-AccessFileSigning @access
    }

    # Set-AuthenticodeSignature keeps a file with no registered SIP open in this process until the process exits.
    $sip = Get-SipSubject -LiteralPath $LiteralPath
    if (-not $sip.Supported) {
        return New-SigningResult -Path $LiteralPath -Status 'Failed' -Detail (Get-SipGapMessage -LiteralPath $LiteralPath -Provider $provider)
    }

    $expectedThumbprint = $null
    if ($Certificate) {
        $expectedThumbprint = $Certificate.Thumbprint
    }
    elseif ($CertificateFile) {
        try {
            $fileCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertificateFile)
            $expectedThumbprint = $fileCertificate.Thumbprint
            $fileSubject = $fileCertificate.Subject
            $fileCertificate.Dispose()
        }
        catch {
            return New-SigningResult -Path $LiteralPath -Status 'Failed' -Detail "The certificate file could not be read: $($_.Exception.Message)"
        }
    }

    $expectedSubject = if ($Certificate) { $Certificate.Subject } elseif ($CertificateFile) { $fileSubject } else { $null }
    if ($provider.Id -eq 'AppPackage' -and $expectedSubject) {
        try {
            $identity = Get-AppPackageIdentity -LiteralPath $LiteralPath
            if (-not (Test-CertificateMatchesPublisher -Publisher $identity.Publisher -Subject $expectedSubject)) {
                return New-SigningResult -Path $LiteralPath -Status 'Failed' -Detail "The package Publisher '$($identity.Publisher)' does not match the certificate subject '$expectedSubject'."
            }
        }
        catch {
            return New-SigningResult -Path $LiteralPath -Status 'Failed' -Detail "Not a readable app package: $($_.Exception.Message)"
        }
    }

    $clearOffice = $provider.Id -eq 'OfficeVba' -and $ClearOfficeSignatures
    if ($clearOffice -and (-not $OffClearSigPath -or -not [System.IO.File]::Exists($OffClearSigPath))) {
        return New-SigningResult -Path $LiteralPath -Status 'Failed' -Detail 'offclearsig.exe from the Office SIP package was not found, so existing VBA signatures could not be cleared.'
    }
    # Clearing destroys the existing VBA signatures, so it runs only after every check that can refuse the run.
    $clearSignatures = {
        $cleared = Clear-OfficeVbaSignature -LiteralPath $LiteralPath -OffClearSigPath $OffClearSigPath -Confirm:$false
        if (-not $cleared.Success) {
            New-SigningResult -Path $LiteralPath -Status 'Failed' -Detail "Existing VBA signatures could not be cleared: $($cleared.Message)"
        }
    }

    $passes = [int]$provider.SignPasses
    $notes = [System.Collections.Generic.List[string]]::new()
    $completed = 0

    if ($Engine -eq 'PowerShell') {
        if (-not $Certificate) {
            return New-SigningResult -Path $LiteralPath -Status 'Failed' -Detail 'The PowerShell engine needs a certificate from the certificate store.'
        }
        if ($TimestampMode -eq 'Rfc3161') {
            return New-SigningResult -Path $LiteralPath -Status 'Failed' -Detail 'RFC 3161 timestamps need the SignTool engine; the PowerShell engine adds Authenticode timestamps.'
        }
        if ($DualSign) {
            $notes.Add('Dual signing needs the SignTool engine; signed once.')
        }
        $parameters = @{
            LiteralPath   = $LiteralPath
            Certificate   = $Certificate
            HashAlgorithm = $DigestAlgorithm
            IncludeChain  = $IncludeChain
            ErrorAction   = 'Stop'
        }
        if ($TimestampMode -ne 'None') {
            $parameters.TimestampServer = $TimestampServer
        }
        if ($clearOffice) {
            $refusal = & $clearSignatures
            if ($refusal) {
                return $refusal
            }
        }
        $total = $passes
    }
    else {
        if (-not $SignToolPath -or -not [System.IO.File]::Exists($SignToolPath)) {
            return New-SigningResult -Path $LiteralPath -Status 'Failed' -Detail 'signtool.exe was not found. Install the Windows SDK signing tools or set the signtool path.'
        }
        $thumbprint = if ($Certificate -and -not $CertificateFile) { $Certificate.Thumbprint } else { $null }

        $plan = [System.Collections.Generic.List[hashtable]]::new()
        $common = @{
            LiteralPath     = $LiteralPath
            Thumbprint      = $thumbprint
            StoreLocation   = $StoreLocation
            CertificateFile = $CertificateFile
            DlibPath        = $DlibPath
            MetadataPath    = $MetadataPath
            Description     = $Description
            DescriptionUrl  = $DescriptionUrl
        }
        if ($DualSign -and $provider.SupportsAppend) {
            $first = $common.Clone()
            $first.DigestAlgorithm = 'SHA1'
            if ($TimestampMode -ne 'None') {
                $first.TimestampMode = 'Authenticode'
                $first.TimestampServer = $TimestampServer
            }
            $plan.Add($first)
            $second = $common.Clone()
            $second.DigestAlgorithm = $DigestAlgorithm
            $second.TimestampMode = $TimestampMode
            $second.TimestampServer = $TimestampServer
            $second.AppendSignature = $true
            $plan.Add($second)
        }
        else {
            if ($DualSign) {
                $notes.Add("$($provider.Name) files hold one signature; signed with $DigestAlgorithm only.")
            }
            for ($pass = 1; $pass -le $passes; $pass++) {
                $single = $common.Clone()
                $single.DigestAlgorithm = $DigestAlgorithm
                $single.TimestampMode = $TimestampMode
                $single.TimestampServer = $TimestampServer
                $plan.Add($single)
            }
        }

        $total = $plan.Count
        $argumentSets = [System.Collections.Generic.List[object]]::new()
        foreach ($passParameters in $plan) {
            try {
                $argumentSets.Add([string[]](New-SignToolSignArgument @passParameters))
            }
            catch {
                return New-SigningResult -Path $LiteralPath -Status 'Failed' -Detail $_.Exception.Message
            }
        }
        if ($clearOffice) {
            $refusal = & $clearSignatures
            if ($refusal) {
                return $refusal
            }
        }
    }

    # An attempt runs every pass again from the first. For other formats the first pass replaces all signatures, so a
    # retry never stacks an extra appended signature. The Office SIPs add to the VBA signatures already in the file
    # (a file that holds them gets only a new V3 signature), so an Office retry clears them first. That is safe only
    # when the file held no VBA signature before this run, or when the run cleared them already.
    $attempts = if ($TimestampMode -ne 'None') { $TimestampRetryCount + 1 } else { 1 }
    $officeRetry = $provider.Id -eq 'OfficeVba'
    if ($officeRetry -and $attempts -gt 1) {
        if (-not $OffClearSigPath) {
            $sip = Get-OfficeSipStatus | Where-Object { $_.Is64Bit -eq [Environment]::Is64BitProcess } | Select-Object -First 1
            if ($sip) {
                $OffClearSigPath = $sip.OffClearSigPath
            }
        }
        $canClear = $OffClearSigPath -and [System.IO.File]::Exists($OffClearSigPath)
        if (-not $canClear -or (-not $clearOffice -and (Get-FileSignatureState -LiteralPath $LiteralPath).State -ne 'NotSigned')) {
            $attempts = 1
        }
    }
    for ($attempt = 1; $attempt -le $attempts; $attempt++) {
        if ($attempt -gt 1) {
            Start-Sleep -Seconds $TimestampRetryDelaySeconds
            if ($officeRetry) {
                $refusal = & $clearSignatures
                if ($refusal) {
                    return $refusal
                }
            }
        }
        $completed = 0
        $warnings = [System.Collections.Generic.List[string]]::new()
        $retry = $false
        for ($index = 0; $index -lt $total; $index++) {
            $pass = $index + 1
            $failure = $null
            $failureText = $null
            if ($Engine -eq 'PowerShell') {
                try {
                    $signature = Set-AuthenticodeSignature @parameters
                }
                catch {
                    $failure = $_.Exception.Message
                    $failureText = $failure
                }
                if (-not $failure -and (-not $signature.SignerCertificate -or $signature.SignerCertificate.Thumbprint -ne $Certificate.Thumbprint)) {
                    if ($provider.Id -eq 'OfficeVba' -and $pass -eq 1 -and $signature.StatusMessage -match '800403f3') {
                        return New-SigningResult -Path $LiteralPath -Status 'Skipped' -Detail 'No VBA project.'
                    }
                    # For a file a Windows catalog covers, the returned signature is the catalog's, not the one just embedded.
                    $embedded = Get-FileSignatureState -LiteralPath $LiteralPath
                    if ($embedded.Thumbprint -ne $Certificate.Thumbprint) {
                        $failure = "$($signature.Status): $($signature.StatusMessage)"
                        $failureText = $failure
                    }
                }
            }
            else {
                $run = Invoke-SignTool -SignToolPath $SignToolPath -ArgumentList $argumentSets[$index] -TimeoutSeconds $TimeoutSeconds
                if ($run.ExitCode -notin 0, 2) {
                    if ($provider.Id -eq 'OfficeVba' -and $pass -eq 1 -and ($run.Output + $run.Error) -match '800403f3') {
                        return New-SigningResult -Path $LiteralPath -Status 'Skipped' -Detail 'No VBA project.'
                    }
                    $failure = Get-SignToolFailureMessage -Run $run
                    $failureText = $run.Output + "`n" + $run.Error
                }
                else {
                    foreach ($warning in $run.Warnings) {
                        if (-not $warnings.Contains($warning)) {
                            $warnings.Add($warning)
                        }
                    }
                }
            }
            if ($failure) {
                $timestampFailure = Test-TimestampFailureText -Text $failureText
                if ($attempt -lt $attempts -and $timestampFailure) {
                    $retry = $true
                    break
                }
                if ($attempts -gt 1 -and $timestampFailure) {
                    $failure = "$($failure.TrimEnd()) Failed after $attempts attempts."
                }
                return New-SigningResult -Path $LiteralPath -Status 'Failed' -Passes $completed -Detail (Format-PassFailure -Pass $pass -Passes $total -Completed $completed -Message $failure)
            }
            $completed = $pass
        }
        if ($retry) {
            continue
        }

        $state = Get-FileSignatureState -LiteralPath $LiteralPath
        # The state shows one signature only. A timestamp warning from any pass also means a signature has no timestamp,
        # for example the appended signature of a dual-signed file.
        $timestampMissing = -not $state.Timestamped -or @($warnings | Where-Object { Test-TimestampFailureText -Text $_ }).Count -gt 0
        $signedAsExpected = $state.State -notin 'NotSigned', 'Invalid', 'Unknown' -and (-not $expectedThumbprint -or $state.Thumbprint -eq $expectedThumbprint)
        if ($TimestampMode -ne 'None' -and $timestampMissing -and $signedAsExpected -and $attempt -lt $attempts) {
            continue
        }
        break
    }
    foreach ($warning in $warnings) {
        if (-not $notes.Contains($warning)) {
            $notes.Add($warning)
        }
    }

    if ($state.State -in 'NotSigned', 'Invalid', 'Unknown') {
        return New-SigningResult -Path $LiteralPath -Status 'Failed' -Passes $completed -Signature $state -Detail "Signing reported success but the file is $($state.State): $($state.Message)"
    }
    if ($expectedThumbprint -and $state.Thumbprint -ne $expectedThumbprint) {
        return New-SigningResult -Path $LiteralPath -Status 'Failed' -Passes $completed -Signature $state -Detail "The file carries a signature from $($state.Signer), not the selected certificate."
    }

    if ($TimestampMode -ne 'None' -and $timestampMissing) {
        $tries = if ($attempts -gt 1) { " after $attempts attempts" } else { '' }
        return New-SigningResult -Path $LiteralPath -Status 'Failed' -Passes $completed -Signature $state -Detail "The file was signed without the requested timestamp; $TimestampServer could not be reached or refused the request$tries. Sign again when the server is reachable, or choose no timestamp."
    }
    $summary = if ($state.State -eq 'Valid') { 'Signed and verified.' } else { "Signed; not trusted on this PC: $($state.Message)" }
    $notes.Insert(0, $summary)
    if ($attempt -gt 1) {
        $notes.Insert(1, "Timestamped on attempt $attempt of $attempts.")
    }
    New-SigningResult -Path $LiteralPath -Status 'Signed' -Passes $completed -Signature $state -Detail ($notes -join ' ')
}

function Test-TimestampFailureText {
    <#
    .SYNOPSIS
        True when signing output says the timestamp server could not be reached or refused the request.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [AllowEmptyString()]
        [AllowNull()]
        [string]$Text
    )

    [bool]($Text -match '(?i)timestamp server|attempting to timestamp|time-stamp server')
}

function Format-PassFailure {
    param(
        [int]$Pass,
        [int]$Passes,
        [int]$Completed,
        [string]$Message
    )

    if ($Passes -le 1) {
        return $Message
    }
    if ($Completed -eq 0) {
        return "Pass 1 of ${Passes} failed: $Message"
    }
    "Signed $Completed of $Passes passes; pass $Pass failed: $Message"
}

function Get-SignToolFailureMessage {
    param([object]$Run)

    if ($Run.TimedOut) {
        return 'signtool.exe timed out.'
    }
    $lines = [System.Collections.Generic.List[string]]::new()
    foreach ($line in $Run.Errors) {
        if ($line -notmatch '^An error occurred while attempting to sign' -and -not $lines.Contains($line)) {
            $lines.Add($line)
        }
    }
    $information = (($Run.Output + "`n" + $Run.Error) -split "`r?`n" | Where-Object { $_ -match '^\s*Error information:' } | ForEach-Object { ($_ -replace '^\s*Error information:\s*', '').Trim() })
    foreach ($line in $information) {
        $lines.Add($line)
    }
    if ($lines.Count -eq 0) {
        return "signtool.exe exited with code $($Run.ExitCode)."
    }
    $text = $lines -join ' '
    if ($text -match '0x8007000b') {
        $text += ' For app packages this means the manifest Publisher does not match the certificate subject.'
    }
    # A digest signing library reports service failures as an HTTP status in its exception text, and signtool then
    # reports only "SignerSign() failed (0x80004005)".
    $status = [regex]::Match(($Run.Output + "`n" + $Run.Error), '(?m)^\s*Status:\s*(\d{3})')
    if ($status.Success) {
        $hint = switch ($status.Groups[1].Value) {
            '401' { 'The signing service rejected the sign-in (401). Sign in with az login, or set AZURE_CLIENT_ID, AZURE_TENANT_ID and AZURE_CLIENT_SECRET.' }
            '403' { 'The signing service refused the request (403). Give the signed-in identity the Artifact Signing Certificate Profile Signer role, and check the endpoint region, account name and certificate profile name.' }
            '404' { 'The signing service did not find the account or certificate profile (404). Check the endpoint region, account name and certificate profile name.' }
            default { "The signing service returned HTTP status $($status.Groups[1].Value)." }
        }
        $text = "$hint $text"
    }
    $text
}

function Test-FileSignature {
    <#
    .SYNOPSIS
        Verifies a file's embedded signature; with signtool, also counts signatures and timestamps.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$LiteralPath,

        [string]$SignToolPath,

        [switch]$SkipRevocation,

        [int]$TimeoutSeconds = 120
    )

    $state = Get-FileSignatureState -LiteralPath $LiteralPath -CheckRevocation:(-not $SkipRevocation)
    $count = $null
    $timestamps = $null
    if ($SignToolPath -and [System.IO.File]::Exists($SignToolPath) -and $state.State -notin 'NotSigned', 'NotChecked') {
        $run = Invoke-SignTool -SignToolPath $SignToolPath -ArgumentList @('verify', '/pa', '/all', '/v', '--', $LiteralPath) -TimeoutSeconds $TimeoutSeconds
        $lines = ($run.Output + "`n" + $run.Error) -split "`r?`n"
        $count = @($lines | Where-Object { $_ -match '^\s*Signature Index:' }).Count
        $timestamps = @($lines | Where-Object { $_ -match '^\s*The signature is timestamped' }).Count
    }

    $detail = switch ($state.State) {
        'NotSigned' { 'Not signed.' }
        'Valid' { "Valid signature from $($state.Signer)." }
        'Untrusted' { "Signed by $($state.Signer); not trusted on this PC: $($state.Message)" }
        'Revoked' { "Signed by $($state.Signer); the signing certificate or its issuer has been revoked." }
        'Invalid' { 'The signature is invalid; the file changed after signing.' }
        'NotChecked' { "Not checked. $($state.Message)" }
        default { "The signature could not be checked: $($state.Message)" }
    }
    if ($null -ne $count -and $count -gt 0) {
        $detail += " $count signature(s), $timestamps timestamped."
    }
    elseif ($state.State -notin 'NotSigned', 'NotChecked') {
        $detail += if ($state.Timestamped) { ' Timestamped.' } else { ' Not timestamped.' }
    }

    [pscustomobject]@{
        Path             = $LiteralPath
        State            = $state.State
        Signer           = $state.Signer
        SignerThumbprint = $state.Thumbprint
        Timestamped      = $state.Timestamped
        SignatureCount   = $count
        Detail           = $detail
    }
}
