# WinVerifyTrust returns HRESULTs as signed 32-bit integers.
$script:TrustResults = @{
    NoSignature = [int]-2146762496
    BadDigest   = [int]-2146869232
}

function Get-FileSignatureState {
    <#
    .SYNOPSIS
        Reads the embedded signature of a file and reduces it to a state the file list can show.
    .DESCRIPTION
        Uses WinVerifyTrust on the file itself. Get-AuthenticodeSignature reports a matching catalog signature for files
        that Windows catalogs cover, which hides the embedded signature a signing run just wrote.
    .OUTPUTS
        Object with State (NotSigned, Valid, Untrusted, Invalid, Unknown), StatusCode, Signer, Thumbprint, Timestamped, Message.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$LiteralPath
    )

    try {
        $result = [SigningSuite.Native.Trust]::VerifyEmbedded($LiteralPath)
    }
    catch {
        return [pscustomobject]@{
            State       = 'Unknown'
            StatusCode  = $null
            Signer      = $null
            Thumbprint  = $null
            Timestamped = $false
            Message     = $_.Exception.Message
        }
    }

    $code = [int]$result.Status
    $state = if ($code -eq 0) {
        'Valid'
    }
    elseif ($code -eq $script:TrustResults.BadDigest) {
        'Invalid'
    }
    elseif ($code -eq $script:TrustResults.NoSignature -and -not $result.Signer) {
        'NotSigned'
    }
    elseif ($result.Signer) {
        'Untrusted'
    }
    else {
        'Unknown'
    }

    $message = ([string]$result.Message).Trim()
    if ($message -and $message -notmatch '[.!?]$') {
        $message += '.'
    }

    $nameType = [System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName
    try {
        [pscustomobject]@{
            State       = $state
            StatusCode  = '0x{0:X8}' -f $code
            Signer      = if ($result.Signer) { $result.Signer.GetNameInfo($nameType, $false) } else { $null }
            Thumbprint  = if ($result.Signer) { $result.Signer.Thumbprint } else { $null }
            Timestamped = [bool]$result.Timestamped
            Message     = $message
        }
    }
    finally {
        foreach ($certificate in $result.Signer, $result.TimestampSigner) {
            if ($certificate) {
                $certificate.Dispose()
            }
        }
    }
}
