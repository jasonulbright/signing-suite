# WinVerifyTrust returns HRESULTs as signed 32-bit integers.
$script:TrustResults = @{
    NoSignature = [int]-2146762496
    BadDigest   = [int]-2146869232
    Revoked     = [int]-2146762484
}

function Get-FileSignatureState {
    <#
    .SYNOPSIS
        Reads the embedded signature of a file and reduces it to a state the file list can show.
    .DESCRIPTION
        Uses WinVerifyTrust on the file itself. Get-AuthenticodeSignature reports a matching catalog signature for files
        that Windows catalogs cover, which hides the embedded signature a signing run just wrote.
        Without -CheckRevocation, revocation is not checked and nothing is retrieved from the network, so Valid means
        the chain and digest are good as of the local cache. -CheckRevocation checks the chain below the root online.
    .OUTPUTS
        Object with State (NotSigned, Valid, Untrusted, Revoked, Invalid, Unknown), StatusCode, Signer, Thumbprint,
        Timestamped, Message.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$LiteralPath,

        [switch]$CheckRevocation
    )

    try {
        $result = [SigningSuite.Native.Trust]::VerifyEmbedded($LiteralPath, [bool]$CheckRevocation)
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
    elseif ($code -eq $script:TrustResults.Revoked) {
        'Revoked'
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
