function Resolve-SigningEngine {
    <#
    .SYNOPSIS
        Picks the engine for one file from the requested engine, the file format, the signing source and the options.
    .OUTPUTS
        Object with Engine (PowerShell, SignTool, or $null) and Reason (why no engine can sign the file).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Provider,

        [ValidateSet('Auto', 'PowerShell', 'SignTool')]
        [string]$Requested = 'Auto',

        [bool]$SignToolAvailable,

        [ValidateSet('Store', 'ArtifactSigning', 'Dlib')]
        [string]$Source = 'Store',

        [ValidateSet('None', 'Rfc3161', 'Authenticode')]
        [string]$TimestampMode = 'None'
    )

    $needsSignTool = [System.Collections.Generic.List[string]]::new()
    if ($Source -eq 'ArtifactSigning') {
        $needsSignTool.Add('Artifact Signing')
    }
    elseif ($Source -eq 'Dlib') {
        $needsSignTool.Add('digest signing libraries')
    }
    if ($Provider.Engines -notcontains 'PowerShell') {
        $needsSignTool.Add("$($Provider.Name) files")
    }
    if ($TimestampMode -eq 'Rfc3161') {
        $needsSignTool.Add('RFC 3161 timestamps')
    }

    $engine = switch ($Requested) {
        'SignTool' { 'SignTool' }
        'PowerShell' {
            if ($needsSignTool.Count -gt 0) {
                return [pscustomobject]@{ Engine = $null; Reason = "The PowerShell engine cannot sign this file: $($needsSignTool -join ', ') need the SignTool engine." }
            }
            'PowerShell'
        }
        default {
            if ($SignToolAvailable) { 'SignTool' } else { 'PowerShell' }
        }
    }

    if ($engine -eq 'SignTool' -and -not $SignToolAvailable) {
        $reason = if ($needsSignTool.Count -gt 0) { "signtool.exe was not found; $($needsSignTool -join ', ') need it." } else { 'signtool.exe was not found.' }
        return [pscustomobject]@{ Engine = $null; Reason = $reason }
    }
    if ($engine -eq 'PowerShell' -and $needsSignTool.Count -gt 0) {
        return [pscustomobject]@{ Engine = $null; Reason = "signtool.exe was not found; $($needsSignTool -join ', ') need it." }
    }
    [pscustomobject]@{ Engine = $engine; Reason = $null }
}

function ConvertTo-SignatureText {
    <#
    .SYNOPSIS
        Short text for the Signature column.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowEmptyString()]
        [string]$State,

        [AllowNull()]
        [string]$Signer
    )

    switch ($State) {
        'NotSigned' { 'Not signed' }
        'Valid' { "Valid: $Signer" }
        'Untrusted' { "Untrusted: $Signer" }
        'Invalid' { 'Invalid (file changed)' }
        'Unknown' { 'Unreadable' }
        default { '' }
    }
}

function Test-SkipValidSignature {
    <#
    .SYNOPSIS
        Decides whether "skip files that already have a valid signature" leaves a file alone.
    .DESCRIPTION
        A valid signature without the timestamp a run asks for is not skipped: a run that failed on an unreachable
        timestamp server leaves such a file behind, and skipping it would hide the missing timestamp for good.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [AllowEmptyString()]
        [string]$SignatureState,

        [bool]$Timestamped,

        [ValidateSet('None', 'Rfc3161', 'Authenticode')]
        [string]$TimestampMode = 'None'
    )

    $SignatureState -eq 'Valid' -and ($TimestampMode -eq 'None' -or $Timestamped)
}

function ConvertTo-SafeCsvField {
    <#
    .SYNOPSIS
        Prefixes a value that a spreadsheet would evaluate as a formula with an apostrophe.
    .DESCRIPTION
        File names are chosen by whoever produced the files; a name that starts with =, +, -, @, tab or carriage return
        runs as a formula when the exported CSV is opened in Excel.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [object]$Value
    )

    $text = [string]$Value
    if ($text.Length -gt 0 -and "=+-@`t`r".IndexOf($text[0]) -ge 0) {
        return "'" + $text
    }
    $text
}

function New-ArtifactSigningMetadata {
    <#
    .SYNOPSIS
        Writes the metadata.json that the Artifact Signing dlib reads through signtool /dmdf.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [ValidatePattern('^https://')]
        [string]$Endpoint,

        [Parameter(Mandatory)]
        [string]$AccountName,

        [Parameter(Mandatory)]
        [string]$CertificateProfileName,

        [string]$CorrelationId,

        [string[]]$ExcludeCredentials
    )

    $document = [ordered]@{
        Endpoint               = $Endpoint.TrimEnd('/') + '/'
        CodeSigningAccountName = $AccountName
        CertificateProfileName = $CertificateProfileName
    }
    if ($CorrelationId) {
        $document.CorrelationId = $CorrelationId
    }
    if ($ExcludeCredentials) {
        $document.ExcludeCredentials = @($ExcludeCredentials)
    }
    if ($PSCmdlet.ShouldProcess($Path, 'Write Artifact Signing metadata')) {
        $folder = [System.IO.Path]::GetDirectoryName($Path)
        if ($folder) {
            [void][System.IO.Directory]::CreateDirectory($folder)
        }
        [System.IO.File]::WriteAllText($Path, ($document | ConvertTo-Json -Depth 3), [System.Text.UTF8Encoding]::new($false))
    }
    Get-Item -LiteralPath $Path
}
