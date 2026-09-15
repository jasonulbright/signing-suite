function Find-SignTool {
    <#
    .SYNOPSIS
        Locates signtool.exe: an explicit path first, then the newest Windows SDK build for the requested architecture, then PATH.
    .OUTPUTS
        Object with Path, Version, Architecture and Source; nothing when signtool is not found.
    #>
    [CmdletBinding()]
    param(
        [string]$ConfiguredPath,

        [ValidateSet('x64', 'x86', 'arm64')]
        [string]$Architecture
    )

    if (-not $Architecture) {
        $Architecture = switch ($env:PROCESSOR_ARCHITECTURE) {
            'ARM64' { 'arm64' }
            'x86' { if ([Environment]::Is64BitOperatingSystem) { 'x64' } else { 'x86' } }
            default { 'x64' }
        }
    }

    if ($ConfiguredPath) {
        if ([System.IO.File]::Exists($ConfiguredPath)) {
            # The path comes from a per-user settings file; an unsigned or tampered binary there would run with every signing pass.
            $signature = Get-FileSignatureState -LiteralPath $ConfiguredPath
            if ($signature.State -eq 'Valid') {
                return New-SignToolInfo -Path $ConfiguredPath -Source 'Configured'
            }
            Write-Warning "The configured signtool path is ignored because it does not carry a valid signature: $ConfiguredPath"
        }
        else {
            Write-Verbose "Configured signtool path does not exist: $ConfiguredPath"
        }
    }

    $roots = [System.Collections.Generic.List[string]]::new()
    foreach ($view in [Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32) {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
        try {
            $key = $base.OpenSubKey('SOFTWARE\Microsoft\Windows Kits\Installed Roots')
            if ($key) {
                try {
                    $root = [string]$key.GetValue('KitsRoot10')
                    if ($root -and -not $roots.Contains($root)) {
                        $roots.Add($root)
                    }
                }
                finally {
                    $key.Close()
                }
            }
        }
        finally {
            $base.Close()
        }
    }
    if (${env:ProgramFiles(x86)}) {
        $defaultRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\'
        if (-not $roots.Contains($defaultRoot)) {
            $roots.Add($defaultRoot)
        }
    }

    $candidates = foreach ($root in $roots) {
        $bin = Join-Path $root 'bin'
        if (-not [System.IO.Directory]::Exists($bin)) {
            continue
        }
        foreach ($directory in [System.IO.Directory]::GetDirectories($bin)) {
            $version = $null
            if ([version]::TryParse([System.IO.Path]::GetFileName($directory), [ref]$version)) {
                $path = Join-Path $directory "$Architecture\signtool.exe"
                if ([System.IO.File]::Exists($path)) {
                    [pscustomobject]@{ Path = $path; Version = $version }
                }
            }
        }
        $flat = Join-Path $bin "$Architecture\signtool.exe"
        if ([System.IO.File]::Exists($flat)) {
            [pscustomobject]@{ Path = $flat; Version = [version]'0.0' }
        }
    }
    $best = $candidates | Sort-Object -Property Version -Descending | Select-Object -First 1
    if ($best) {
        return New-SignToolInfo -Path $best.Path -Source 'WindowsSdk'
    }

    $onPath = Get-Command -Name signtool.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($onPath) {
        return New-SignToolInfo -Path $onPath.Source -Source 'Path'
    }
}

function New-SignToolInfo {
    param(
        [string]$Path,
        [string]$Source
    )

    $item = Get-Item -LiteralPath $Path
    $fileVersion = $item.VersionInfo.FileVersion
    $parsed = $null
    $version = if ($fileVersion -and [version]::TryParse(($fileVersion -split ' ')[0], [ref]$parsed)) { $parsed } else { $null }
    $architecture = Split-Path -Leaf (Split-Path -Parent $Path)
    [pscustomobject]@{
        Path         = $item.FullName
        Version      = $version
        Architecture = if ($architecture -in 'x64', 'x86', 'arm64') { $architecture } else { $null }
        Source       = $Source
    }
}

function Find-ArtifactSigningDlib {
    <#
    .SYNOPSIS
        Locates Azure.CodeSigning.Dlib.dll from the Artifact Signing Client Tools installer or an extracted NuGet package.
    #>
    [CmdletBinding()]
    param(
        [string]$ConfiguredPath,

        [ValidateSet('x64', 'x86', 'arm64')]
        [string]$Architecture = 'x64'
    )

    if ($ConfiguredPath -and [System.IO.File]::Exists($ConfiguredPath)) {
        return (Get-Item -LiteralPath $ConfiguredPath).FullName
    }

    $candidates = [System.Collections.Generic.List[string]]::new()
    if ($env:LOCALAPPDATA) {
        $candidates.Add((Join-Path $env:LOCALAPPDATA 'Microsoft\MicrosoftArtifactSigningClientTools\Azure.CodeSigning.Dlib.dll'))
        $candidates.Add((Join-Path $env:LOCALAPPDATA "Microsoft\MicrosoftArtifactSigningClientTools\bin\$Architecture\Azure.CodeSigning.Dlib.dll"))
        $candidates.Add((Join-Path $env:LOCALAPPDATA 'Microsoft\MicrosoftTrustedSigningClientTools\Azure.CodeSigning.Dlib.dll'))
    }
    if (${env:ProgramFiles(x86)}) {
        $candidates.Add((Join-Path ${env:ProgramFiles(x86)} 'Microsoft\ArtifactSigningClientTools\Azure.CodeSigning.Dlib.dll'))
    }
    if ($env:ProgramFiles) {
        $candidates.Add((Join-Path $env:ProgramFiles 'Microsoft\ArtifactSigningClientTools\Azure.CodeSigning.Dlib.dll'))
    }
    foreach ($candidate in $candidates) {
        if ([System.IO.File]::Exists($candidate)) {
            return $candidate
        }
    }
}

function New-SignToolSignArgument {
    <#
    .SYNOPSIS
        Builds the argument list for one signtool sign pass.
    .DESCRIPTION
        Pure function: no process is started, so every combination is testable. The file path follows `--` so a
        name that starts with a dash is not read as an option.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [string]$LiteralPath,

        [ValidateSet('SHA1', 'SHA256', 'SHA384', 'SHA512')]
        [string]$DigestAlgorithm = 'SHA256',

        [string]$Thumbprint,

        [ValidateSet('CurrentUser', 'LocalMachine')]
        [string]$StoreLocation = 'CurrentUser',

        [string]$CertificateFile,

        [string]$DlibPath,

        [string]$MetadataPath,

        [ValidateSet('None', 'Rfc3161', 'Authenticode')]
        [string]$TimestampMode = 'None',

        [string]$TimestampServer,

        [ValidateSet('SHA1', 'SHA256', 'SHA384', 'SHA512')]
        [string]$TimestampDigestAlgorithm,

        [switch]$AppendSignature,

        [string]$Description,

        [string]$DescriptionUrl,

        [ValidateSet('Default', 'On', 'Off')]
        [string]$PageHashes = 'Default',

        [switch]$VerboseOutput
    )

    $arguments = [System.Collections.Generic.List[string]]::new()
    $arguments.Add('sign')
    if ($VerboseOutput) {
        $arguments.Add('/v')
    }
    $arguments.Add('/fd')
    $arguments.Add($DigestAlgorithm)

    if ($DlibPath) {
        $arguments.Add('/dlib')
        $arguments.Add($DlibPath)
        if ($MetadataPath) {
            $arguments.Add('/dmdf')
            $arguments.Add($MetadataPath)
        }
    }

    if ($CertificateFile) {
        $arguments.Add('/f')
        $arguments.Add($CertificateFile)
    }
    elseif ($Thumbprint) {
        $arguments.Add('/sha1')
        $arguments.Add(($Thumbprint -replace '\s', '').ToUpperInvariant())
        $arguments.Add('/s')
        $arguments.Add('My')
        if ($StoreLocation -eq 'LocalMachine') {
            $arguments.Add('/sm')
        }
    }
    elseif (-not $DlibPath) {
        throw 'A certificate thumbprint, a certificate file, or a digest signing library is required.'
    }

    switch ($TimestampMode) {
        'Rfc3161' {
            if (-not $TimestampServer) {
                throw 'An RFC 3161 timestamp needs a timestamp server URL.'
            }
            $arguments.Add('/tr')
            $arguments.Add($TimestampServer)
            $arguments.Add('/td')
            $arguments.Add($(if ($TimestampDigestAlgorithm) { $TimestampDigestAlgorithm } else { $DigestAlgorithm }))
        }
        'Authenticode' {
            if (-not $TimestampServer) {
                throw 'An Authenticode timestamp needs a timestamp server URL.'
            }
            $arguments.Add('/t')
            $arguments.Add($TimestampServer)
        }
    }

    if ($AppendSignature) {
        $arguments.Add('/as')
    }
    if ($Description) {
        $arguments.Add('/d')
        $arguments.Add($Description)
    }
    if ($DescriptionUrl) {
        $arguments.Add('/du')
        $arguments.Add($DescriptionUrl)
    }
    switch ($PageHashes) {
        'On' { $arguments.Add('/ph') }
        'Off' { $arguments.Add('/nph') }
    }

    $arguments.Add('--')
    $arguments.Add($LiteralPath)
    [string[]]$arguments.ToArray()
}

function Invoke-SignTool {
    <#
    .SYNOPSIS
        Runs signtool.exe and separates its "SignTool Error:" and "SignTool Warning:" lines.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SignToolPath,

        [Parameter(Mandatory)]
        [string[]]$ArgumentList,

        [int]$TimeoutSeconds = 300,

        [hashtable]$Environment
    )

    $run = Invoke-ExternalProcess -FilePath $SignToolPath -ArgumentList $ArgumentList -TimeoutSeconds $TimeoutSeconds -Environment $Environment
    $messages = ConvertFrom-SignToolOutput -Text ($run.Output + "`n" + $run.Error)

    [pscustomobject]@{
        ExitCode = $run.ExitCode
        TimedOut = $run.TimedOut
        Output   = $run.Output
        Error    = $run.Error
        Errors   = $messages.Errors
        Warnings = $messages.Warnings
    }
}

function ConvertFrom-SignToolOutput {
    <#
    .SYNOPSIS
        Extracts "SignTool Error:" and "SignTool Warning:" messages, joining the indented lines signtool wraps them onto.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyString()]
        [string]$Text
    )

    $errors = [System.Collections.Generic.List[string]]::new()
    $warnings = [System.Collections.Generic.List[string]]::new()
    $current = $null
    $target = $null
    foreach ($line in ($Text -split "`r?`n")) {
        if ($line -match '^\s*SignTool (Error|Warning):\s*(.*)$') {
            if ($null -ne $current) {
                $target.Add($current.Trim())
            }
            # Assigned in branches: an if-expression would enumerate an empty list into $null.
            if ($Matches[1] -eq 'Error') {
                $target = $errors
            }
            else {
                $target = $warnings
            }
            $current = $Matches[2]
        }
        elseif ($null -ne $current -and $line -match '^\s+\S') {
            $current += ' ' + $line.Trim()
        }
        elseif ($null -ne $current) {
            $target.Add($current.Trim())
            $current = $null
        }
    }
    if ($null -ne $current) {
        $target.Add($current.Trim())
    }
    [pscustomobject]@{
        Errors   = [string[]]$errors.ToArray()
        Warnings = [string[]]$warnings.ToArray()
    }
}
