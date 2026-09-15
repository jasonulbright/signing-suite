function Find-SignableFile {
    <#
    .SYNOPSIS
        Expands dropped files and folders into candidate file paths.
    .DESCRIPTION
        Folders are searched recursively for supported extensions only. Files named explicitly are always returned so the
        list can say why an unsupported file is skipped. Office owner files (~$name) are ignored.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$Path,

        [ref]$UnreadableCount
    )

    $extensions = [System.Collections.Generic.HashSet[string]]::new([string[]](Get-SupportedExtension), [System.StringComparer]::OrdinalIgnoreCase)
    $unreadable = 0

    foreach ($entry in $Path) {
        if (-not $entry) {
            continue
        }
        if ([System.IO.Directory]::Exists($entry)) {
            $walkErrors = $null
            $files = Get-ChildItem -LiteralPath $entry -Recurse -File -ErrorAction SilentlyContinue -ErrorVariable walkErrors
            if ($walkErrors) {
                $unreadable += @($walkErrors).Count
            }
            foreach ($file in $files) {
                if ($extensions.Contains($file.Extension) -and -not $file.Name.StartsWith('~$')) {
                    $file.FullName
                }
            }
        }
        elseif ([System.IO.File]::Exists($entry)) {
            [System.IO.Path]::GetFullPath($entry)
        }
        else {
            $unreadable++
        }
    }

    if ($UnreadableCount) {
        $UnreadableCount.Value = $unreadable
    }
}

function Test-OfficeVbaProject {
    <#
    .SYNOPSIS
        Reports whether an Office file contains a VBA project.
    .OUTPUTS
        $true, $false, or $null when the format stores the project where it cannot be found without parsing it.
        Throws when the file cannot be read as its format (encrypted, damaged, locked).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$LiteralPath
    )

    $extension = [System.IO.Path]::GetExtension($LiteralPath).ToLowerInvariant()
    if ($script:OfficeOpenXmlExtensions -contains $extension) {
        Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
        $zip = [System.IO.Compression.ZipFile]::OpenRead($LiteralPath)
        try {
            foreach ($entry in $zip.Entries) {
                if ($entry.FullName -like '*vbaProject.bin') {
                    return $true
                }
            }
            return $false
        }
        finally {
            $zip.Dispose()
        }
    }

    $marker = [System.Text.Encoding]::Unicode.GetBytes('_VBA_PROJECT')
    if ([SigningSuite.Native.Sip]::FileContains($LiteralPath, $marker)) {
        return $true
    }
    if ($script:OfficeLegacyMarkerExtensions -contains $extension) {
        return $false
    }
    return $null
}

function Get-AppPackageIdentity {
    <#
    .SYNOPSIS
        Reads Identity Name, Publisher and Version from an MSIX/APPX package or bundle manifest.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$LiteralPath
    )

    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::OpenRead($LiteralPath)
    try {
        $manifest = $zip.GetEntry('AppxManifest.xml')
        if (-not $manifest) {
            $manifest = $zip.GetEntry('AppxMetadata/AppxBundleManifest.xml')
        }
        if (-not $manifest) {
            throw 'The package has no AppxManifest.xml or AppxBundleManifest.xml.'
        }
        $signed = $null -ne $zip.GetEntry('AppxSignature.p7x')

        $settings = [System.Xml.XmlReaderSettings]::new()
        $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
        $settings.XmlResolver = $null
        $stream = $manifest.Open()
        try {
            $reader = [System.Xml.XmlReader]::Create($stream, $settings)
            try {
                while ($reader.Read()) {
                    if ($reader.NodeType -eq [System.Xml.XmlNodeType]::Element -and $reader.LocalName -eq 'Identity') {
                        return [pscustomobject]@{
                            Name      = $reader.GetAttribute('Name')
                            Publisher = $reader.GetAttribute('Publisher')
                            Version   = $reader.GetAttribute('Version')
                            IsBundle  = $manifest.FullName -like 'AppxMetadata/*'
                            Signed    = $signed
                        }
                    }
                }
            }
            finally {
                $reader.Dispose()
            }
        }
        finally {
            $stream.Dispose()
        }
        throw 'The package manifest has no Identity element.'
    }
    finally {
        $zip.Dispose()
    }
}

function Test-CertificateMatchesPublisher {
    <#
    .SYNOPSIS
        Compares an app package Publisher with a certificate subject as distinguished names.
    .DESCRIPTION
        SignTool refuses a package whose manifest Publisher differs from the signing certificate subject (0x8007000B).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string]$Publisher,

        [Parameter(Mandatory)]
        [string]$Subject
    )

    try {
        $flags = [System.Security.Cryptography.X509Certificates.X500DistinguishedNameFlags]::None
        $left = [System.Security.Cryptography.X509Certificates.X500DistinguishedName]::new($Publisher)
        $right = [System.Security.Cryptography.X509Certificates.X500DistinguishedName]::new($Subject)
        return [string]::Equals($left.Decode($flags), $right.Decode($flags), [System.StringComparison]::Ordinal)
    }
    catch {
        return [string]::Equals($Publisher.Trim(), $Subject.Trim(), [System.StringComparison]::Ordinal)
    }
}

function Test-SipRegistered {
    <#
    .SYNOPSIS
        Checks the registry view of the current process for a SIP that can recognize files by name or content.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string]$Guid
    )

    $braced = '{' + $Guid.Trim('{', '}').ToUpperInvariant() + '}'
    foreach ($function in 'CryptSIPDllIsMyFileType2', 'CryptSIPDllIsMyFileType') {
        $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\$function\$braced")
        if ($key) {
            $key.Close()
            return $true
        }
    }
    return $false
}

function Get-SipGapMessage {
    <#
    .SYNOPSIS
        Explains why Windows has no signing handler for a file.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$LiteralPath,

        [object]$Provider
    )

    $extension = [System.IO.Path]::GetExtension($LiteralPath).ToLowerInvariant()
    $bits = if ([Environment]::Is64BitProcess) { '64-bit' } else { '32-bit' }
    if (-not $Provider) {
        return 'Windows has no signing handler (SIP) for this file.'
    }
    switch ($Provider.Id) {
        'OfficeVba' {
            $guid = if ($script:OfficeOpenXmlExtensions -contains $extension) { $script:OfficeSipGuids.OpenXml } else { $script:OfficeSipGuids.Legacy }
            $dll = if ($script:OfficeOpenXmlExtensions -contains $extension) { 'msosipx.dll' } else { 'msosip.dll' }
            if (-not (Test-SipRegistered -Guid $guid)) {
                return "The Office signing add-in ($dll) is not registered for $bits PowerShell."
            }
            return 'The Office signing add-in does not recognize this file; it may be damaged or not an Office file.'
        }
        'PortableExecutable' { return 'The file is not a valid Windows executable or library.' }
        'WindowsInstaller' { return 'The file is not a valid Windows Installer database.' }
        'Cabinet' { return 'The file is not a valid cabinet archive.' }
        'Catalog' { return 'The file is not a valid security catalog.' }
        'AppPackage' { return 'The file is not a valid app package.' }
        default { return 'Windows has no signing handler (SIP) for this file.' }
    }
}

function Get-SignableFileInfo {
    <#
    .SYNOPSIS
        Classifies one file for the signing list: format, readiness, reason, and current signature.
    .OUTPUTS
        Object with Path, Name, Folder, Extension, ProviderId, Format, Status (Ready, Failed, Skipped), Detail,
        SignatureState, Signer, SignerThumbprint, Timestamped, Publisher.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$LiteralPath,

        [switch]$SkipSignature
    )

    $info = [pscustomobject]@{
        Path             = $LiteralPath
        Name             = [System.IO.Path]::GetFileName($LiteralPath)
        Folder           = [System.IO.Path]::GetDirectoryName($LiteralPath)
        Extension        = [System.IO.Path]::GetExtension($LiteralPath).ToLowerInvariant()
        ProviderId       = $null
        Format           = ''
        Status           = 'Ready'
        Detail           = ''
        SignatureState   = ''
        Signer           = $null
        SignerThumbprint = $null
        Timestamped      = $false
        Publisher        = $null
    }

    $provider = Get-FormatProvider -Extension $info.Extension
    if (-not $provider) {
        $info.Status = 'Skipped'
        $info.Detail = 'Not a signable file type.'
        return $info
    }
    $info.ProviderId = $provider.Id
    $info.Format = $provider.Name

    try {
        $item = [System.IO.FileInfo]::new($LiteralPath)
        if (-not $item.Exists) {
            $info.Status = 'Skipped'
            $info.Detail = 'The file no longer exists.'
            return $info
        }
        if ($item.Length -eq 0) {
            $info.Status = 'Skipped'
            $info.Detail = 'The file is empty.'
            return $info
        }
        $readOnly = $item.IsReadOnly
    }
    catch {
        $info.Status = 'Skipped'
        $info.Detail = "Could not read the file: $($_.Exception.Message)"
        return $info
    }

    $notes = [System.Collections.Generic.List[string]]::new()
    if ($provider.Id -eq 'OfficeVba') {
        try {
            $hasVba = Test-OfficeVbaProject -LiteralPath $LiteralPath
        }
        catch {
            $info.Status = 'Skipped'
            $info.Detail = "Could not read the file (password-protected, damaged, or locked): $($_.Exception.Message)"
            return $info
        }
        if ($hasVba -eq $false) {
            $info.Status = 'Skipped'
            $info.Detail = 'No VBA project.'
            return $info
        }
        if ($null -eq $hasVba) {
            $notes.Add('VBA project not detected before signing; signing confirms it.')
        }
    }
    elseif ($provider.Id -eq 'AppPackage') {
        try {
            $identity = Get-AppPackageIdentity -LiteralPath $LiteralPath
            $info.Publisher = $identity.Publisher
            $notes.Add("Publisher $($identity.Publisher).")
        }
        catch {
            $info.Status = 'Skipped'
            $info.Detail = "Not a readable app package: $($_.Exception.Message)"
            return $info
        }
    }

    $sip = Get-SipSubject -LiteralPath $LiteralPath
    if (-not $sip.Supported) {
        $info.Status = 'Failed'
        $info.Detail = Get-SipGapMessage -LiteralPath $LiteralPath -Provider $provider
        return $info
    }

    if (-not $SkipSignature) {
        $signature = Get-FileSignatureState -LiteralPath $LiteralPath
        $info.SignatureState = $signature.State
        $info.Signer = $signature.Signer
        $info.SignerThumbprint = $signature.Thumbprint
        $info.Timestamped = $signature.Timestamped
        switch ($signature.State) {
            'NotSigned' { $notes.Insert(0, 'Not signed.') }
            'Valid' { $notes.Insert(0, "Signed by $($signature.Signer); valid.") }
            'Untrusted' { $notes.Insert(0, "Signed by $($signature.Signer); not trusted on this PC.") }
            'Invalid' { $notes.Insert(0, 'Signature is invalid; the file changed after signing.') }
            default { $notes.Insert(0, "Signature could not be read: $($signature.Message)") }
        }
    }

    if ($readOnly) {
        $info.Status = 'Failed'
        $notes.Insert(0, 'The file is read-only.')
    }
    $info.Detail = $notes -join ' '
    $info
}
