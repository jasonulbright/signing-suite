$script:OfficeOpenXmlExtensions = @('.xlsm', '.xlsb', '.xltm', '.xlam', '.docm', '.dotm', '.pptm', '.potm', '.ppam', '.ppsm', '.vsdm', '.vssm', '.vstm')
$script:OfficeLegacyExtensions = @('.xls', '.xlt', '.xla', '.doc', '.dot', '.wiz', '.ppt', '.pot', '.pps', '.ppa', '.mpp', '.mpt', '.pub', '.vsd', '.vss', '.vst', '.vdw')
# Excel and Word binary files store the VBA project under a storage named _VBA_PROJECT; the other legacy formats compress it.
$script:OfficeLegacyMarkerExtensions = @('.xls', '.xlt', '.xla', '.doc', '.dot', '.wiz')
$script:OfficeSipGuids = @{
    OpenXml = '6e64d5bd-ceb0-4b66-b4a0-15ac71775c48'
    Legacy  = '01f45160-3e3e-11d3-b49a-00104b2cf645'
}

$script:FormatProviders = @(
    [pscustomobject]@{
        Id             = 'PowerShell'
        Name           = 'PowerShell'
        Extensions     = @('.ps1', '.psm1', '.psd1', '.ps1xml', '.psc1', '.cdxml')
        Engines        = @('PowerShell', 'SignTool')
        SignPasses     = 1
        SupportsAppend = $false
        Description    = 'Scripts, modules, manifests, formatting and type files'
    }
    [pscustomobject]@{
        Id             = 'WindowsScriptHost'
        Name           = 'Windows Script Host'
        Extensions     = @('.vbs', '.vbe', '.js', '.jse', '.wsf')
        Engines        = @('PowerShell', 'SignTool')
        SignPasses     = 1
        SupportsAppend = $false
        Description    = 'VBScript, JScript and Windows Script Files'
    }
    [pscustomobject]@{
        Id             = 'PortableExecutable'
        Name           = 'Executable'
        Extensions     = @('.exe', '.dll', '.sys', '.ocx', '.scr', '.cpl', '.efi', '.drv', '.winmd', '.mui', '.com')
        Engines        = @('PowerShell', 'SignTool')
        SignPasses     = 1
        SupportsAppend = $true
        Description    = 'Programs, libraries, drivers and controls'
    }
    [pscustomobject]@{
        Id             = 'WindowsInstaller'
        Name           = 'Windows Installer'
        Extensions     = @('.msi', '.msp', '.mst', '.msm')
        Engines        = @('PowerShell', 'SignTool')
        SignPasses     = 1
        SupportsAppend = $false
        Description    = 'Installer packages, patches, transforms and merge modules'
    }
    [pscustomobject]@{
        Id             = 'Cabinet'
        Name           = 'Cabinet'
        Extensions     = @('.cab')
        Engines        = @('PowerShell', 'SignTool')
        SignPasses     = 1
        SupportsAppend = $true
        Description    = 'Cabinet archives'
    }
    [pscustomobject]@{
        Id             = 'Catalog'
        Name           = 'Catalog'
        Extensions     = @('.cat')
        Engines        = @('PowerShell', 'SignTool')
        SignPasses     = 1
        SupportsAppend = $false
        Description    = 'Security catalogs'
    }
    [pscustomobject]@{
        Id             = 'OfficeVba'
        Name           = 'Office VBA'
        Extensions     = @($script:OfficeOpenXmlExtensions + $script:OfficeLegacyExtensions)
        Engines        = @('PowerShell', 'SignTool')
        # Office SIPs add the legacy, agile and V3 VBA signatures on successive passes.
        SignPasses     = 3
        SupportsAppend = $false
        Description    = 'VBA projects in Excel, Word, PowerPoint, Visio, Project and Publisher files'
    }
    [pscustomobject]@{
        Id             = 'AppPackage'
        Name           = 'App package'
        Extensions     = @('.msix', '.appx', '.msixbundle', '.appxbundle')
        Engines        = @('SignTool')
        SignPasses     = 1
        SupportsAppend = $false
        Description    = 'MSIX and APPX packages and bundles'
    }
)

function Get-FormatProvider {
    <#
    .SYNOPSIS
        Returns every format provider, the provider with an id, or the provider that owns a file extension.
    #>
    [CmdletBinding()]
    param(
        [string]$Extension,
        [string]$Id
    )

    if ($Id) {
        return $script:FormatProviders | Where-Object Id -eq $Id
    }
    if ($PSBoundParameters.ContainsKey('Extension')) {
        $normalized = $Extension.ToLowerInvariant()
        if ($normalized -and -not $normalized.StartsWith('.')) {
            $normalized = ".$normalized"
        }
        return $script:FormatProviders | Where-Object { $_.Extensions -contains $normalized } | Select-Object -First 1
    }
    $script:FormatProviders
}

function Get-SupportedExtension {
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    [string[]]@($script:FormatProviders | ForEach-Object { $_.Extensions })
}
