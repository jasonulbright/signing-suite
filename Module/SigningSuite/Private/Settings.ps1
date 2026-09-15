$script:DefaultSettings = [ordered]@{
    Source                   = 'Store'
    CertificateThumbprint    = ''
    Engine                   = 'Auto'
    DigestAlgorithm          = 'SHA256'
    TimestampMode            = 'Rfc3161'
    TimestampServer          = 'http://timestamp.digicert.com'
    DualSign                 = $false
    SkipValid                = $true
    ClearVbaSignatures       = $false
    Description              = ''
    DescriptionUrl           = ''
    SignToolPath             = ''
    ArtifactDlibPath         = ''
    ArtifactMetadataPath     = ''
    ArtifactTimestampServer  = 'http://timestamp.acs.microsoft.com'
    DlibPath                 = ''
    DlibMetadataPath         = ''
    DlibCertificateFile      = ''
    OptionsExpanded          = $false
    WindowWidth              = 0
    WindowHeight             = 0
}

function Get-SigningSuiteSettingsPath {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ApplicationData)) 'SigningSuite\settings.json'
}

function Get-SigningSuiteSettings {
    <#
    .SYNOPSIS
        Reads saved settings over the defaults; unknown keys are dropped and a damaged file yields the defaults.
    #>
    [CmdletBinding()]
    param(
        [string]$Path = (Get-SigningSuiteSettingsPath)
    )

    $settings = [ordered]@{}
    foreach ($key in $script:DefaultSettings.Keys) {
        $settings[$key] = $script:DefaultSettings[$key]
    }
    if (-not [System.IO.File]::Exists($Path)) {
        return [pscustomobject]$settings
    }
    try {
        $saved = [System.IO.File]::ReadAllText($Path) | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        Write-Verbose "Settings file ignored: $($_.Exception.Message)"
        return [pscustomobject]$settings
    }
    foreach ($property in $saved.PSObject.Properties) {
        if ($settings.Contains($property.Name) -and $null -ne $property.Value) {
            $default = $script:DefaultSettings[$property.Name]
            try {
                $settings[$property.Name] = if ($default -is [bool]) { [bool]$property.Value } elseif ($default -is [int]) { [int]$property.Value } else { [string]$property.Value }
            }
            catch {
                Write-Verbose "Setting $($property.Name) ignored: $($_.Exception.Message)"
            }
        }
    }
    [pscustomobject]$settings
}

function Save-SigningSuiteSettings {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [object]$Settings,

        [string]$Path = (Get-SigningSuiteSettingsPath)
    )

    $document = [ordered]@{}
    foreach ($key in $script:DefaultSettings.Keys) {
        $property = $Settings.PSObject.Properties[$key]
        $document[$key] = if ($property) { $property.Value } else { $script:DefaultSettings[$key] }
    }
    if ($PSCmdlet.ShouldProcess($Path, 'Save settings')) {
        [void][System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($Path))
        $temporary = "$Path.tmp"
        [System.IO.File]::WriteAllText($temporary, ($document | ConvertTo-Json), [System.Text.UTF8Encoding]::new($false))
        if ([System.IO.File]::Exists($Path)) {
            # A PowerShell $null becomes an empty string for a [string] parameter, which File.Replace rejects as a backup path.
            [System.IO.File]::Replace($temporary, $Path, [NullString]::Value)
        }
        else {
            [System.IO.File]::Move($temporary, $Path)
        }
    }
}
