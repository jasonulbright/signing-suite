#Requires -Version 5.1
<#
.SYNOPSIS
    Builds SigningSuiteSetup-<version>.exe with Inno Setup from a git ref and adds it to checksums.txt.

.DESCRIPTION
    The installer payload is the same file set as the portable zip: `git archive` of the ref, so export-ignore paths stay
    out. Every prerequisite download named in installer\SigningSuite.iss is fetched and checked against its pinned SHA256
    and its Microsoft signature before compiling, so a stale pin fails the build instead of a user's installation.

.PARAMETER Version
    Release version in YYYY.MM.DD.#### form. Defaults to the version in the module manifest.

.PARAMETER Ref
    Git ref to package. Defaults to the tag v<Version>.

.PARAMETER OutputDirectory
    Folder for the installer and checksums.txt. Defaults to dist under the repository.

.PARAMETER SkipDownloadCheck
    Compiles without fetching the prerequisite downloads.
#>
[CmdletBinding()]
param(
    [ValidatePattern('^\d{4}\.\d{2}\.\d{2}\.\d{4}$')]
    [string]$Version,

    [string]$Ref,

    [string]$OutputDirectory,

    [switch]$SkipDownloadCheck
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$repoRoot = Split-Path -Parent $PSScriptRoot
$manifest = Import-PowerShellDataFile -LiteralPath (Join-Path $repoRoot 'Module\SigningSuite\SigningSuite.psd1')
if (-not $Version) {
    $Version = $manifest.PrivateData.SigningSuiteVersion
}
if ($Version -ne $manifest.PrivateData.SigningSuiteVersion) {
    throw "Version $Version does not match the module manifest version $($manifest.PrivateData.SigningSuiteVersion)."
}
if (-not $Ref) {
    $Ref = "v$Version"
}
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $repoRoot 'dist'
}
[void][System.IO.Directory]::CreateDirectory($OutputDirectory)

$iscc = @(
    (Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe')
    (Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe')
    (Join-Path $env:ProgramFiles 'Inno Setup 6\ISCC.exe')
) | Where-Object { [System.IO.File]::Exists($_) } | Select-Object -First 1
if (-not $iscc) {
    throw 'ISCC.exe was not found. Install Inno Setup 6 (winget install -e --id JRSoftware.InnoSetup).'
}

& git -C $repoRoot rev-parse --verify --quiet "$Ref^{commit}" *> $null
if ($LASTEXITCODE -ne 0) {
    throw "Git ref $Ref does not exist."
}

$script = Join-Path $repoRoot 'installer\SigningSuite.iss'
$scriptText = [System.IO.File]::ReadAllText($script)

if (-not $SkipDownloadCheck) {
    $pairs = [regex]::Matches($scriptText, "(?m)^\s*(\w+)Url\s*=\s*'([^']+)';\s*\r?\n\s*\1Sha256\s*=\s*'([0-9a-fA-F]{64})';")
    if ($pairs.Count -eq 0) {
        throw 'No download URL and SHA256 pairs were found in installer\SigningSuite.iss.'
    }
    $cache = Join-Path ([System.IO.Path]::GetTempPath()) 'SigningSuiteInstallerDownloads'
    [void][System.IO.Directory]::CreateDirectory($cache)
    foreach ($pair in $pairs) {
        $name = $pair.Groups[1].Value
        $url = $pair.Groups[2].Value
        $expected = $pair.Groups[3].Value.ToUpperInvariant()
        $file = Join-Path $cache ($name + [System.IO.Path]::GetExtension(([uri]$url).AbsolutePath))
        if (-not [System.IO.File]::Exists($file) -or (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -ne $expected) {
            Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $file
        }
        $actual = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
        if ($actual -ne $expected) {
            throw "$name download hash is $actual, but installer\SigningSuite.iss pins $expected ($url)."
        }
        $signature = Get-AuthenticodeSignature -LiteralPath $file
        if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch '^CN=Microsoft Corporation,') {
            throw "$name download is not validly signed by Microsoft Corporation: $($signature.Status) $($signature.SignerCertificate.Subject)"
        }
        Write-Verbose "$name verified: $url"
    }
}

$work = Join-Path ([System.IO.Path]::GetTempPath()) ("SigningSuiteInstaller-" + [guid]::NewGuid().ToString('N'))
$stage = Join-Path $work 'stage'
try {
    [void][System.IO.Directory]::CreateDirectory($stage)
    $archive = Join-Path $work 'payload.zip'
    & git -C $repoRoot archive --format=zip -o $archive $Ref
    if ($LASTEXITCODE -ne 0) {
        throw "git archive failed with exit code $LASTEXITCODE."
    }
    Expand-Archive -LiteralPath $archive -DestinationPath $stage
    foreach ($required in 'start-signingsuite.ps1', 'MainWindow.xaml', 'Module\SigningSuite\SigningSuite.psd1', 'LICENSE') {
        if (-not [System.IO.File]::Exists((Join-Path $stage $required))) {
            throw "The installer payload is missing $required."
        }
    }

    $parts = $Version.Split('.') | ForEach-Object { [int]$_ }
    $fileVersion = '{0}.{1}.{2}.{3}' -f $parts
    $output = & $iscc "/DAppVersion=$Version" "/DFileVersion=$fileVersion" "/DStageDir=$stage" "/O$OutputDirectory" "/FSigningSuiteSetup-$Version" $script 2>&1
    if ($LASTEXITCODE -ne 0) {
        $output | Select-Object -Last 30 | ForEach-Object { Write-Warning $_ }
        throw "ISCC failed with exit code $LASTEXITCODE."
    }
}
finally {
    if ([System.IO.Directory]::Exists($work)) {
        [System.IO.Directory]::Delete($work, $true)
    }
}

$setupName = "SigningSuiteSetup-$Version.exe"
$setup = Join-Path $OutputDirectory $setupName
$hash = (Get-FileHash -LiteralPath $setup -Algorithm SHA256).Hash.ToLowerInvariant()
$checksums = Join-Path $OutputDirectory 'checksums.txt'
$lines = @()
if ([System.IO.File]::Exists($checksums)) {
    $lines = @([System.IO.File]::ReadAllLines($checksums) | Where-Object { $_ -and $_ -notmatch "  $([regex]::Escape($setupName))$" })
}
$lines += "$hash  $setupName"
[System.IO.File]::WriteAllText($checksums, (($lines -join "`n") + "`n"), [System.Text.UTF8Encoding]::new($false))

[pscustomobject]@{
    Setup     = $setup
    Checksums = $checksums
    Sha256    = $hash
    Ref       = $Ref
}
