#Requires -Version 5.1
<#
.SYNOPSIS
    Builds the release zip and checksums.txt from a release tag.

.DESCRIPTION
    The zip comes from `git archive` of the tag, so only committed files ship and every path marked export-ignore in
    .gitattributes (tests, native test sources, release tooling) stays out. The build refuses a tag that does not match
    the version in the module manifest, and checks the zip for excluded paths before writing checksums.

.PARAMETER Version
    Release version in YYYY.MM.DD.#### form. Defaults to the version in the module manifest.

.PARAMETER OutputDirectory
    Folder for SigningSuite-<version>.zip and checksums.txt. Defaults to dist under the repository.
#>
[CmdletBinding()]
param(
    [ValidatePattern('^\d{4}\.\d{2}\.\d{2}\.\d{4}$')]
    [string]$Version,

    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$manifest = Import-PowerShellDataFile -LiteralPath (Join-Path $repoRoot 'Module\SigningSuite\SigningSuite.psd1')
$manifestVersion = $manifest.PrivateData.SigningSuiteVersion
if (-not $Version) {
    $Version = $manifestVersion
}
if ($Version -ne $manifestVersion) {
    throw "Version $Version does not match the module manifest version $manifestVersion."
}
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $repoRoot 'dist'
}
[void][System.IO.Directory]::CreateDirectory($OutputDirectory)

$tag = "v$Version"
& git -C $repoRoot rev-parse --verify --quiet "refs/tags/$tag" *> $null
if ($LASTEXITCODE -ne 0) {
    throw "Tag $tag does not exist. Commit the release and create the tag first."
}

$zipName = "SigningSuite-$Version.zip"
$zipPath = Join-Path $OutputDirectory $zipName
if ([System.IO.File]::Exists($zipPath)) {
    [System.IO.File]::Delete($zipPath)
}
& git -C $repoRoot archive --format=zip -o $zipPath $tag
if ($LASTEXITCODE -ne 0) {
    throw "git archive failed with exit code $LASTEXITCODE."
}

Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
try {
    $entries = @($zip.Entries | ForEach-Object { $_.FullName })
}
finally {
    $zip.Dispose()
}
$forbidden = @($entries | Where-Object { $_ -match '^(Tests|tools)/' -or $_ -match '\.local\.' -or $_ -in 'RELEASING.md', 'ROADMAP.md', '.gitattributes', '.gitignore' })
if ($forbidden.Count -gt 0) {
    throw "The archive contains excluded paths: $($forbidden -join ', ')"
}
foreach ($required in 'start-signingsuite.ps1', 'MainWindow.xaml', 'Module/SigningSuite/SigningSuite.psd1', 'README.md', 'LICENSE') {
    if ($entries -notcontains $required) {
        throw "The archive is missing $required."
    }
}

$hash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
$checksums = Join-Path $OutputDirectory 'checksums.txt'
[System.IO.File]::WriteAllText($checksums, "$hash  $zipName`n", [System.Text.UTF8Encoding]::new($false))

[pscustomobject]@{
    Zip       = $zipPath
    Checksums = $checksums
    Sha256    = $hash
    Entries   = $entries.Count
}
