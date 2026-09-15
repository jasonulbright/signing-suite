#Requires -Version 5.1
<#
.SYNOPSIS
    Builds the x64 and x86 test digest-signing libraries used by the signtool /dlib tests.

.DESCRIPTION
    Needs Visual Studio or Build Tools with the C++ workload. Output goes to Tests\Native\bin\<arch>\TestDigestSign.dll.
    The libraries are test fixtures only and are never packaged.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) {
    throw 'vswhere.exe was not found; install Visual Studio or Build Tools with the C++ workload.'
}
$installation = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $installation) {
    throw 'No Visual Studio installation with the C++ x86/x64 tools was found.'
}
$vcvars = Join-Path $installation 'VC\Auxiliary\Build\vcvarsall.bat'
# vcvarsall.bat calls vswhere.exe by name.
$env:PATH = "$(Split-Path -Parent $vswhere);$env:PATH"

foreach ($arch in 'x64', 'x86') {
    $out = Join-Path $PSScriptRoot "bin\$arch"
    $obj = Join-Path $PSScriptRoot "obj\$arch"
    [void][System.IO.Directory]::CreateDirectory($out)
    [void][System.IO.Directory]::CreateDirectory($obj)
    $source = Join-Path $PSScriptRoot 'TestDigestSign.c'
    $def = Join-Path $PSScriptRoot 'TestDigestSign.def'
    $dll = Join-Path $out 'TestDigestSign.dll'
    $batch = Join-Path $obj 'build.cmd'
    [System.IO.File]::WriteAllLines($batch, [string[]]@(
        '@echo off'
        "call `"$vcvars`" $arch >nul || exit /b 1"
        "cl.exe /nologo /W4 /WX /O2 /LD /Fo`"$obj\\`" `"$source`" /link /NOLOGO /DEF:`"$def`" /OUT:`"$dll`""
    ))
    & cmd.exe /d /c "`"$batch`""
    if ($LASTEXITCODE -ne 0) {
        throw "Building the $arch test digest-signing library failed with exit code $LASTEXITCODE."
    }
}
