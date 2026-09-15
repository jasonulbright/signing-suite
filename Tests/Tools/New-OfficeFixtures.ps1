#Requires -Version 5.1
<#
.SYNOPSIS
    Creates macro-enabled Office files for the Office VBA signing tests.

.DESCRIPTION
    Uses Excel, Word and PowerPoint through COM to write Macro.xlsm, Macro.xls, Macro.docm, Macro.pptm, Macro.ppt and
    NoMacro.xlsm. Adding a VBA module needs "Trust access to the VBA project object model" (AccessVBOM); the script
    turns it on per application and restores the previous value after that application's process has exited, because
    Word and PowerPoint write their Trust Center values back when they quit.

.PARAMETER OutputDirectory
    Folder for the fixtures. Point SIGNINGSUITE_OFFICE_FIXTURES at it before running the tests.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
[void][System.IO.Directory]::CreateDirectory($OutputDirectory)
$OutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).ProviderPath
$code = "Sub Hello()`r`n    MsgBox ""Signing Suite fixture""`r`nEnd Sub`r`n"

function Invoke-WithVbaAccess {
    param(
        [string]$Application,
        [string]$ProcessName,
        [scriptblock]$Action
    )

    $key = "HKCU:\Software\Microsoft\Office\16.0\$Application\Security"
    $existed = Test-Path -LiteralPath $key
    if (-not $existed) {
        [void](New-Item -Path $key -Force)
    }
    $previous = (Get-ItemProperty -LiteralPath $key -Name AccessVBOM -ErrorAction SilentlyContinue).AccessVBOM
    $before = @(Get-Process -Name $ProcessName -ErrorAction SilentlyContinue | ForEach-Object Id)
    Set-ItemProperty -LiteralPath $key -Name AccessVBOM -Value 1 -Type DWord
    try {
        & $Action
    }
    finally {
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
        $deadline = [DateTime]::UtcNow.AddSeconds(60)
        while ([DateTime]::UtcNow -lt $deadline -and @(Get-Process -Name $ProcessName -ErrorAction SilentlyContinue | Where-Object { $before -notcontains $_.Id }).Count -gt 0) {
            Start-Sleep -Milliseconds 500
        }
        if ($null -eq $previous) {
            Remove-ItemProperty -LiteralPath $key -Name AccessVBOM -ErrorAction SilentlyContinue
        }
        else {
            Set-ItemProperty -LiteralPath $key -Name AccessVBOM -Value $previous -Type DWord
        }
    }
}

Invoke-WithVbaAccess -Application Excel -ProcessName EXCEL -Action {
    $excel = New-Object -ComObject Excel.Application
    $excel.DisplayAlerts = $false
    try {
        foreach ($file in @(@{ Name = 'Macro.xlsm'; Format = 52; Vba = $true }, @{ Name = 'Macro.xls'; Format = 56; Vba = $true }, @{ Name = 'NoMacro.xlsm'; Format = 52; Vba = $false })) {
            $workbook = $excel.Workbooks.Add()
            if ($file.Vba) {
                [void]$workbook.VBProject.VBComponents.Add(1).CodeModule.AddFromString($code)
            }
            $workbook.SaveAs((Join-Path $OutputDirectory $file.Name), $file.Format)
            $workbook.Close($false)
        }
    }
    finally {
        $excel.Quit()
        [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($excel)
    }
}

Invoke-WithVbaAccess -Application Word -ProcessName WINWORD -Action {
    $word = New-Object -ComObject Word.Application
    $word.DisplayAlerts = 0
    try {
        $document = $word.Documents.Add()
        [void]$document.VBProject.VBComponents.Add(1).CodeModule.AddFromString($code)
        $document.SaveAs2([ref](Join-Path $OutputDirectory 'Macro.docm'), [ref]13)
        $document.Close([ref]0)
    }
    finally {
        $word.Quit([ref]0)
        [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($word)
    }
}

Invoke-WithVbaAccess -Application PowerPoint -ProcessName POWERPNT -Action {
    $powerPoint = New-Object -ComObject PowerPoint.Application
    try {
        foreach ($file in @(@{ Name = 'Macro.pptm'; Format = 25 }, @{ Name = 'Macro.ppt'; Format = 1 })) {
            $presentation = $powerPoint.Presentations.Add(0)
            [void]$presentation.Slides.Add(1, 12)
            [void]$presentation.VBProject.VBComponents.Add(1).CodeModule.AddFromString($code)
            $presentation.SaveAs((Join-Path $OutputDirectory $file.Name), $file.Format)
            $presentation.Close()
        }
    }
    finally {
        $powerPoint.Quit()
        [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($powerPoint)
    }
}

Get-ChildItem -LiteralPath $OutputDirectory -File | Select-Object Name, Length
