Set-StrictMode -Version 2.0

foreach ($folder in 'Private', 'Public') {
    $path = Join-Path $PSScriptRoot $folder
    if ([System.IO.Directory]::Exists($path)) {
        foreach ($file in [System.IO.Directory]::GetFiles($path, '*.ps1') | Sort-Object) {
            . $file
        }
    }
}
