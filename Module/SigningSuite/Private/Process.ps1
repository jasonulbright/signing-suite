function Invoke-ExternalProcess {
    <#
    .SYNOPSIS
        Runs a console program with a timeout and returns exit code and output without deadlocking on full pipes.
    .DESCRIPTION
        Arguments are quoted by the CommandLineToArgvW rules. A timed-out process is killed and reported with ExitCode -1.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$ArgumentList,

        [int]$TimeoutSeconds = 300,

        [hashtable]$Environment
    )

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.Arguments = (@($ArgumentList | ForEach-Object { ConvertTo-CommandLineArgument -Value $_ }) -join ' ')
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    if ($Environment) {
        foreach ($name in $Environment.Keys) {
            $startInfo.EnvironmentVariables[$name] = [string]$Environment[$name]
        }
    }

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        [void]$process.Start()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $timedOut = -not $process.WaitForExit([Math]::Max(1, $TimeoutSeconds) * 1000)
        if ($timedOut) {
            try {
                $process.Kill()
            }
            catch {
                Write-Verbose "The process exited before it could be stopped: $($_.Exception.Message)"
            }
            [void]$process.WaitForExit(5000)
        }
        else {
            # The parameterless overload waits for the redirected streams to reach end of file.
            $process.WaitForExit()
        }

        [pscustomobject]@{
            ExitCode = if ($timedOut) { -1 } else { $process.ExitCode }
            TimedOut = $timedOut
            Output   = $stdout.GetAwaiter().GetResult()
            Error    = $stderr.GetAwaiter().GetResult()
        }
    }
    finally {
        $process.Dispose()
    }
}

function ConvertTo-CommandLineArgument {
    <#
    .SYNOPSIS
        Quotes one argument by the CommandLineToArgvW rules that Windows console programs use to parse their command line.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Value
    )

    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') {
        return $Value
    }
    $builder = [System.Text.StringBuilder]::new()
    [void]$builder.Append('"')
    $backslashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') {
            $backslashes++
            continue
        }
        if ($character -eq '"') {
            [void]$builder.Append('\', ($backslashes * 2) + 1)
        }
        elseif ($backslashes -gt 0) {
            [void]$builder.Append('\', $backslashes)
        }
        $backslashes = 0
        [void]$builder.Append($character)
    }
    [void]$builder.Append('\', $backslashes * 2)
    [void]$builder.Append('"')
    $builder.ToString()
}
