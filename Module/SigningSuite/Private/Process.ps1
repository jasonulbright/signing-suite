if (-not ('SigningSuite.Native.ProcessRunner' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections;
using System.ComponentModel;
using System.Diagnostics;
using System.Text;
using System.Threading;

namespace SigningSuite.Native
{
    public sealed class ProcessResult
    {
        public int ExitCode;
        public bool TimedOut;
        public bool StreamsClosed;
        public string Output;
        public string Error;
    }

    public static class ProcessRunner
    {
        public static ProcessResult Run(string fileName, string arguments, int timeoutMilliseconds, IDictionary environment)
        {
            StringBuilder output = new StringBuilder();
            StringBuilder error = new StringBuilder();
            ManualResetEvent outputClosed = new ManualResetEvent(false);
            ManualResetEvent errorClosed = new ManualResetEvent(false);

            ProcessStartInfo info = new ProcessStartInfo(fileName, arguments);
            info.UseShellExecute = false;
            info.CreateNoWindow = true;
            info.RedirectStandardOutput = true;
            info.RedirectStandardError = true;
            if (environment != null)
            {
                foreach (DictionaryEntry entry in environment)
                {
                    info.EnvironmentVariables[(string)entry.Key] = entry.Value == null ? null : entry.Value.ToString();
                }
            }

            ProcessResult result = new ProcessResult();
            using (Process process = new Process())
            {
                process.StartInfo = info;
                process.OutputDataReceived += delegate(object sender, DataReceivedEventArgs e)
                {
                    if (e.Data == null) { outputClosed.Set(); } else { lock (output) { output.AppendLine(e.Data); } }
                };
                process.ErrorDataReceived += delegate(object sender, DataReceivedEventArgs e)
                {
                    if (e.Data == null) { errorClosed.Set(); } else { lock (error) { error.AppendLine(e.Data); } }
                };
                process.Start();
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();

                result.TimedOut = !process.WaitForExit(Math.Max(1, timeoutMilliseconds));
                if (result.TimedOut)
                {
                    try { process.Kill(); }
                    catch (InvalidOperationException) { }
                    catch (Win32Exception) { }
                    process.WaitForExit(5000);
                }

                // A child process that inherited the pipe handles keeps both streams open after the parent exits.
                // WaitHandle.WaitAll is not allowed on STA threads, so the two events are awaited one after the other.
                DateTime deadline = DateTime.UtcNow.AddSeconds(10);
                bool outputDone = outputClosed.WaitOne(Remaining(deadline));
                bool errorDone = errorClosed.WaitOne(Remaining(deadline));
                result.StreamsClosed = outputDone && errorDone;
                result.ExitCode = (!result.TimedOut && process.HasExited) ? process.ExitCode : -1;
                lock (output) { result.Output = output.ToString(); }
                lock (error) { result.Error = error.ToString(); }
                if (!result.StreamsClosed)
                {
                    try { process.CancelOutputRead(); } catch (InvalidOperationException) { }
                    try { process.CancelErrorRead(); } catch (InvalidOperationException) { }
                }
            }
            return result;
        }

        private static TimeSpan Remaining(DateTime deadline)
        {
            TimeSpan left = deadline - DateTime.UtcNow;
            return left > TimeSpan.Zero ? left : TimeSpan.Zero;
        }
    }
}
'@
}

function Invoke-ExternalProcess {
    <#
    .SYNOPSIS
        Runs a console program with a timeout and returns exit code and output without deadlocking on full pipes.
    .DESCRIPTION
        Arguments are quoted by the CommandLineToArgvW rules. A timed-out process is killed and reported with ExitCode -1.
        Output already read is returned even when a child process keeps the pipes open past the wait.
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

    $arguments = (@($ArgumentList | ForEach-Object { ConvertTo-CommandLineArgument -Value $_ }) -join ' ')
    $result = [SigningSuite.Native.ProcessRunner]::Run($FilePath, $arguments, [Math]::Max(1, $TimeoutSeconds) * 1000, $Environment)
    $errorText = $result.Error
    if (-not $result.StreamsClosed) {
        $errorText += 'Output may be incomplete: a child process kept the output pipes open.'
    }

    [pscustomobject]@{
        ExitCode      = $result.ExitCode
        TimedOut      = $result.TimedOut
        StreamsClosed = $result.StreamsClosed
        Output        = $result.Output
        Error         = $errorText
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
