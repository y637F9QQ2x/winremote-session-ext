<#
  Runs the main bodies of scripts\*.ps1 offline, called by tests/test_powershell.py.

  1. Start-SessionServer.ps1 runs with -Python set to the test Python and a stub
     winremote_session_ext package first on PYTHONPATH. The stub records its
     arguments and environment and exits; no server starts. '--reload' is passed
     as well, so if the real launcher ran instead of the stub it would refuse
     at once (exit 2) and the checks below would fail.
  2. Invoke-WinRemoteTool.ps1 (PowerShell 7 only) runs with Invoke-WebRequest
     replaced by a function that answers like an MCP server, so no request
     leaves the process.

  Needs PYTHON_FOR_TESTS (a python.exe). Everything it writes goes to a new
  folder under the temporary directory, which it deletes at the end.
#>
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).ProviderPath
$start = Join-Path $repo 'scripts\Start-SessionServer.ps1'
$invoke = Join-Path $repo 'scripts\Invoke-WinRemoteTool.ps1'
$script:failures = 0

function Check([bool]$Condition, [string]$Name) {
    if (-not $Condition) { $script:failures++; [Console]::Error.WriteLine("FAIL: $Name") }
}

$python = $env:PYTHON_FOR_TESTS
if (-not $python) { [Console]::Error.WriteLine('PYTHON_FOR_TESTS is not set'); exit 1 }

$work = Join-Path ([IO.Path]::GetTempPath()) ('wse-ps-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
Push-Location -LiteralPath $work
try {
    # ------------------------------------------------ 1. Start-SessionServer.ps1
    $stubPackage = Join-Path $work 'stub\winremote_session_ext'
    New-Item -ItemType Directory -Force -Path $stubPackage | Out-Null
    Set-Content -LiteralPath (Join-Path $stubPackage '__init__.py') -Value '' -Encoding ascii
    $stubMain = @'
import json, os, sys
report = os.environ["STUB_REPORT"]
with open(report + ".tmp", "w", encoding="utf-8") as f:
    json.dump({"argv": sys.argv[1:], "key": os.environ.get("WINREMOTE_AUTH_KEY"),
               "result_dir": os.environ.get("WINREMOTE_EXT_RESULT_DIR")}, f)
os.replace(report + ".tmp", report)
sys.exit(int(os.environ.get("STUB_EXIT", "0")))
'@
    Set-Content -LiteralPath (Join-Path $stubPackage '__main__.py') -Value $stubMain -Encoding ascii

    $key = 'K' + [guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N')
    $keyFile = Join-Path $work 'key.txt'
    Set-Content -LiteralPath $keyFile -Value $key -Encoding ascii  # ends with a line break
    $results = Join-Path $work 'results'
    New-Item -ItemType Directory -Path $results | Out-Null

    $env:PYTHONPATH = Join-Path $work 'stub'
    $env:STUB_REPORT = Join-Path $work 'report.json'
    $env:STUB_EXIT = '7'
    Remove-Item Env:WINREMOTE_AUTH_KEY -ErrorAction SilentlyContinue
    $env:WINREMOTE_EXT_RESULT_DIR = 'previous-dir'

    if ((Get-Process -Id $PID).SessionId -eq 0) {
        # Session 0, for example a CI runner that runs as a service: the script must refuse.
        $refused = $false
        try { & $start -Python $python -KeyFile $keyFile -ServerArgs '--reload' *> $null }
        catch { $refused = "$_" -like '*session 0*' }
        Check $refused 'Start-SessionServer refuses to run in session 0'
        Check (-not (Test-Path -LiteralPath $env:STUB_REPORT)) 'no server process starts in session 0'
    }
    else {
        & $start -Python $python -KeyFile $keyFile -ResultDir $results -Port 18090 -ServerArgs '--reload' *> $null
        $code = $LASTEXITCODE
        Check ($code -eq 7) "Start-SessionServer returns the server's exit code (got $code)"
        $report = Get-Content -LiteralPath $env:STUB_REPORT -Raw | ConvertFrom-Json
        $argv = @($report.argv)
        Check ($report.key -ceq $key) 'the key reaches the server through its environment, trimmed'
        Check (-not ($argv -contains $key)) 'the key is not on the server command line'
        Check (($argv -join ' ') -ceq '--transport streamable-http --host 127.0.0.1 --port 18090 --reload') "server arguments: $($argv -join ' ')"
        Check ($report.result_dir -eq $results) 'WINREMOTE_EXT_RESULT_DIR reaches the server'
        Check ($null -eq $env:WINREMOTE_AUTH_KEY) 'WINREMOTE_AUTH_KEY is removed again from the calling session'
        Check ($env:WINREMOTE_EXT_RESULT_DIR -eq 'previous-dir') 'WINREMOTE_EXT_RESULT_DIR is restored in the calling session'

        # A key that was already set in the calling session is restored after the run.
        $env:WINREMOTE_AUTH_KEY = 'previous-key'
        Remove-Item -LiteralPath $env:STUB_REPORT
        & $start -Python $python -KeyFile $keyFile -ServerArgs '--reload' *> $null
        $report = Get-Content -LiteralPath $env:STUB_REPORT -Raw | ConvertFrom-Json
        Check ($report.key -ceq $key) '-KeyFile wins over a key already in the environment'
        Check ($env:WINREMOTE_AUTH_KEY -ceq 'previous-key') 'a previous WINREMOTE_AUTH_KEY is restored'

        # -Background: hidden start with log files, same key handoff.
        Remove-Item Env:WINREMOTE_AUTH_KEY
        Remove-Item -LiteralPath $env:STUB_REPORT
        $env:STUB_EXIT = '0'
        $logs = Join-Path $work 'logs'
        $output = & $start -Python $python -KeyFile $keyFile -ServerArgs '--reload' -Background -LogDir $logs
        Check ($LASTEXITCODE -eq 0) '-Background returns 0'
        Check ([string]$output -like 'Started pid *') "-Background reports the pid: $output"
        $deadline = (Get-Date).AddSeconds(30)
        while (-not (Test-Path -LiteralPath $env:STUB_REPORT) -and (Get-Date) -lt $deadline) {
            Start-Sleep -Milliseconds 200
        }
        # The stub exits right after its report; wait for that, so its log files are closed.
        if ([string]$output -match 'Started pid (\d+)') {
            Wait-Process -Id ([int]$Matches[1]) -Timeout 30 -ErrorAction SilentlyContinue
        }
        Check (Test-Path -LiteralPath $env:STUB_REPORT) '-Background started the server process'
        if (Test-Path -LiteralPath $env:STUB_REPORT) {
            $report = Get-Content -LiteralPath $env:STUB_REPORT -Raw | ConvertFrom-Json
            Check ($report.key -ceq $key) '-Background passes the key through the environment'
            Check (-not (@($report.argv) -contains $key)) '-Background keeps the key off the command line'
        }
        Check (Test-Path -LiteralPath (Join-Path $logs 'server.err.log')) '-Background writes server.err.log'
        Check ($null -eq $env:WINREMOTE_AUTH_KEY) '-Background leaves no key in the calling session'
    }
    Remove-Item Env:PYTHONPATH, Env:STUB_REPORT, Env:STUB_EXIT, Env:WINREMOTE_EXT_RESULT_DIR

    # ------------------------------------------------ 2. Invoke-WinRemoteTool.ps1
    if ($PSVersionTable.PSVersion.Major -ge 7) {
        # The replacement keeps its state in $fake, captured by GetNewClosure().
        $fake = @{
            Calls      = [System.Collections.Generic.List[object]]::new()
            ToolResult = '{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"hello"}],"isError":false}}'
        }
        $replacement = {
            param(
                [string]$Uri, [string]$Method, [string]$ContentType, [switch]$SkipHttpErrorCheck,
                [hashtable]$Headers, [string]$Body, [int]$TimeoutSec
            )
            $fake.Calls.Add([pscustomobject]@{
                    Uri = $Uri; Method = $Method; ContentType = $ContentType
                    SkipHttpErrorCheck = [bool]$SkipHttpErrorCheck; Headers = $Headers.Clone()
                    Body = $Body; TimeoutSec = $TimeoutSec
                })
            if ($Method -eq 'Delete') { return [pscustomobject]@{ StatusCode = 200; Content = ''; Headers = @{} } }
            switch (($Body | ConvertFrom-Json).method) {
                'initialize' {
                    return [pscustomobject]@{
                        StatusCode = 200
                        Content    = '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"fake","version":"0"}}}'
                        Headers    = @{ 'Content-Type' = @('application/json'); 'mcp-session-id' = @('session-1') }
                    }
                }
                'notifications/initialized' { return [pscustomobject]@{ StatusCode = 202; Content = ''; Headers = @{} } }
                'tools/call' {
                    return [pscustomobject]@{
                        StatusCode = 200
                        Content    = "event: message`ndata: $($fake.ToolResult)`n`n"
                        Headers    = @{ 'Content-Type' = @('text/event-stream') }
                    }
                }
            }
            throw "unexpected request: $Body"
        }.GetNewClosure()
        New-Item -Path Function:\global:Invoke-WebRequest -Value $replacement | Out-Null
        # Run nothing unless the replacement is the command the script will call.
        if ((Get-Command Invoke-WebRequest).CommandType -ne 'Function') { throw 'Invoke-WebRequest is not replaced' }
        $url = 'http://127.0.0.1:1/mcp'
        try {
            Remove-Item Env:WINREMOTE_AUTH_KEY -ErrorAction SilentlyContinue
            $out = & $invoke -Tool WhoAmI -KeyFile $keyFile -Url $url -ArgsJson '{"a":1}'
            $code = $LASTEXITCODE
            Check ($code -eq 0) "Invoke-WinRemoteTool exit code 0 (got $code)"
            Check ([string]$out -ceq 'hello') "Invoke-WinRemoteTool prints the text result: $out"
            $calls = $fake.Calls
            Check ($calls.Count -eq 4) "four requests (got $($calls.Count))"
            if ($calls.Count -eq 4) {
                $methods = @($calls | ForEach-Object { if ($_.Body) { ($_.Body | ConvertFrom-Json).method } else { $_.Method } })
                Check (($methods -join ',') -ceq 'initialize,notifications/initialized,tools/call,Delete') "request order: $($methods -join ',')"
                Check (@($calls | Where-Object { $_.Uri -cne $url }).Count -eq 0) 'every request goes to -Url'
                Check (@($calls | Where-Object { -not $_.SkipHttpErrorCheck }).Count -eq 0) 'every request reads error statuses itself'
                Check (@($calls[0..2] | Where-Object { $_.ContentType -cne 'application/json' }).Count -eq 0) 'POST bodies are sent as JSON'
                Check (@($calls | Where-Object { $_.Headers['Authorization'] -cne "Bearer $key" }).Count -eq 0) 'every request carries the trimmed key'
                Check ($null -eq $calls[0].Headers['mcp-session-id']) 'initialize carries no session id'
                Check (@($calls[1..3] | Where-Object { $_.Headers['mcp-session-id'] -cne 'session-1' }).Count -eq 0) 'later requests carry the session id'
                Check ($calls[2].Headers['MCP-Protocol-Version'] -eq '2025-06-18') 'tools/call carries the negotiated protocol version'
                $params = ($calls[2].Body | ConvertFrom-Json).params
                Check ($params.name -ceq 'WhoAmI' -and $params.arguments.a -eq 1) 'tools/call names the tool and passes ArgsJson'
                Check ((($calls | ForEach-Object TimeoutSec) -join ',') -eq '20,20,150,5') "timeouts: $(($calls | ForEach-Object TimeoutSec) -join ',')"
            }
            Check ($null -eq $env:WINREMOTE_AUTH_KEY) '-KeyFile does not set WINREMOTE_AUTH_KEY'

            $fake.Calls.Clear()
            $raw = & $invoke -Tool WhoAmI -KeyFile $keyFile -Url $url -Raw
            Check ((($raw -join "`n") | ConvertFrom-Json).content[0].text -ceq 'hello') '-Raw prints the result object'

            $fake.ToolResult = '{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"failed"}],"isError":true}}'
            $fake.Calls.Clear()
            $null = & $invoke -Tool WhoAmI -KeyFile $keyFile -Url $url
            Check ($LASTEXITCODE -eq 1) 'a tool error gives exit code 1'
            Check ($fake.Calls[-1].Method -eq 'Delete') 'the session is closed after a tool error'

            $fake.Calls.Clear()
            $null = & $invoke -Tool WhoAmI -Url $url 2> $null
            Check ($LASTEXITCODE -eq 2) 'no key gives exit code 2'
            $null = & $invoke -Tool WhoAmI -KeyFile $keyFile -Url 'http://192.0.2.1:8090/mcp' 2> $null
            Check ($LASTEXITCODE -eq 2) 'plain http to a non-loopback host gives exit code 2'
            Check ($fake.Calls.Count -eq 0) 'no request is sent in the refused cases'
        }
        finally {
            Remove-Item -LiteralPath 'Function:\Invoke-WebRequest' -ErrorAction SilentlyContinue
        }
    }
}
finally {
    Pop-Location
    Remove-Item -LiteralPath $work -Recurse -Force
}

if ($script:failures) { exit 1 }
Write-Output 'script run checks passed'
exit 0
