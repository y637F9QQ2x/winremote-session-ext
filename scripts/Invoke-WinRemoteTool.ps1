#Requires -Version 7.0
<#
.SYNOPSIS
  Call one tool on a winremote-mcp server over streamable HTTP, without an MCP client.

.DESCRIPTION
  Sends initialize, notifications/initialized and tools/call on one MCP session,
  prints the text result (or the JSON result with -Raw) and ends the session.
  The API key is read from -KeyFile into a local variable, or else from the
  WINREMOTE_AUTH_KEY environment variable. The script sets no environment variable.

  Exit codes: 0 success, 1 the tool reported an error, 2 transport or protocol failure.

.PARAMETER Tool
  Tool name, for example WhoAmI.

.PARAMETER ArgsJson
  Tool arguments as a JSON object. Default '{}'.

.PARAMETER Url
  Server endpoint. Default http://127.0.0.1:8090/mcp (for example through an SSH tunnel).

.PARAMETER KeyFile
  Text file that holds the API key. Leading and trailing white space is removed.
  Without it, the key comes from WINREMOTE_AUTH_KEY.

.PARAMETER TimeoutSec
  Timeout in seconds for the tools/call request. Default 150, which is longer
  than the 120 s that WaitForWindow waits at most. initialize and
  notifications/initialized use 20 s, the closing DELETE uses 5 s.

.PARAMETER Raw
  Print the JSON result object instead of the text content.

.PARAMETER AllowPlainHttp
  Permit an http:// URL that is not loopback. The key then crosses the network in clear text.

.EXAMPLE
  .\scripts\Invoke-WinRemoteTool.ps1 -KeyFile "$HOME\.winremote\key.txt" -Tool WhoAmI

.EXAMPLE
  .\scripts\Invoke-WinRemoteTool.ps1 -KeyFile "$HOME\.winremote\key.txt" -Tool WaitForWindow -ArgsJson '{"title":"Notepad","timeout_s":30}'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$Tool,
    [string]$ArgsJson = '{}',
    [string]$Url = 'http://127.0.0.1:8090/mcp',
    [string]$KeyFile,
    [ValidateRange(1, 3600)] [int]$TimeoutSec = 150,
    [switch]$Raw,
    [switch]$AllowPlainHttp
)
$ErrorActionPreference = 'Stop'

function Test-LoopbackHost([string]$HostName) {
    $name = $HostName.Trim('[', ']')
    if ($name -eq 'localhost') { return $true }
    $address = $null
    if ([Net.IPAddress]::TryParse($name, [ref]$address)) { return [Net.IPAddress]::IsLoopback($address) }
    return $false
}

function Read-RpcMessage($Response, [int]$Id) {
    $body = [string]$Response.Content
    $type = [string]($Response.Headers['Content-Type'] | Select-Object -First 1)
    if ($type -like 'application/json*') { return ($body | ConvertFrom-Json) }
    # text/event-stream: events are separated by a blank line; data lines are joined.
    foreach ($block in ($body -split "`r?`n`r?`n")) {
        $data = @($block -split "`r?`n" | Where-Object { $_ -like 'data:*' } |
            ForEach-Object { $_.Substring(5).TrimStart() }) -join "`n"
        if (-not $data) { continue }
        $message = $data | ConvertFrom-Json
        if ($message.PSObject.Properties['id'] -and $message.id -eq $Id) { return $message }
    }
    throw "no JSON-RPC response with id $Id (content type '$type')"
}

if ($KeyFile) {
    try { $key = ([string](Get-Content -LiteralPath $KeyFile -Raw)).Trim() }
    catch { [Console]::Error.WriteLine("cannot read the key file: $($_.Exception.Message)"); exit 2 }
}
else { $key = $env:WINREMOTE_AUTH_KEY }
if (-not $key) { [Console]::Error.WriteLine('no API key: pass -KeyFile or set WINREMOTE_AUTH_KEY'); exit 2 }

$uri = [Uri]$Url
if ($uri.Scheme -notin 'http', 'https') { [Console]::Error.WriteLine("unsupported URL scheme: $($uri.Scheme)"); exit 2 }
if ($uri.Scheme -eq 'http' -and -not (Test-LoopbackHost $uri.Host) -and -not $AllowPlainHttp) {
    [Console]::Error.WriteLine('refusing plain HTTP to a non-loopback host; use an SSH tunnel or https, or pass -AllowPlainHttp')
    exit 2
}

try { $arguments = $ArgsJson | ConvertFrom-Json -AsHashtable }
catch { [Console]::Error.WriteLine("ArgsJson is not valid JSON: $($_.Exception.Message)"); exit 2 }
if ($null -eq $arguments) { $arguments = @{} }

$headers = @{ Authorization = "Bearer $key"; Accept = 'application/json, text/event-stream' }
$common = @{ Uri = $Url; Method = 'Post'; ContentType = 'application/json'; SkipHttpErrorCheck = $true }
$sessionHeaders = $null
try {
    $init = @{ jsonrpc = '2.0'; id = 1; method = 'initialize'; params = @{
            protocolVersion = '2025-06-18'; capabilities = @{}
            clientInfo = @{ name = 'Invoke-WinRemoteTool'; version = '0.1.0' } } } |
        ConvertTo-Json -Depth 6 -Compress
    $r1 = Invoke-WebRequest @common -Headers $headers -Body $init -TimeoutSec 20
    if ([int]$r1.StatusCode -ne 200) { [Console]::Error.WriteLine("initialize: HTTP $($r1.StatusCode) $($r1.Content)"); exit 2 }
    $initResult = Read-RpcMessage $r1 1
    if ($initResult.PSObject.Properties['error']) { [Console]::Error.WriteLine("initialize: $($initResult.error | ConvertTo-Json -Compress)"); exit 2 }

    $sessionHeaders = $headers.Clone()
    $sessionId = [string]($r1.Headers['mcp-session-id'] | Select-Object -First 1)
    if ($sessionId) { $sessionHeaders['mcp-session-id'] = $sessionId }
    $sessionHeaders['MCP-Protocol-Version'] = [string]$initResult.result.protocolVersion

    $note = @{ jsonrpc = '2.0'; method = 'notifications/initialized' } | ConvertTo-Json -Compress
    [void](Invoke-WebRequest @common -Headers $sessionHeaders -Body $note -TimeoutSec 20)

    $call = @{ jsonrpc = '2.0'; id = 2; method = 'tools/call'; params = @{ name = $Tool; arguments = $arguments } } |
        ConvertTo-Json -Depth 20 -Compress
    $r3 = Invoke-WebRequest @common -Headers $sessionHeaders -Body $call -TimeoutSec $TimeoutSec
    if ([int]$r3.StatusCode -ne 200) { [Console]::Error.WriteLine("tools/call: HTTP $($r3.StatusCode) $($r3.Content)"); exit 2 }
    $message = Read-RpcMessage $r3 2
}
catch {
    [Console]::Error.WriteLine("transport failure: $($_.Exception.Message)")
    exit 2
}
finally {
    if ($sessionHeaders -and $sessionHeaders['mcp-session-id']) {
        try { [void](Invoke-WebRequest -Uri $Url -Method Delete -Headers $sessionHeaders -TimeoutSec 5 -SkipHttpErrorCheck) }
        catch { Write-Verbose "session delete failed: $($_.Exception.Message)" }
    }
}

if ($message.PSObject.Properties['error']) {
    [Console]::Error.WriteLine("JSON-RPC error: $($message.error | ConvertTo-Json -Compress -Depth 6)")
    exit 2
}
if ($Raw) { $message.result | ConvertTo-Json -Depth 20 }
else {
    $texts = @($message.result.content | Where-Object { $_.type -eq 'text' } | ForEach-Object { $_.text })
    if ($texts.Count) { $texts -join "`n" } else { $message.result | ConvertTo-Json -Depth 20 -Compress }
}
if ($message.result.isError) { exit 1 }
exit 0
