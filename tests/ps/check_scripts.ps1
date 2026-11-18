<#
  Offline checks for scripts\*.ps1, run by tests/test_powershell.py:
  1. every script parses without errors (PowerShell AST);
  2. the pure helper functions behave as documented. They are loaded from the
     script's AST, so no script body runs.
  Needs PYTHON_FOR_TESTS (a python.exe) for the command line round trip.
#>
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).ProviderPath
$scripts = Join-Path $repo 'scripts'
$script:failures = 0

function Check([bool]$Condition, [string]$Name) {
    if (-not $Condition) { $script:failures++; [Console]::Error.WriteLine("FAIL: $Name") }
}

function Get-FunctionText([string]$Path, [string]$Name) {
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
    $fn = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $Name }, $true)
    if (-not $fn) { throw "function $Name not found in $Path" }
    return $fn.Extent.Text
}

foreach ($file in Get-ChildItem -LiteralPath $scripts -Filter *.ps1) {
    $tokens = $null; $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
    Check ($errors.Count -eq 0) "parse $($file.Name): $($errors | ForEach-Object Message)"
}

$start = Join-Path $scripts 'Start-SessionServer.ps1'
$invoke = Join-Path $scripts 'Invoke-WinRemoteTool.ps1'
. ([scriptblock]::Create((Get-FunctionText $start 'ConvertTo-ArgumentString')))
. ([scriptblock]::Create((Get-FunctionText $start 'Test-BroadReadAccess')))
. ([scriptblock]::Create((Get-FunctionText $invoke 'Test-LoopbackHost')))
. ([scriptblock]::Create((Get-FunctionText $invoke 'Read-RpcMessage')))

# ConvertTo-ArgumentString: round trip through python's own argv parsing.
$python = $env:PYTHON_FOR_TESTS
if ($python) {
    $items = @('plain', 'with space', 'quote"inside', 'trail\', 'C:\dir with space\', '', 'a\\"b', '--tools=WhoAmI,Snapshot')
    $code = 'import sys, json; sys.stdout.write(json.dumps(sys.argv[1:]))'
    $info = [System.Diagnostics.ProcessStartInfo]::new($python)
    $info.Arguments = ConvertTo-ArgumentString (@('-I', '-c', $code) + $items)
    $info.UseShellExecute = $false
    $info.RedirectStandardOutput = $true
    $info.CreateNoWindow = $true
    $proc = [System.Diagnostics.Process]::Start($info)
    $out = $proc.StandardOutput.ReadToEnd()
    $proc.WaitForExit()
    $parsed = $out | ConvertFrom-Json
    $parsed = @($parsed)  # Windows PowerShell 5.1 emits a JSON array as one object
    Check ($parsed.Count -eq $items.Count) 'argument count survives quoting'
    for ($i = 0; $i -lt $items.Count; $i++) {
        Check ($parsed[$i] -ceq $items[$i]) "argument round trip: [$($items[$i])]"
    }
}
else { Check $false 'PYTHON_FOR_TESTS is not set' }

# Test-LoopbackHost
Check (Test-LoopbackHost '127.0.0.1') 'loopback 127.0.0.1'
Check (Test-LoopbackHost 'localhost') 'loopback localhost'
Check (Test-LoopbackHost '[::1]') 'loopback [::1]'
Check (-not (Test-LoopbackHost '192.0.2.1')) 'not loopback 192.0.2.1'
Check (-not (Test-LoopbackHost 'example.com')) 'not loopback example.com'

# Read-RpcMessage: SSE with a notification before the response, and plain JSON.
$sse = [pscustomobject]@{
    Content = "event: message`r`ndata: {`"jsonrpc`":`"2.0`",`"method`":`"notifications/progress`"}`r`n`r`n" +
              "event: message`r`ndata: {`"jsonrpc`":`"2.0`",`"id`":2,`"result`":{`"content`":[]}}`r`n`r`n"
    Headers = @{ 'Content-Type' = @('text/event-stream') }
}
Check ((Read-RpcMessage $sse 2).id -eq 2) 'SSE response picked by id'
$json = [pscustomobject]@{ Content = '{"jsonrpc":"2.0","id":1,"result":{}}'; Headers = @{ 'Content-Type' = @('application/json') } }
Check ((Read-RpcMessage $json 1).id -eq 1) 'JSON response parsed'

# Test-BroadReadAccess on a temporary file.
$tmp = [IO.Path]::GetTempFileName()
try {
    # icacls changes only this temporary file's ACL.
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    & icacls.exe $tmp /inheritance:r /grant:r "*${me}:F" | Out-Null
    Check (-not (Test-BroadReadAccess $tmp)) 'owner-only file is not broad'
    & icacls.exe $tmp /grant '*S-1-5-32-545:R' | Out-Null
    Check (Test-BroadReadAccess $tmp) 'BUILTIN\Users read is broad'
}
finally { Remove-Item -LiteralPath $tmp -Force }

if ($script:failures) { exit 1 }
Write-Output 'powershell checks passed'
exit 0
