#Requires -Version 5.1
<#
.SYNOPSIS
  Start winremote-mcp with winremote-session-ext inside the current user session.

.DESCRIPTION
  Run this in the logon session whose desktop the tools should see and control
  (a console or RDP logon). The server runs as the current user at the current
  integrity level. The script does not elevate, does not create scheduled tasks
  or services, and does not change firewall, logon or registry settings.

  The API key comes from the WINREMOTE_AUTH_KEY environment variable, or from
  -KeyFile. It reaches the server only through the process environment, never
  on its command line.

.PARAMETER Python
  python.exe of the virtual environment where winremote-mcp and this extension
  are installed.

.PARAMETER BindHost
  Address to listen on. Default 127.0.0.1. Any other address also needs
  --ip-allowlist and TLS (see README.md, "Security and trust model").

.PARAMETER Port
  TCP port. Default 8090.

.PARAMETER KeyFile
  Text file that holds the API key. The script warns when Everyone,
  Authenticated Users or BUILTIN\Users can read it.

.PARAMETER ResultDir
  Directory that ReadResultFile may read from (sets WINREMOTE_EXT_RESULT_DIR).

.PARAMETER ServerArgs
  Extra upstream options, for example '--tools','WhoAmI,SessionList,Snapshot'.

.PARAMETER Background
  Start the server hidden and write its output to -LogDir.

.PARAMETER LogDir
  Log folder for -Background. Default %LOCALAPPDATA%\winremote-session-ext.

.EXAMPLE
  .\scripts\Start-SessionServer.ps1 -Python .\.venv\Scripts\python.exe -KeyFile "$HOME\.winremote\key.txt"

  -KeyFile reads the key, removes leading and trailing white space (a final
  line break included) and passes it to the server through its environment.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$Python,
    [string]$BindHost = '127.0.0.1',
    [ValidateRange(1, 65535)] [int]$Port = 8090,
    [string]$KeyFile,
    [string]$ResultDir,
    [string[]]$ServerArgs = @(),
    [switch]$Background,
    [string]$LogDir = (Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'winremote-session-ext')
)
$ErrorActionPreference = 'Stop'

function ConvertTo-ArgumentString([string[]]$Items) {
    # Quote for the Windows command line parser used by python.exe.
    ($Items | ForEach-Object {
        if ($_ -eq '' -or $_ -match '[\s"]') { '"' + ($_ -replace '(\\*)"', '$1$1\"' -replace '(\\+)$', '$1$1') + '"' }
        else { $_ }
    }) -join ' '
}

function Test-BroadReadAccess([string]$Path) {
    $broad = @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545')
    foreach ($rule in (Get-Acl -LiteralPath $Path).Access) {
        if ($rule.AccessControlType -ne 'Allow') { continue }
        if (-not ($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::ReadData)) { continue }
        try { $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { continue }
        if ($broad -contains $sid) { return $true }
    }
    return $false
}

if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) { throw "python.exe not found: $Python" }

$session = (Get-Process -Id $PID).SessionId
if ($session -eq 0) {
    throw 'This process runs in session 0, which has no interactive desktop. Run the script inside a user logon session.'
}

# The variables are set for the child process and restored afterwards, so a
# key read from -KeyFile does not stay in the calling PowerShell session.
$saved = @{
    WINREMOTE_AUTH_KEY       = $env:WINREMOTE_AUTH_KEY
    WINREMOTE_EXT_RESULT_DIR = $env:WINREMOTE_EXT_RESULT_DIR
}
$exitCode = 0
try {
    if ($KeyFile) {
        if (Test-BroadReadAccess $KeyFile) {
            Write-Warning "$KeyFile is readable by a broad group. Restrict it to your account."
        }
        $env:WINREMOTE_AUTH_KEY = (Get-Content -LiteralPath $KeyFile -Raw).Trim()
    }
    if (-not $env:WINREMOTE_AUTH_KEY) { throw 'Set WINREMOTE_AUTH_KEY or pass -KeyFile.' }

    if ($ResultDir) {
        $env:WINREMOTE_EXT_RESULT_DIR = (Resolve-Path -LiteralPath $ResultDir).ProviderPath
    }

    $arguments = @('-m', 'winremote_session_ext', '--transport', 'streamable-http',
        '--host', $BindHost, '--port', [string]$Port) + $ServerArgs

    if ($Background) {
        New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
        $process = Start-Process -FilePath $Python -ArgumentList (ConvertTo-ArgumentString $arguments) `
            -WindowStyle Hidden -PassThru `
            -RedirectStandardOutput (Join-Path $LogDir 'server.out.log') `
            -RedirectStandardError (Join-Path $LogDir 'server.err.log')
        Write-Output "Started pid $($process.Id) in session $session. Logs: $LogDir"
    }
    else {
        & $Python @arguments
        $exitCode = $LASTEXITCODE
    }
}
finally {
    foreach ($name in $saved.Keys) {
        if ($null -eq $saved[$name]) { Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue }
        else { Set-Item -LiteralPath "Env:$name" -Value $saved[$name] }
    }
}
exit $exitCode
