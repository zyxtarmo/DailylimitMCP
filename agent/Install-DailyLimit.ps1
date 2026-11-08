<#
  Install-DailyLimit.ps1 (v2) - run elevated, with DailyLimit.ps1 in the same folder.
  Safe to re-run: every run refreshes the script + task and updates only the settings you pass.

  MANAGED (recommended): the PC syncs limits, bonuses and locks with your control server every minute.
    .\Install-DailyLimit.ps1 -Server https://mcp.example.com -DeviceId pc-home -DeviceKey <key from server>
    .\Install-DailyLimit.ps1 -Disconnect           # back to local config only (keeps last settings)

  LOCAL (no server): policy lives in config.json on this PC.
    .\Install-DailyLimit.ps1 -Add kid1 -WeekdayMinutes 90 -WeekendMinutes 150 -WeekdayHours 15:00-20:00 -WeekendHours 09:00-21:00
    .\Install-DailyLimit.ps1 -Add kid1 -WeekdayMinutes 60            # change just one setting
    .\Install-DailyLimit.ps1 -List
    .\Install-DailyLimit.ps1 -Remove kid2

  .\Install-DailyLimit.ps1 -Uninstall

  Hours are HH:mm-HH:mm in 24h time, same day only (end may be 24:00); '' clears. Defaults for a new local user:
  120 min weekday / 180 min weekend, no hours restriction.
  -SyncLogonHours additionally sets Windows' own logon hours (net user /times) for a LOCAL -Add user as a second
  layer; needs both windows set, on whole hours.
#>
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$Server,
    [string]$DeviceId,
    [string]$DeviceKey,
    [switch]$Disconnect,
    [string]$Add,
    [string]$Remove,
    [switch]$List,
    [switch]$Uninstall,
    [int]$WeekdayMinutes = 120,
    [int]$WeekendMinutes = 180,
    [string]$WeekdayHours,
    [string]$WeekendHours,
    [switch]$SyncLogonHours
)
$ErrorActionPreference = 'Stop'
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}
$Dir     = Join-Path $env:ProgramData 'DailyLimit'
$CfgFile = Join-Path $Dir 'config.json'
$SrvFile = Join-Path $Dir 'server.json'
$Task    = 'DailyLimit'

if ($Uninstall) {
    Unregister-ScheduledTask -TaskName $Task -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item $Dir -Recurse -Force -ErrorAction SilentlyContinue
    'Removed task and ' + $Dir; return
}
if ($Disconnect) {
    Remove-Item $SrvFile, (Join-Path $Dir 'policy.json'), (Join-Path $Dir 'sync.status') -Force -ErrorAction SilentlyContinue
    'Disconnected from the server. Enforcement now uses config.json (-List shows it).'; return
}

function Read-Users {
    if (-not (Test-Path $CfgFile)) { return }
    $raw = Get-Content $CfgFile -Raw | ConvertFrom-Json
    if ($raw.Users) { $src = @($raw.Users) }
    elseif ($raw.User) {            # migrate old single-user config
        $src = @([pscustomobject]@{ Name = $raw.User; Weekday = $raw.Weekday; Weekend = $raw.Weekend; WeekdayHours = ''; WeekendHours = '' })
    } else { $src = @() }
    foreach ($x in $src) {
        [ordered]@{ Name = [string]$x.Name; Weekday = [int]$x.Weekday; Weekend = [int]$x.Weekend
                    WeekdayHours = [string]$x.WeekdayHours; WeekendHours = [string]$x.WeekendHours }
    }
}
function Write-Users($list) {
    $obj = @{ Users = @($list | ForEach-Object { $_ }) }
    ConvertTo-Json -InputObject $obj -Depth 5 | Set-Content $CfgFile -Encoding UTF8
}
function Test-Hours([string]$s, [string]$label) {
    if ([string]::IsNullOrWhiteSpace($s)) { return }
    if ($s -notmatch '^(\d{2}):(\d{2})-(\d{2}):(\d{2})$') { throw "$label must look like 08:00-20:00 (or '' for unrestricted)." }
    $a = [int]$Matches[1] * 60 + [int]$Matches[2]; $b = [int]$Matches[3] * 60 + [int]$Matches[4]
    if ([int]$Matches[2] -gt 59 -or [int]$Matches[4] -gt 59 -or $b -gt 1440 -or $a -ge $b) { throw "$label '$s' is not a valid same-day window." }
}

$users = New-Object System.Collections.ArrayList
Read-Users | ForEach-Object { [void]$users.Add($_) }

function Show-Users {
    foreach ($u in $users) {
        '  {0,-14} weekday {1} min [{2}]   weekend {3} min [{4}]' -f $u.Name, $u.Weekday, $(if ($u.WeekdayHours) { $u.WeekdayHours } else { 'any time' }), $u.Weekend, $(if ($u.WeekendHours) { $u.WeekendHours } else { 'any time' })
    }
}
if ($List) {
    if (Test-Path $SrvFile) { 'Managed by server: ' + (Get-Content $SrvFile -Raw | ConvertFrom-Json).Url + '  (local list below is only a fallback)' }
    if ($users.Count -eq 0) { 'No local users configured.'; return }
    Show-Users; return
}
if (-not $Add -and -not $Remove -and -not $Server) {
    throw 'Nothing to do. Use -Server/-DeviceId/-DeviceKey, -Add <user>, -Remove <user>, -List, -Disconnect or -Uninstall (see the header of this file).'
}

# ---- validate everything BEFORE touching the system ---------------------------------
if ($Server) {
    if (-not $DeviceId -or -not $DeviceKey) { throw '-Server needs -DeviceId and -DeviceKey.' }
    $u = [Uri]$Server
    if ($u.Scheme -ne 'https' -and $u.Host -notin 'localhost', '127.0.0.1') { throw 'The server URL must be https://.' }
    $Server = $Server.TrimEnd('/')
    $probe = ConvertTo-Json -InputObject @{ day = (Get-Date).ToString('yyyyMMdd'); agent_version = 'installer-test'; users = @() } -Compress
    try {
        $resp = Invoke-RestMethod -Uri "$Server/agent/v1/sync" -Method Post -TimeoutSec 15 -ContentType 'application/json' `
            -Headers @{ 'X-Device-Id' = $DeviceId; 'Authorization' = "Bearer $DeviceKey" } -Body $probe
    } catch { throw "Could not sync with $Server using that device id/key: $($_.Exception.Message)" }
    "Server reachable. It currently manages $(@($resp.Users).Count) child account(s)."
}

if ($Remove) {
    $hit = $users | Where-Object { $_.Name -ieq $Remove } | Select-Object -First 1
    if (-not $hit) { throw "'$Remove' is not configured locally." }
    $users.Remove($hit)
    Remove-Item (Join-Path $Dir "state\$($hit.Name).json") -Force -ErrorAction SilentlyContinue
    "Removed $($hit.Name) from the local list."
}

if ($Add) {
    $lu = Get-LocalUser -Name $Add                           # throws if the account doesn't exist
    $isAdmin = @(Get-LocalGroupMember -SID 'S-1-5-32-544' | Where-Object { $_.Name -like "*\$($lu.Name)" }).Count -gt 0
    if ($isAdmin) { Write-Warning "$($lu.Name) is an administrator - the limit can be bypassed. Make it a standard user first." }

    $entry = $users | Where-Object { $_.Name -ieq $lu.Name } | Select-Object -First 1
    if (-not $entry) {
        $entry = [ordered]@{ Name = $lu.Name; Weekday = 120; Weekend = 180; WeekdayHours = ''; WeekendHours = '' }
        [void]$users.Add($entry)
    }
    if ($PSBoundParameters.ContainsKey('WeekdayMinutes')) { $entry.Weekday = $WeekdayMinutes }
    if ($PSBoundParameters.ContainsKey('WeekendMinutes')) { $entry.Weekend = $WeekendMinutes }
    if ($PSBoundParameters.ContainsKey('WeekdayHours'))   { $entry.WeekdayHours = $WeekdayHours.Trim() }
    if ($PSBoundParameters.ContainsKey('WeekendHours'))   { $entry.WeekendHours = $WeekendHours.Trim() }
    Test-Hours $entry.WeekdayHours 'WeekdayHours'
    Test-Hours $entry.WeekendHours 'WeekendHours'
    if (Test-Path $SrvFile) { Write-Warning 'This PC is managed by the server; the local list is only a fallback until the first sync.' }
}

# Admin/SYSTEM-only folder. The task runs the script as SYSTEM, so a standard user must never be able to
# write here (SIDs used so it works on any Windows language). server.json holds the device key.
New-Item $Dir -ItemType Directory -Force | Out-Null
icacls $Dir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
New-Item (Join-Path $Dir 'state') -ItemType Directory -Force | Out-Null
Remove-Item (Join-Path $Dir 'state.json') -Force -ErrorAction SilentlyContinue   # old single-user state
Copy-Item (Join-Path $PSScriptRoot 'DailyLimit.ps1') $Dir -Force
Write-Users $users
if ($Server) {
    ConvertTo-Json -InputObject @{ Url = $Server; DeviceId = $DeviceId; Key = $DeviceKey } | Set-Content $SrvFile -Encoding UTF8
}

$action    = New-ScheduledTaskAction -Execute 'powershell.exe' `
             -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$Dir\DailyLimit.ps1`""
$triggers  = @(
    (New-ScheduledTaskTrigger -AtStartup),
    (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
        -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 3650))
)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
             -StartWhenAvailable -MultipleInstances IgnoreNew -Hidden -ExecutionTimeLimit (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName $Task -Action $action -Trigger $triggers -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $Task

if ($Add -and $SyncLogonHours) {
    $wd = $entry.WeekdayHours; $we = $entry.WeekendHours
    if ($wd -match '^\d{2}:00-\d{2}:00$' -and $we -match '^\d{2}:00-\d{2}:00$' -and $wd -notmatch '24:00' -and $we -notmatch '24:00') {
        net user $entry.Name /times:"M-F,$wd;Sa-Su,$we" | Out-Null
        "Windows logon hours set for $($entry.Name)."
    } else { Write-Warning 'Skipped -SyncLogonHours: needs both windows set, whole hours, no 24:00.' }
}

'Done.'
if ($Server) { "Managed by $Server as device '$DeviceId'. Limits are set from your Claude connector; the PC syncs every minute." }
if ($users.Count) { 'Local fallback list:'; Show-Users }
"Check:  & '$Dir\DailyLimit.ps1' -Status"
