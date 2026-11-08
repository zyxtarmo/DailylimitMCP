<#
  DailyLimit.ps1 (v2) - per-user daily screen-time cap AND allowed-hours window for local Windows accounts.
  Runs as SYSTEM from a scheduled task every minute (see Install-DailyLimit.ps1).

  Two modes:
    * Local   : policy comes from config.json (edited with Install-DailyLimit.ps1 -Add ...).
    * Managed : if server.json exists, every run syncs with the control server: it uploads today's usage and
                downloads the policy (limits, hours, today's bonus, parent locks). The last policy is cached in
                policy.json, so enforcement keeps working offline. The server's clock + time zone are used for
                the hours window, so changing the PC clock / time zone doesn't help (while syncs succeed).

  For each configured user:
    * a minute is counted only while their session is Active (not disconnected, not locked)
    * outside the allowed hours, or while locked by a parent -> logged off (also when logging in)
    * daily minutes used up                                  -> logged off
    * warnings at 10 / 5 / 1 minutes left (whichever limit ends first)

  Admin helpers (run elevated):
    .\DailyLimit.ps1 -Status [-User kid]
    .\DailyLimit.ps1 -User kid -AddMinutes 30    # LOCAL mode only: bonus minutes for today
    .\DailyLimit.ps1 -User kid -Reset            # zero today's local counter
    .\DailyLimit.ps1 -NoSync                     # run once without contacting the server (debugging)
#>
[CmdletBinding()]
param(
    [string]$User,
    [switch]$Status,
    [int]$AddMinutes = 0,
    [switch]$Reset,
    [switch]$NoSync
)

$ErrorActionPreference = 'Stop'
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}

$AgentVersion = '2'
$Dir        = Join-Path $env:ProgramData 'DailyLimit'
$CfgFile    = Join-Path $Dir 'config.json'
$SrvFile    = Join-Path $Dir 'server.json'
$PolFile    = Join-Path $Dir 'policy.json'
$SyncStatus = Join-Path $Dir 'sync.status'
$StDir      = Join-Path $Dir 'state'
$LogFile    = Join-Path $Dir 'log.txt'
$WarnAt     = 10, 5, 1

function Write-Log([string]$m) {
    try {
        if ((Test-Path $LogFile) -and (Get-Item $LogFile).Length -gt 1MB) { Move-Item $LogFile "$LogFile.old" -Force }
        Add-Content -Path $LogFile -Value ("{0:yyyy-MM-dd HH:mm:ss} {1}" -f (Get-Date), $m)
    } catch {}
}

if (-not ('Wts' -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class Wts {
  [StructLayout(LayoutKind.Sequential)]
  struct WTS_SESSION_INFO { public int SessionId; public IntPtr WinStationName; public int State; }
  [DllImport("wtsapi32.dll", SetLastError=true)]
  static extern bool WTSEnumerateSessionsW(IntPtr h, int reserved, int version, out IntPtr info, out int count);
  [DllImport("wtsapi32.dll")]
  static extern void WTSFreeMemory(IntPtr p);
  [DllImport("wtsapi32.dll", SetLastError=true)]
  static extern bool WTSQuerySessionInformationW(IntPtr h, int id, int infoClass, out IntPtr buf, out int bytes);
  [DllImport("wtsapi32.dll", SetLastError=true)]
  static extern bool WTSLogoffSession(IntPtr h, int id, bool wait);
  [DllImport("wtsapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern bool WTSSendMessageW(IntPtr h, int id, string title, int titleLen, string msg, int msgLen, int style, int timeout, out int response, bool wait);

  // "id|user|state" per session; state 0 = Active
  public static List<string> Sessions() {
    var list = new List<string>();
    IntPtr p; int n;
    if (!WTSEnumerateSessionsW(IntPtr.Zero, 0, 1, out p, out n)) return list;
    int sz = Marshal.SizeOf(typeof(WTS_SESSION_INFO));
    for (int i = 0; i < n; i++) {
      var si = (WTS_SESSION_INFO)Marshal.PtrToStructure(new IntPtr(p.ToInt64() + (long)i * sz), typeof(WTS_SESSION_INFO));
      string user = "";
      IntPtr b; int bytes;
      if (WTSQuerySessionInformationW(IntPtr.Zero, si.SessionId, 5, out b, out bytes)) {
        user = Marshal.PtrToStringUni(b);
        WTSFreeMemory(b);
      }
      list.Add(si.SessionId + "|" + user + "|" + si.State);
    }
    WTSFreeMemory(p);
    return list;
  }
  public static void Logoff(int id) { WTSLogoffSession(IntPtr.Zero, id, false); }
  public static void Msg(int id, string title, string text) {
    int r;
    WTSSendMessageW(IntPtr.Zero, id, title, title.Length * 2, text, text.Length * 2, 0x40, 0, out r, false);
  }
}
"@
}

# ---- policy source + trusted clock ---------------------------------------------
$managed = Test-Path $SrvFile

function Get-Policy {
    if (Test-Path $PolFile) {
        try { return (Get-Content $PolFile -Raw | ConvertFrom-Json) } catch { Write-Log 'policy cache unreadable' }
    }
    return $null
}

# Wall-clock time as the SERVER sees it (managed mode with a cached sync); otherwise the PC's own clock.
function Get-TrustedNow($pol) {
    if ($managed -and $pol -and $null -ne $pol.ClockOffsetSeconds) {
        return [DateTime]::UtcNow.AddSeconds([double]$pol.ClockOffsetSeconds).AddMinutes([double]$pol.UtcOffsetMinutes)
    }
    return Get-Date
}
function Get-TrustedEpoch($pol) {
    $e = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    if ($managed -and $pol -and $null -ne $pol.ClockOffsetSeconds) { $e += [long]$pol.ClockOffsetSeconds }
    return $e
}

function Get-LocalUsers {
    if (-not (Test-Path $CfgFile)) { return @() }
    $c = Get-Content $CfgFile -Raw | ConvertFrom-Json
    return @($c.Users)
}

$pol   = $(if ($managed) { Get-Policy } else { $null })
$now   = Get-TrustedNow $pol
$today = $now.ToString('yyyyMMdd')
New-Item -ItemType Directory -Path $StDir -Force | Out-Null

function New-UserState { [pscustomobject]@{ Day = $today; Minutes = 0.0; Bonus = 0; LastTicks = 0L; Warned = @() } }

function Get-UserState([string]$name) {
    $f = Join-Path $StDir "$name.json"
    $s = $null
    if (Test-Path $f) {
        try { $s = Get-Content $f -Raw | ConvertFrom-Json } catch { Write-Log "[$name] state unreadable, reset" }
    }
    if (-not $s -or [string]$s.Day -ne $today) { $s = New-UserState }
    return $s
}
function Set-UserState([string]$name, $s) {
    $s | ConvertTo-Json | Set-Content -Path (Join-Path $StDir "$name.json") -Encoding UTF8
}

function Get-Users($pol) {
    if ($managed -and $pol) { return @($pol.Users) }
    return @(Get-LocalUsers)
}

# ---- sync with the control server (managed mode) -----------------------------------
function Invoke-Sync($users) {
    $srv = Get-Content $SrvFile -Raw | ConvertFrom-Json
    $report = @()
    foreach ($u in $users) {
        $s = Get-UserState ([string]$u.Name)
        $report += @{ name = [string]$u.Name; minutes = [Math]::Round([double]$s.Minutes, 2) }
    }
    $body = ConvertTo-Json -InputObject @{ day = $today; agent_version = $AgentVersion; users = @($report) } -Depth 5 -Compress
    $t0 = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $resp = Invoke-RestMethod -Uri (([string]$srv.Url).TrimEnd('/') + '/agent/v1/sync') -Method Post -TimeoutSec 8 `
        -ContentType 'application/json; charset=utf-8' `
        -Headers @{ 'X-Device-Id' = [string]$srv.DeviceId; 'Authorization' = "Bearer $($srv.Key)" } `
        -Body ([Text.Encoding]::UTF8.GetBytes($body))
    $t1 = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $new = [ordered]@{
        PolicyDay          = [string]$resp.day
        ClockOffsetSeconds = [long]$resp.server_time - [long][Math]::Round(($t0 + $t1) / 2)
        UtcOffsetMinutes   = [int]$resp.utc_offset_minutes
        SyncedEpoch        = $t1
        Users              = @($resp.Users)
    }
    ConvertTo-Json -InputObject $new -Depth 6 | Set-Content -Path $PolFile -Encoding UTF8
}

function Set-SyncStatus([string]$state, [string]$detail) {
    $prev = $(if (Test-Path $SyncStatus) { (Get-Content $SyncStatus -Raw).Trim() } else { '' })
    if ($prev -ne $state) { Write-Log "server sync $state $detail" }          # log transitions only
    Set-Content -Path $SyncStatus -Value $state
}

$syncOk = $null
if ($managed -and -not $NoSync -and -not $Status -and -not $Reset -and $AddMinutes -eq 0) {
    try {
        Invoke-Sync (Get-Users $pol)
        $syncOk = $true; Set-SyncStatus 'ok' ''
    } catch {
        $syncOk = $false; Set-SyncStatus 'failed' "($($_.Exception.Message)) - enforcing cached policy"
    }
    $pol   = Get-Policy                                  # fresh (or still the cached one)
    $now   = Get-TrustedNow $pol
    $today = $now.ToString('yyyyMMdd')
}

$users     = @(Get-Users $pol)
$isWeekend = $now.DayOfWeek -in 'Saturday', 'Sunday'
$nowEpoch  = Get-TrustedEpoch $pol

# "08:00-20:00" -> window object; empty -> $null (unrestricted). "24:00" allowed as end.
function Get-Window([string]$spec) {
    if ([string]::IsNullOrWhiteSpace($spec)) { return $null }
    $p = $spec.Split('-')
    $end = $(if ($p[1] -eq '24:00') { New-TimeSpan -Hours 24 } else { [TimeSpan]::Parse($p[1]) })
    [pscustomobject]@{ Start = [TimeSpan]::Parse($p[0]); End = $end }
}

function Get-Limits($u, $st) {
    $spec = $(if ($isWeekend) { [string]$u.WeekendHours } else { [string]$u.WeekdayHours })
    $base = $(if ($isWeekend) { [int]$u.Weekend } else { [int]$u.Weekday })
    $bonus = 0
    if ($managed -and $pol) {
        if ([string]$pol.PolicyDay -eq $today -and $null -ne $u.Bonus) { $bonus = [int]$u.Bonus }   # stale-day bonus ignored
    } else { $bonus = [int]$st.Bonus }
    $lockedUntil = $(if ($null -ne $u.LockedUntil) { [long]$u.LockedUntil } else { 0L })
    [pscustomobject]@{ Minutes = [Math]::Max(0, $base + $bonus); Window = (Get-Window $spec); Spec = $spec; LockedUntil = $lockedUntil }
}

# ---- admin helpers ------------------------------------------------------------
function Find-User([string]$name) {
    $u = $users | Where-Object { $_.Name -ieq $name } | Select-Object -First 1
    if (-not $u) { throw "User '$name' is not configured. Configured: $(($users | ForEach-Object Name) -join ', ')" }
    return $u
}

if ($Reset) {
    if (-not $User) { throw '-Reset needs -User <name>.' }
    $u = Find-User $User
    Set-UserState $u.Name (New-UserState); Write-Log "[$($u.Name)] manual reset"
    "$($u.Name): counter reset."; return
}
if ($AddMinutes -ne 0) {
    if ($managed) { throw 'Managed mode: add bonus time through the control server (add_bonus), not locally.' }
    if (-not $User) { throw '-AddMinutes needs -User <name>.' }
    $u  = Find-User $User
    $st = Get-UserState $u.Name
    $st.Bonus = [int]$st.Bonus + $AddMinutes; $st.Warned = @()
    Set-UserState $u.Name $st; Write-Log "[$($u.Name)] bonus $AddMinutes min (now $($st.Bonus))"
    "$($u.Name): bonus today is now $($st.Bonus) min."; return
}
if ($Status) {
    if ($managed) {
        $age = $(if ($pol -and $pol.SyncedEpoch) { [Math]::Round(([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - [long]$pol.SyncedEpoch) / 60, 1) } else { 'never' })
        "Managed by server; last successful sync: $age min ago; server time now: $($now.ToString('yyyy-MM-dd HH:mm'))"
    } else { 'Local mode (no server.json).' }
    $sel = $(if ($User) { @(Find-User $User) } else { $users })
    foreach ($u in $sel) {
        $st = Get-UserState $u.Name; $l = Get-Limits $u $st
        $lock = $(if ($l.LockedUntil -gt $nowEpoch) { '  LOCKED by parent' } else { '' })
        '{0,-14} used {1,6:N1} / {2} min   remaining {3,6:N1}   hours today: {4}{5}' -f `
            $u.Name, $st.Minutes, $l.Minutes, ($l.Minutes - $st.Minutes), $(if ($l.Spec) { $l.Spec } else { 'unrestricted' }), $lock
    }
    return
}

# ---- main loop ----------------------------------------------------------------
$sessions = @([Wts]::Sessions() | ForEach-Object {
    $p = $_.Split('|')
    [pscustomobject]@{ Id = [int]$p[0]; User = $p[1]; State = [int]$p[2] }
})
# LogonUI.exe runs inside a session while it is locked
$lockedSessions = @(Get-Process -Name LogonUI -ErrorAction SilentlyContinue | ForEach-Object { $_.SessionId })

foreach ($u in $users) {
    $name = [string]$u.Name
    try {
        $st  = Get-UserState $name
        $l   = Get-Limits $u $st
        $tod = $now.TimeOfDay
        $parentLocked = $l.LockedUntil -gt $nowEpoch
        $inWindow = (-not $l.Window) -or ($tod -ge $l.Window.Start -and $tod -lt $l.Window.End)

        $mine   = @($sessions | Where-Object { $_.User -ieq $name })
        $active = @($mine | Where-Object { $_.State -eq 0 -and $lockedSessions -notcontains $_.Id })

        # elapsed since last run, capped so sleep / clock jumps don't over-count
        $delta = 1.0
        if ([long]$st.LastTicks -gt 0) {
            $delta = ([TimeSpan]::FromTicks($now.Ticks - [long]$st.LastTicks)).TotalMinutes
            $delta = [Math]::Max(0, [Math]::Min($delta, 1.5))
        }
        $st.LastTicks = $now.Ticks
        if ($active.Count -gt 0 -and $inWindow -and -not $parentLocked) { $st.Minutes = [double]$st.Minutes + $delta }

        $remUse = $l.Minutes - [double]$st.Minutes
        $remWin = $(if (-not $l.Window) { [double]::PositiveInfinity } elseif (-not $inWindow) { -1.0 } else { ($l.Window.End - $tod).TotalMinutes })
        if ($parentLocked) {
            $remaining = -1.0
            $until = [DateTimeOffset]::FromUnixTimeSeconds($l.LockedUntil).UtcDateTime.AddMinutes([double]$pol.UtcOffsetMinutes).ToString('HH:mm')
            $why = "locked by a parent until $until"
        } else {
            $remaining = [Math]::Min($remUse, $remWin)
            $why = $(if ($remUse -le $remWin) { 'daily time used up' } else { 'outside allowed hours' })
        }

        # re-arm warnings if time was added (bonus / wider hours) and we're back above a threshold
        $st.Warned = @(@($st.Warned) | Where-Object { $remaining -le $_ })

        if ($remaining -le 0) {
            foreach ($s in $mine) {
                Write-Log ("[{0}] {1} (used {2:N1}/{3} min) - logging off session {4}" -f $name, $why, $st.Minutes, $l.Minutes, $s.Id)
                if ($s.State -eq 0) { [Wts]::Msg($s.Id, 'Screen time', "Screen time is over ($why). Logging off now.") }
                [Wts]::Logoff($s.Id)
            }
        } elseif ($active.Count -gt 0) {
            $due = @($WarnAt | Where-Object { $remaining -le $_ -and @($st.Warned) -notcontains $_ }) | Sort-Object | Select-Object -First 1
            if ($due) {
                $mins = [Math]::Max(1, [Math]::Ceiling($remaining))
                foreach ($s in $active) { [Wts]::Msg($s.Id, 'Screen time', "$mins minute(s) left ($why). Save your work.") }
                $st.Warned = @($WarnAt | Where-Object { $_ -ge $remaining })
                Write-Log "[$name] warned, $mins min left ($why)"
            }
        }
        Set-UserState $name $st
    } catch {
        Write-Log "[$name] error: $_"
    }
}
