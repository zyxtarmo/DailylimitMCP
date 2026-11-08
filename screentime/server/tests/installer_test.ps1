# Runs Install-DailyLimit.ps1 on Linux with Windows-only cmdlets stubbed, to test its logic (config merging, validation).
param([string]$Installer, [string]$PD, [string]$ServerUrl, [string]$DevKey)
$env:ProgramData = $PD
$global:calls = New-Object System.Collections.ArrayList
function Get-LocalUser { param($Name) if ($Name -in 'kid1','kid2','adminkid') { [pscustomobject]@{ Name = $Name } } else { throw "no such user $Name" } }
function Get-LocalGroupMember { param($SID) @([pscustomobject]@{ Name = 'PC\adminkid' }) }
function icacls { [void]$global:calls.Add("icacls $args") }
function net { [void]$global:calls.Add("net $args") }
function New-ScheduledTaskAction { param($Execute,$Argument) [void]$global:calls.Add("action $Execute $Argument"); 'a' }
function New-ScheduledTaskTrigger { param([switch]$AtStartup,[switch]$Once,$At,$RepetitionInterval,$RepetitionDuration) 't' }
function New-ScheduledTaskPrincipal { param($UserId,$LogonType,$RunLevel) 'p' }
function New-ScheduledTaskSettingsSet { param([switch]$AllowStartIfOnBatteries,[switch]$DontStopIfGoingOnBatteries,[switch]$StartWhenAvailable,$MultipleInstances,[switch]$Hidden,$ExecutionTimeLimit) 's' }
function Register-ScheduledTask { param($TaskName,$Action,$Trigger,$Principal,$Settings,[switch]$Force) [void]$global:calls.Add("register $TaskName") }
function Start-ScheduledTask { param($TaskName) [void]$global:calls.Add("start $TaskName") }
function Unregister-ScheduledTask { param($TaskName,$Confirm,$ErrorAction) [void]$global:calls.Add("unregister $TaskName") }

function Run([string]$label, [scriptblock]$sb) {
    try { $out = & $sb 2>&1 3>&1 | Out-String; "--- $label`n$($out.Trim())" } catch { "--- $label`nTHROWS: $($_.Exception.Message)" }
}
$cfg = Join-Path $PD 'DailyLimit/config.json'
Run 'add kid1 full'    { & $Installer -Add kid1 -WeekdayMinutes 90 -WeekendMinutes 150 -WeekdayHours 15:00-20:00 -WeekendHours 09:00-24:00 }
Run 'add kid2 defaults'{ & $Installer -Add kid2 }
Run 'update kid1 minutes only' { & $Installer -Add kid1 -WeekdayMinutes 60 }
Run 'list'             { & $Installer -List }
Run 'bad hours'        { & $Installer -Add kid1 -WeekdayHours 20:00-08:00 }
Run 'unknown user'     { & $Installer -Add ghost }
Run 'admin child warns'{ & $Installer -Add adminkid }
Run 'clear hours'      { & $Installer -Add kid1 -WeekendHours '' }
Run 'remove kid2'      { & $Installer -Remove kid2 }
"--- config.json after local ops`n" + (Get-Content $cfg -Raw)
Run 'server needs key' { & $Installer -Server $ServerUrl }
Run 'server http refused' { & $Installer -Server http://evil.example.com -DeviceId x -DeviceKey y }
Run 'server wrong key' { & $Installer -Server $ServerUrl -DeviceId pc-inst -DeviceKey wrong }
Run 'server ok'        { & $Installer -Server $ServerUrl -DeviceId pc-inst -DeviceKey $DevKey }
"--- server.json`n" + (Get-Content (Join-Path $PD 'DailyLimit/server.json') -Raw)
Run 'list managed'     { & $Installer -List }
Run 'disconnect'       { & $Installer -Disconnect }
"server.json exists after disconnect: " + (Test-Path (Join-Path $PD 'DailyLimit/server.json'))
Run 'nothing'          { & $Installer }
"--- stub calls (tail)`n" + (($global:calls | Select-Object -Last 8) -join "`n")
