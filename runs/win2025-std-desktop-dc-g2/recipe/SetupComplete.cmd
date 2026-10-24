@echo off
rem Runs as SYSTEM once setup has finished, before the logon screen.
rem Register collect.ps1 at startup (in case setup reboots once more) and
rem start it now; collect.ps1 waits for boot to settle and runs only once.
schtasks /create /f /tn BaselineCollect /ru SYSTEM /rl HIGHEST /sc onstart /tr "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\bl-tools\collect.ps1" > C:\bl-tools\setupcomplete.log 2>&1
schtasks /run /tn BaselineCollect >> C:\bl-tools\setupcomplete.log 2>&1
