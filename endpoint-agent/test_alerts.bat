@echo off
echo Triggering 'cmd.exe /c' alert...
cmd.exe /c timeout 3 > nul

echo Triggering powershell hidden alert...
powershell -nop -w hidden -c "Start-Sleep -Seconds 3"

echo Test processes launched. Check your agent's terminal!
