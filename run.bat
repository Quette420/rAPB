```bat
@echo off
cd /d "E:\ProgrammingProjects\C#\rAPB\Emulator\APB SERVER"

start "" "LobbyServer.exe"
timeout /t 2 /nobreak >nul

start "" "WorldServer.exe"
timeout /t 2 /nobreak >nul

start "" "DistrictServer.exe"

exit
```
