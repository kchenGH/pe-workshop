@echo off
setlocal
if exist "%~dp0artifacts\PEWorkshop\PEWorkshop.exe" (
    start "" "%~dp0artifacts\PEWorkshop\PEWorkshop.exe" %*
) else (
    dotnet run --project "%~dp0src\PeWorkshop.App" -c Release -- %*
)
