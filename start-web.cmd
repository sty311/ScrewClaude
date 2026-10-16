@echo off
setlocal
if not exist "%~dp0ScrewClaude.Web.exe" goto missing
if not exist "%~dp0ScrewClaude.Web.exe.config" goto missing
set "SC_NET_RELEASE=0"
for /f "tokens=3" %%R in ('reg query "HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" /v Release 2^>nul') do set /a SC_NET_RELEASE=%%R >nul 2>&1
if %SC_NET_RELEASE% LSS 528040 goto runtime
if /i "%~1"=="--check" (
 echo ScrewClaude: executable, configuration and .NET Framework 4.8+ are available.
 exit /b 0
)
pushd "%~dp0"
if errorlevel 1 exit /b 1
start "" "%CD%\ScrewClaude.Web.exe" %*
popd
exit /b 0
:missing
echo Extract the complete portable ZIP before starting ScrewClaude.
if /i not "%~1"=="--check" pause
exit /b 1
:runtime
echo ScrewClaude requires .NET Framework 4.8 or newer on Windows 10/11.
echo Download: https://dotnet.microsoft.com/en-us/download/dotnet-framework/net48
if /i not "%~1"=="--check" pause
exit /b 1
