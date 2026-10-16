@echo off
setlocal
cd /d "%~dp0"
if not exist work\web-test-build mkdir work\web-test-build
call build-web.cmd --no-pause work\web-test-build\ScrewClaude.Web.exe
if not "%ERRORLEVEL%"=="0" exit /b %ERRORLEVEL%
set "LL_CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%LL_CSC%" set "LL_CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
"%LL_CSC%" /nologo /codepage:65001 /out:work\web-test-build\WebChecks.exe /reference:work\web-test-build\ScrewClaude.Web.exe /reference:System.Web.Extensions.dll tests\WebChecks.cs
if not "%ERRORLEVEL%"=="0" exit /b %ERRORLEVEL%
work\web-test-build\WebChecks.exe
if not "%ERRORLEVEL%"=="0" exit /b %ERRORLEVEL%
"%LL_CSC%" /nologo /codepage:65001 /out:work\web-test-build\LocationProbeChecks.exe /reference:work\web-test-build\ScrewClaude.Web.exe /reference:System.Web.Extensions.dll tests\LocationProbeChecks.cs
if not "%ERRORLEVEL%"=="0" exit /b %ERRORLEVEL%
work\web-test-build\LocationProbeChecks.exe
if not "%ERRORLEVEL%"=="0" exit /b %ERRORLEVEL%
if /i not "%~1"=="--no-pause" pause
