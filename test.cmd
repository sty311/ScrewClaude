@echo off
setlocal
cd /d "%~dp0"
call build.cmd --no-pause
if not "%ERRORLEVEL%"=="0" exit /b %ERRORLEVEL%
set "LL_CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%LL_CSC%" set "LL_CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
if not exist work mkdir work
copy /Y LocalLens.exe work\LocalLens.exe >nul
if not "%ERRORLEVEL%"=="0" exit /b %ERRORLEVEL%
xcopy tests\fixtures work\fixtures /E /I /Y >nul
if not "%ERRORLEVEL%"=="0" exit /b %ERRORLEVEL%
"%LL_CSC%" /nologo /codepage:65001 /out:work\Checks.exe /reference:LocalLens.exe /reference:System.Web.Extensions.dll tests\Checks.cs
if not "%ERRORLEVEL%"=="0" exit /b %ERRORLEVEL%
work\Checks.exe
if not "%ERRORLEVEL%"=="0" exit /b %ERRORLEVEL%
"%LL_CSC%" /nologo /codepage:65001 /out:work\ExtendedChecks.exe /reference:LocalLens.exe /reference:System.Web.Extensions.dll tests\ExtendedChecks.cs
if not "%ERRORLEVEL%"=="0" exit /b %ERRORLEVEL%
work\ExtendedChecks.exe work\fixtures
if not "%ERRORLEVEL%"=="0" exit /b %ERRORLEVEL%
"%LL_CSC%" /nologo /codepage:65001 /out:work\ImportChecks.exe /reference:LocalLens.exe /reference:System.Web.Extensions.dll tests\ImportChecks.cs
if not "%ERRORLEVEL%"=="0" exit /b %ERRORLEVEL%
work\ImportChecks.exe work\import-fixtures
if not "%ERRORLEVEL%"=="0" exit /b %ERRORLEVEL%
echo All tests passed.
if /i not "%~1"=="--no-pause" pause
