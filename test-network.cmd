@echo off
setlocal
cd /d "%~dp0"
if not exist work\web-test-build mkdir work\web-test-build
call build-web.cmd --no-pause work\web-test-build\LocalLens.Web.exe
if not "%ERRORLEVEL%"=="0" exit /b %ERRORLEVEL%
set "LL_CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%LL_CSC%" set "LL_CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
"%LL_CSC%" /nologo /codepage:65001 /out:work\web-test-build\NetworkChecks.exe /reference:work\web-test-build\LocalLens.Web.exe tests\NetworkChecks.cs
if not "%ERRORLEVEL%"=="0" exit /b %ERRORLEVEL%
work\web-test-build\NetworkChecks.exe
if not "%ERRORLEVEL%"=="0" exit /b %ERRORLEVEL%
"%LL_CSC%" /nologo /codepage:65001 /out:work\web-test-build\ClueRuleChecks.exe /reference:work\web-test-build\LocalLens.Web.exe /reference:System.Web.Extensions.dll tests\ClueRuleChecks.cs
if not "%ERRORLEVEL%"=="0" exit /b %ERRORLEVEL%
work\web-test-build\ClueRuleChecks.exe
if not "%ERRORLEVEL%"=="0" exit /b %ERRORLEVEL%
for %%T in (ContactEvidenceChecks ConfigurationEvidenceChecks HistoryEvidenceChecks) do (
 "%LL_CSC%" /nologo /codepage:65001 /out:work\web-test-build\%%T.exe /reference:work\web-test-build\LocalLens.Web.exe /reference:System.Web.Extensions.dll tests\%%T.cs
 if errorlevel 1 exit /b 1
 work\web-test-build\%%T.exe
 if errorlevel 1 exit /b 1
)
node tests\network-core.test.cjs
if not "%ERRORLEVEL%"=="0" exit /b %ERRORLEVEL%
node tests\network-flow.test.cjs
if not "%ERRORLEVEL%"=="0" exit /b %ERRORLEVEL%
if /i not "%~1"=="--no-pause" pause
