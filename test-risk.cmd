@echo off
setlocal
cd /d "%~dp0"
for %%F in (risk-core.js app.js network-core.js network.js) do (
 node --check web\%%F
 if errorlevel 1 exit /b 1
)
for %%T in (risk-core frontend-ui frontend-markup network-core network-flow) do (
 node tests\%%T.test.cjs
 if errorlevel 1 exit /b 1
)
call test-web.cmd --no-pause
if errorlevel 1 exit /b 1
if /i not "%~1"=="--no-pause" pause
