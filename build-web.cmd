@echo off
setlocal
cd /d "%~dp0"
set "LL_CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%LL_CSC%" set "LL_CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
if not exist "%LL_CSC%" exit /b 1
set "LL_OUTPUT=ScrewClaude.Web.exe"
if not "%~2"=="" set "LL_OUTPUT=%~2"
"%LL_CSC%" /nologo /codepage:65001 /target:winexe /main:LocalLens.WebProgram /platform:anycpu /optimize+ /out:"%LL_OUTPUT%" /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll /reference:System.Management.dll /reference:System.Device.dll /reference:System.IO.Compression.dll /reference:System.IO.Compression.FileSystem.dll /resource:src\catalog.json,catalog.json /resource:src\china-boundary.json,china-boundary.json /resource:src\BrowserCheck.html,BrowserCheck.html /resource:src\app.ico,app.ico /resource:web\mascot-doze.png,web.mascot-doze.png /resource:web\mascot-scan.png,web.mascot-scan.png /resource:web\mascot-result.png,web.mascot-result.png /resource:web\risk-core.js,web.risk-core.js /resource:web\mascot-medium.png,web.mascot-medium.png /resource:web\mascot-high.png,web.mascot-high.png /resource:web\index.html,web.index.html /resource:web\styles.css,web.styles.css /resource:web\logo-avatar.png,web.logo-avatar.png /resource:web\app.js,web.app.js /resource:web\network-core.js,web.network-core.js /resource:web\network.js,web.network.js /win32icon:src\app.ico /win32manifest:src\app.manifest src\*.cs
if errorlevel 1 exit /b 1
copy /Y LocalLens.exe.config "%LL_OUTPUT%.config" >nul
echo Build completed: %LL_OUTPUT%
if /i not "%~1"=="--no-pause" pause
