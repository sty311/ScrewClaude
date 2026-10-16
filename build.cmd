@echo off
setlocal
cd /d "%~dp0"
set "LL_CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%LL_CSC%" set "LL_CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
if not exist "%LL_CSC%" (
  echo .NET Framework C# compiler not found. Install .NET Framework 4.8 from Microsoft.
  if /i not "%~1"=="--no-pause" pause
  exit /b 1
)
"%LL_CSC%" /nologo /codepage:65001 /target:winexe /main:LocalLens.Program /platform:anycpu /optimize+ /out:LocalLens.exe /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll /reference:System.Management.dll /reference:System.Device.dll /reference:System.IO.Compression.dll /reference:System.IO.Compression.FileSystem.dll /resource:src\catalog.json,catalog.json /resource:src\china-boundary.json,china-boundary.json /resource:src\BrowserCheck.html,BrowserCheck.html /resource:src\app.ico,app.ico /win32icon:src\app.ico /win32manifest:src\app.manifest src\*.cs
if errorlevel 1 (
  echo Build failed. Close LocalLens if it is running, then try again.
  if /i not "%~1"=="--no-pause" pause
  exit /b 1
)
echo Build completed: LocalLens.exe
if /i not "%~1"=="--no-pause" pause
