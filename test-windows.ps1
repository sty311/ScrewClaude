param([switch]$Live)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
& cmd.exe /c 'test.cmd --no-pause'
if ($LASTEXITCODE -ne 0) { throw 'Core/import tests failed' }
$testRoot = Join-Path $PSScriptRoot ('work\windows-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot | Out-Null
$junctionTarget = Join-Path $testRoot 'junction-target'
New-Item -ItemType Directory -Path $junctionTarget | Out-Null
$junctionPath = Join-Path $testRoot 'junction'
New-Item -ItemType Junction -Path $junctionPath -Target $junctionTarget | Out-Null
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (!(Test-Path -LiteralPath $compiler)) { $compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }
$architectures = if ([Environment]::Is64BitOperatingSystem) { @('x64','x86') } else { @('x86') }
foreach ($architecture in $architectures) {
    $runner = Join-Path $PSScriptRoot ('work\WindowsChecks-' + $architecture + '.exe')
    & $compiler /nologo /codepage:65001 "/platform:$architecture" "/out:$runner" /reference:LocalLens.exe /reference:System.Drawing.dll tests\WindowsChecks.cs
    if ($LASTEXITCODE -ne 0) { throw 'Native test compilation failed' }
    & $runner (Join-Path $testRoot $architecture) tests\fixtures $junctionPath
    if ($LASTEXITCODE -ne 0) { throw "Native $architecture checks failed" }
}
& $compiler /nologo /codepage:65001 /out:work\GuiSmoke.exe /reference:LocalLens.exe /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll tests\GuiSmoke.cs
if ($LASTEXITCODE -ne 0) { throw 'GUI harness compilation failed' }
& .\work\GuiSmoke.exe (Join-Path $testRoot 'gui')
if ($LASTEXITCODE -ne 0) { throw 'GUI checks failed' }
if ($Live) {
    & .\work\GuiSmoke.exe (Join-Path $testRoot 'live-private') --live
    if ($LASTEXITCODE -ne 0) { throw 'Live offline scan checks failed' }
}
Write-Output "Windows validation completed. Local artifacts: $testRoot"
