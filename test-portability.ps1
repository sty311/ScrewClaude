param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
& cmd.exe /d /c 'build-web.cmd --no-pause'
if ($LASTEXITCODE -ne 0) { throw 'Web build failed' }
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (!(Test-Path -LiteralPath $compiler)) { $compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }
$testRoot = Join-Path $PSScriptRoot ('work\portable-' + [Guid]::NewGuid().ToString('N'))
# Build this path by code points so Windows PowerShell 5.1 handles it without a source BOM.
$unicodeFolder = -join @([char]0x6362,[char]0x673a,[char]0x6d4b,[char]0x8bd5)
$foreignCwd = Join-Path $testRoot 'unrelated working directory'
New-Item -ItemType Directory -Path $foreignCwd | Out-Null
$architectures = if ([Environment]::Is64BitOperatingSystem) { @('x64','x86') } else { @('x86') }
foreach ($architecture in $architectures) {
    $portableRoot = Join-Path $testRoot ($unicodeFolder + ' portable app ' + $architecture)
    New-Item -ItemType Directory -Path $portableRoot | Out-Null
    foreach ($file in @('ScrewClaude.Web.exe','ScrewClaude.Web.exe.config','start-web.cmd')) {
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot $file) -Destination $portableRoot
    }
    $assembly = Join-Path $portableRoot 'ScrewClaude.Web.exe'
    foreach ($harness in @('PortableChecks','WindowsChecks')) {
        $runner = Join-Path $portableRoot ($harness + '.exe')
        & $compiler /nologo /codepage:65001 "/platform:$architecture" "/out:$runner" "/reference:$assembly" /reference:System.Web.Extensions.dll /reference:System.Drawing.dll (Join-Path $PSScriptRoot ('tests\' + $harness + '.cs'))
        if ($LASTEXITCODE -ne 0) { throw "$harness compile failed: $architecture" }
        Copy-Item -LiteralPath (Join-Path $portableRoot 'ScrewClaude.Web.exe.config') -Destination ($runner + '.config')
        Push-Location -LiteralPath $foreignCwd
        try {
            if ($harness -eq 'PortableChecks') { & $runner }
            else { & $runner (Join-Path $testRoot ('native-' + $architecture)) (Join-Path $PSScriptRoot 'tests\fixtures') }
            if ($LASTEXITCODE -ne 0) { throw "$harness failed: $architecture" }
        } finally { Pop-Location }
    }
    Push-Location -LiteralPath $foreignCwd
    try {
        & cmd.exe /d /c ('"' + (Join-Path $portableRoot 'start-web.cmd') + '" --check')
        if ($LASTEXITCODE -ne 0) { throw 'Relocated launcher prerequisite check failed' }
    } finally { Pop-Location }
}
Write-Output 'PORTABILITY VALIDATION PASSED: relocated Unicode/space paths, foreign working directory, embedded assets, x86/x64 native dependencies, launcher prerequisites.'
