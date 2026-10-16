param([string]$Version = '2.10.1')
$ErrorActionPreference = 'Stop'
if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw 'Version must be numeric major.minor.patch' }
Set-Location -LiteralPath $PSScriptRoot
& cmd.exe /d /c 'build-web.cmd --no-pause'
if ($LASTEXITCODE -ne 0) { throw 'Build failed' }
$distRoot = Join-Path $PSScriptRoot 'dist'
$packageName = 'ScrewClaude-' + $Version + '-windows-portable'
$packageRoot = Join-Path $distRoot $packageName
$zipPath = Join-Path $distRoot ($packageName + '.zip')
if ((Test-Path -LiteralPath $packageRoot) -or (Test-Path -LiteralPath $zipPath)) { throw 'Package already exists; preserve it or choose a new version before rebuilding.' }
New-Item -ItemType Directory -Path $packageRoot | Out-Null
$files = @('ScrewClaude.Web.exe','ScrewClaude.Web.exe.config','start-web.cmd','README.md','LICENSE','THIRD_PARTY_NOTICES.md','PORTABILITY.md','SCORING_RULES_2.9.md','NETWORK_CHECKS.md','CHECKS.md')
foreach ($file in $files) { Copy-Item -LiteralPath (Join-Path $PSScriptRoot $file) -Destination $packageRoot }
$hashLines = foreach ($file in $files) { (Get-FileHash -LiteralPath (Join-Path $packageRoot $file) -Algorithm SHA256).Hash.ToLowerInvariant() + '  ' + $file }
[IO.File]::WriteAllLines((Join-Path $packageRoot 'SHA256SUMS.txt'),$hashLines,(New-Object Text.UTF8Encoding($false)))
Add-Type -AssemblyName System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::CreateFromDirectory($packageRoot,$zipPath,[IO.Compression.CompressionLevel]::Optimal,$true)
$zipHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText((Join-Path $distRoot 'SHA256SUMS.txt'),($zipHash + '  ' + $packageName + '.zip' + [Environment]::NewLine),(New-Object Text.UTF8Encoding($false)))
Write-Output ('Portable package: ' + $zipPath)
Write-Output ('SHA256: ' + $zipHash)
