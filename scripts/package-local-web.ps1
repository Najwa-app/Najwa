param([switch]$DebugBuild, [switch]$SkipBuild)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$configuration = if ($DebugBuild) { 'debug' } else { 'release' }
if (!$SkipBuild) {
    Push-Location (Join-Path $projectRoot 'apps/desktop')
    try {
        & npm run web:build
        if ($LASTEXITCODE -ne 0) { throw 'Web UI build failed.' }
    } finally { Pop-Location }
    $cargoArguments = @('build','--manifest-path',(Join-Path $projectRoot 'Cargo.toml'),'--locked','-p','najwa-web','--features','bundled-ui')
    if (!$DebugBuild) { $cargoArguments += '--release' }
    & (Join-Path $PSScriptRoot 'native-cargo.ps1') -CargoArguments $cargoArguments
    if ($LASTEXITCODE -ne 0) { throw 'Native service build failed.' }
}
& python (Join-Path $PSScriptRoot 'package-local-web.py') --skip-build --configuration $configuration
if ($LASTEXITCODE -ne 0) { throw 'Native app packaging failed.' }
