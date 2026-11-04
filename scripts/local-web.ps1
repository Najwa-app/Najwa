# Development launcher; the packaged app needs neither Node nor Rust installed.
param([string]$Profile, [int]$Port = 1421, [switch]$SkipBuild)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
if (!$SkipBuild) {
    Push-Location (Join-Path $projectRoot 'apps/desktop')
    try {
        & npm run web:build
        if ($LASTEXITCODE -ne 0) { throw 'The local web UI build failed.' }
    } finally { Pop-Location }
    & (Join-Path $PSScriptRoot 'native-cargo.ps1') -CargoArguments @('build','--manifest-path', (Join-Path $projectRoot 'Cargo.toml'),'--locked','-p','najwa-web')
    if ($LASTEXITCODE -ne 0) { throw 'The local service build failed.' }
}
$arguments = @('--assets',(Join-Path $projectRoot 'target/local-web-ui'),'--port', $Port)
if ($Profile) { $arguments += @('--profile',$Profile) }
Write-Host 'Najwa will open your browser. Keep this window open while using the development build.'
& (Join-Path $projectRoot 'target/debug/najwa-web.exe') @arguments
exit $LASTEXITCODE
