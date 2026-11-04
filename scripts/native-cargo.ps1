# Run the Windows workspace with the installed MSVC compiler and native tools.
param([Parameter(ValueFromRemainingArguments = $true)][string[]]$CargoArguments)
$ErrorActionPreference = 'Stop'
$vsInstall = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath
$compiler = Get-ChildItem -LiteralPath "$vsInstall\VC\Tools\MSVC" -Directory |
    Where-Object { Test-Path -LiteralPath "$($_.FullName)\bin\Hostx64\x64\cl.exe" } |
    Sort-Object Name -Descending | Select-Object -First 1
if (!$compiler) { throw 'Install the Visual Studio C++ desktop build tools.' }
$sdk = Get-ChildItem -LiteralPath "${env:ProgramFiles(x86)}\Windows Kits\10\Lib" -Directory |
    Where-Object { Test-Path -LiteralPath "$($_.FullName)\um\x64\kernel32.lib" } |
    Sort-Object Name -Descending | Select-Object -First 1
if (!$sdk) { throw 'Install a Windows SDK with x64 libraries.' }
$kit = "${env:ProgramFiles(x86)}\Windows Kits\10"
$env:VCINSTALLDIR = "$vsInstall\VC\"
$env:VSINSTALLDIR = "$vsInstall\"
$env:VCToolsInstallDir = "$($compiler.FullName)\"
$env:VSCMD_ARG_TGT_ARCH = 'x64'
$env:WindowsSdkDir = "$kit\"
$env:WindowsSDKVersion = "$($sdk.Name)\"
$env:PATH = "$($compiler.FullName)\bin\Hostx64\x64;$kit\bin\$($sdk.Name)\x64;C:\Strawberry\perl\bin;$env:PATH"
if (!(Get-Command nasm.exe -ErrorAction SilentlyContinue)) {
    $nasm = Get-ChildItem -Path "$env:LOCALAPPDATA\Microsoft\WinGet\Packages" -Recurse -Filter nasm.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($nasm) { $env:PATH = "$($nasm.DirectoryName);$env:PATH" }
}
$env:INCLUDE = "$($compiler.FullName)\include;$kit\Include\$($sdk.Name)\ucrt;$kit\Include\$($sdk.Name)\um;$kit\Include\$($sdk.Name)\shared"
$env:LIB = "$($compiler.FullName)\lib\x64;$kit\Lib\$($sdk.Name)\ucrt\x64;$kit\Lib\$($sdk.Name)\um\x64"
& cargo +stable-x86_64-pc-windows-msvc @CargoArguments
exit $LASTEXITCODE
