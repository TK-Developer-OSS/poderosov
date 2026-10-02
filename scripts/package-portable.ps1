# Builds the portable Windows version of PoderosoV and zips it.
#
#   powershell -ExecutionPolicy Bypass -File scripts\package-portable.ps1
#
# Needs the MSYS2 UCRT64 Rust toolchain (cargo, gcc, objdump). The result is
# dist\PoderosoV-<version>-portable-win64.zip: unpack it anywhere and run
# PoderosoV.exe. Settings stay in its "settings" folder.

param(
    [string]$Msys2Bin = 'D:\msys64\ucrt64\bin'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$env:PATH = "$Msys2Bin;$env:PATH"

$version = (Select-String -Path (Join-Path $root 'Cargo.toml') -Pattern '^version\s*=\s*"([^"]+)"').Matches[0].Groups[1].Value
$name = "PoderosoV-$version-portable-win64"
$dist = Join-Path $root 'dist'
$stage = Join-Path $dist $name

Write-Host "Building PoderosoV $version (release)..."
Push-Location $root
try {
    # custom-protocol is what the Tauri CLI turns on for production builds.
    cargo build --release -p poderosov --features tauri/custom-protocol
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed ($LASTEXITCODE)" }
} finally {
    Pop-Location
}

$release = Join-Path $root 'target\release'
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Path $stage | Out-Null
New-Item -ItemType Directory -Path (Join-Path $stage 'settings') | Out-Null
New-Item -ItemType Directory -Path (Join-Path $stage 'licenses') | Out-Null

$exe = Join-Path $stage 'PoderosoV.exe'
Copy-Item (Join-Path $release 'poderosov.exe') $exe
# The GNU toolchain links WebView2 through this loader instead of statically.
Copy-Item (Join-Path $release 'WebView2Loader.dll') $stage

# Any MinGW runtime DLL the executable still depends on travels with it.
$imports = & objdump -p $exe | Select-String 'DLL Name:\s*(\S+)' | ForEach-Object { $_.Matches[0].Groups[1].Value }
foreach ($dll in $imports) {
    $candidate = Join-Path $Msys2Bin $dll
    if (Test-Path $candidate) {
        Write-Host "  bundling $dll"
        Copy-Item $candidate $stage
    }
}

Copy-Item (Join-Path $root 'ui\vendor\xterm\LICENSE') (Join-Path $stage 'licenses\xterm.js-LICENSE.txt')
Copy-Item (Join-Path $root 'ui\vendor\xterm\LICENSE.addon-fit') (Join-Path $stage 'licenses\xterm-addon-fit-LICENSE.txt')

Copy-Item (Join-Path $PSScriptRoot 'portable-README.txt') (Join-Path $stage 'README.txt')

$zip = Join-Path $dist "$name.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path $stage -DestinationPath $zip
Write-Host "Done: $zip"
Get-ChildItem $stage -Recurse | Select-Object FullName, Length | Format-Table -AutoSize
