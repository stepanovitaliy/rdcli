# build.ps1 — сборка rdcli.exe на Windows через vcpkg (статическая линковка).
# Требования: установленный vcpkg и переменная окружения VCPKG_INSTALLATION_ROOT.
# Результат: build\Release\rdcli.exe (и копия в release\rdcli.exe).

$ErrorActionPreference = "Stop"

$Triplet = "x64-windows-static-md"

if (-not $env:VCPKG_INSTALLATION_ROOT) {
    Write-Error "VCPKG_INSTALLATION_ROOT не задана. Установите vcpkg (https://github.com/microsoft/vcpkg) и задайте переменную."
    exit 1
}

$vcpkg = Join-Path $env:VCPKG_INSTALLATION_ROOT "vcpkg.exe"
$toolchain = Join-Path $env:VCPKG_INSTALLATION_ROOT "scripts\buildsystems\vcpkg.cmake"

Write-Host "==> vcpkg install (triplet: $Triplet)" -ForegroundColor Cyan
& $vcpkg install --triplet $Triplet protobuf libsodium zstd curl
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "==> cmake configure" -ForegroundColor Cyan
cmake -S . -B build -A x64 `
  -DCMAKE_TOOLCHAIN_FILE="$toolchain" `
  -DVCPKG_TARGET_TRIPLET="$Triplet" `
  -DCMAKE_BUILD_TYPE=Release
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "==> cmake build" -ForegroundColor Cyan
cmake --build build --config Release
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

New-Item -ItemType Directory -Force -Path release | Out-Null
Copy-Item build\Release\rdcli.exe release\rdcli.exe -Force

Write-Host ""
Write-Host "Готово: release\rdcli.exe" -ForegroundColor Green
