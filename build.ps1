$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
Write-Host 'Restoring SmartBackupDiscovery 3.7...'
dotnet restore .\SmartBackupDiscovery.csproj
if ($LASTEXITCODE -ne 0) { throw 'The .NET command failed. See output above.' }
Write-Host 'Building Windows customer edition...'
dotnet build .\SmartBackupDiscovery.csproj -c Release -f net10.0-windows --no-restore
if ($LASTEXITCODE -ne 0) { throw 'The .NET command failed. See output above.' }
dotnet run --project .\SmartBackupDiscovery.csproj -c Release -f net10.0-windows --no-build -- selftest
if ($LASTEXITCODE -ne 0) { throw 'The .NET command failed. See output above.' }
Write-Host 'Publishing win-x64...'
dotnet publish .\SmartBackupDiscovery.csproj -c Release -f net10.0-windows -r win-x64 --self-contained false -o .\publish\win-x64
if ($LASTEXITCODE -ne 0) { throw 'The .NET command failed. See output above.' }
Write-Host 'Done: publish\win-x64'
