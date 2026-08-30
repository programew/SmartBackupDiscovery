$ErrorActionPreference = 'Stop'
Write-Host 'Restoring SmartBackupDiscovery 3.3...'
dotnet restore .\SmartBackupDiscovery.csproj
Write-Host 'Building Windows customer edition...'
dotnet build .\SmartBackupDiscovery.csproj -c Release -f net10.0-windows --no-restore
dotnet run --project .\SmartBackupDiscovery.csproj -c Release -f net10.0-windows --no-build -- selftest
Write-Host 'Publishing win-x64...'
dotnet publish .\SmartBackupDiscovery.csproj -c Release -f net10.0-windows -r win-x64 --self-contained false -o .\publish\win-x64
Write-Host 'Done: publish\win-x64'
