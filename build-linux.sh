#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
echo 'Restoring SmartBackupDiscovery 3.3 net10.0...'
dotnet restore SmartBackupDiscovery.csproj -p:TargetFramework=net10.0
echo 'Building Linux/cross-platform CLI...'
dotnet build SmartBackupDiscovery.csproj -c Release -f net10.0 --no-restore
dotnet run --project SmartBackupDiscovery.csproj -c Release -f net10.0 --no-build -- selftest
echo 'Publishing linux-x64...'
dotnet publish SmartBackupDiscovery.csproj -c Release -f net10.0 -r linux-x64 --self-contained false --no-restore -o ./publish/linux-x64
echo 'Done: publish/linux-x64'
