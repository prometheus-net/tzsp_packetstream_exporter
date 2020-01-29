$ErrorActionPreference = "Stop"

dotnet publish -c Release -r linux-x64
if ($LASTEXITCODE -ne 0) {
  Write-Error "Build failed for linux-64"
}

dotnet publish -c Release -r win-x64
if ($LASTEXITCODE -ne 0) {
  Write-Error "Build failed for win-64"
}

if (!(Test-Path ./Output/)) {
  New-Item -ItemType Directory ./Output/ | Out-Null
}

Get-ChildItem ./Output/ | Remove-Item

Compress-Archive -Path ./bin/Release/netcoreapp3.1/linux-x64/publish/* -DestinationPath ./Output/linux-x64.zip
Compress-Archive -Path ./bin/Release/netcoreapp3.1/win-x64/publish/* -DestinationPath ./Output/win-x64.zip