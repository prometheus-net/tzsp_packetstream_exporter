$ErrorActionPreference = "Stop"

dotnet publish -c Release -r linux-x64
if ($LASTEXITCODE -ne 0) {
  Write-Error "Build failed for linux-64"
}

dotnet publish -c Release -r win-x64
if ($LASTEXITCODE -ne 0) {
  Write-Error "Build failed for win-64"
}