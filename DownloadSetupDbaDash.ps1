<#

DownloadSetupDbaDash.ps1.ps1

.SYNOPSIS
.\DownloadSetupDbaDash.ps1

.DESCRIPTION
Download and extract DbaDash and Dotnet10 
source,  David DbaDash Monitoring

.EXAMPLE
.\RunForMinutes.ps1


 Modification History
 --------------------
 2026-04-25 tdu Created
 #>
 
 
 # 1. Determine the installation drive (D: if available, otherwise C:)
$Drive = if (Test-Path "D:") { "D:\" } else { "C:\" }
$DBADashPath = Join-Path $Drive "DBADash"
$DotNetPath = Join-Path $Drive "dotnet"

# 2. Setup Directories
Write-Host "Installing to $Drive..." -ForegroundColor Cyan
foreach ($Path in @($DBADashPath, $DotNetPath)) {
    if (!(Test-Path $Path)) {
        New-Item -Path $Path -ItemType Directory | Out-Null
        Write-Host "Created folder: $Path"
    }
}

# 3. Download & Install DBA Dash (Latest GitHub Release)
$Repo = "trimble-oss/dba-dash"
$ApiUrl = "https://api.github.com/repos/$Repo/releases/latest"

Write-Host "Fetching latest DBA Dash version info..."
$ReleaseInfo = Invoke-RestMethod -Uri $ApiUrl
$Asset = $ReleaseInfo.assets | Where-Object { $_.name -like "DBADash_*.zip" } | Select-Object -First 1

if ($Asset) {
    $ZipFile = Join-Path $env:TEMP "DBADash.zip"
    Write-Host "Downloading DBA Dash $($ReleaseInfo.tag_name)..." -ForegroundColor Green
    Invoke-WebRequest -Uri $Asset.browser_download_url -OutFile $ZipFile
    
    Write-Host "Extracting to $DBADashPath..."
    Expand-Archive -Path $ZipFile -DestinationPath $DBADashPath -Force
    Remove-Item $ZipFile
}

# 4. Download .NET 10 Binaries (Windows x64)
# Note: Using the direct binary link for .NET 10.0
$DotNetUrl = "https://dotnetcli.azureedge.net/dotnet/Runtime/10.0.0/dotnet-runtime-10.0.0-win-x64.zip"
$DotNetZip = Join-Path $env:TEMP "dotnet10.zip"

Write-Host "Downloading .NET 10 Binaries (No Install)..." -ForegroundColor Green
Invoke-WebRequest -Uri $DotNetUrl -OutFile $DotNetZip

Write-Host "Extracting .NET 10 to $DotNetPath..."
Expand-Archive -Path $DotNetZip -DestinationPath $DotNetPath -Force
Remove-Item $DotNetZip

Write-Host "`nInstallation Complete!" -ForegroundColor Cyan
Write-Host "DBA Dash: $DBADashPath"
Write-Host ".NET 10:  $DotNetPath"
