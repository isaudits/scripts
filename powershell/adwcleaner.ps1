<#
.SYNOPSIS
    Run AdwCleaner scan.
.DESCRIPTION
    Downloads the current version of AdwCleaner and executes a .
.PARAMETER workingDir
    The working directory where the AdwCleaner.exe will be downloaded and run.
.EXAMPLE
    .\adwcleaner.ps1 -workingDir "C:\custom\path\"
.AUTHOR
    Matthew C. Jones, CPA, CISA, OSCP, CCFE
    Symphona, LLP
.CHANGELOG
    1/9/2023 - Initial release.
#>

param(
    [string]$workingDir = "C:\temp\"
)

$downloadUrl = "https://adwcleaner.malwarebytes.com/adwcleaner?channel=release"
$savePath = "$workingDir\AdwCleaner.exe"
$logPath = "$workingDir\Adwcleaner\Logs"
$quarantinePath = "$workingDir\Adwcleaner\Quarantine"
$switches = "/eula /clean /noreboot /path $workingDir"

# Create the directory if it doesn't exist
$null = New-Item -ItemType Directory -Force -Path (Split-Path -Parent $savePath)

# Download the file
Invoke-WebRequest -Uri $downloadUrl -OutFile $savePath

# Run the file
Start-Process -FilePath $savePath -ArgumentList $switches -Verb RunAs -Wait

# Get the most recent file in the logs directory
$logFile = Get-ChildItem -Path $logPath | Sort-Object LastWriteTime -Descending | Select-Object -First 1

# Read the content of the file
$content = Get-Content -LiteralPath $logFile.FullName

# Output the content to the CLI
Write-Output $logFile.FullName
Write-Output $content