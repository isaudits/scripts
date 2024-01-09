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

# Store the start time of the script
$startTime = Get-Date

# Run the file
Start-Process -FilePath $savePath -ArgumentList $switches -Verb RunAs -Wait

# Get all files in the logs directory that have been modified since the start time of the script
$logFiles = Get-ChildItem -Path $logPath | Where-Object { $_.LastWriteTime -gt $startTime }

# Read the contents of the files into the $content variable
$content = $logFiles | ForEach-Object { 
    $_.FullName
    Get-Content -LiteralPath $_.FullName 
}

# Output the content to the CLI
Write-Output $content