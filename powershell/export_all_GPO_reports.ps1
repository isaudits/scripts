#Exports all group policy objects as individual GPO reports

Import-Module GroupPolicy
$outDir = (Get-Location -PSProvider FileSystem).ProviderPath
Get-GPO -all | % { Get-GPOReport -GUID $_.id -ReportType HTML -Path (Join-Path $outDir "GPO_$($_.displayName).html") }
Get-GPOReport -All -ReportType html -Path (Join-Path $outDir GPO_all.html)
Get-GPOReport -All -ReportType xml -Path (Join-Path $outDir GPO_all.xml)