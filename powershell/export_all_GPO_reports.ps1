#Exports all group policy objects as individual GPO reports

Import-Module GroupPolicy 
Get-GPO -all | % { Get-GPOReport -GUID $_.id -ReportType HTML -Path "GPO_$($_.displayName).html" }
Get-GPOReport -All -ReportType html -Path GPO_all.html
Get-GPOReport -All -ReportType xml -Path GPO_all.xml