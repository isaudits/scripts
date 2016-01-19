#Exports all group policy objects as individual GPO reports

Import-Module GroupPolicy 
Get-GPO -all | % { Get-GPOReport -GUID $_.id -ReportType HTML -Path "GPO_$($_.displayName).html" }