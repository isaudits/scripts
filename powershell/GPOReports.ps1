#GPOReports.ps1
#Create GPO reports
#alan dot kaplan at va dot gov
#6-10-2013

Import-Module activedirectory
[void][System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic')  

$domain = [Microsoft.VisualBasic.Interaction]::InputBox("Report GPOs in what domain?", "Domain", "$env:userdnsdomain")
if ($domain.Length -eq 0)   {Exit}

$ReportPath =  [Microsoft.VisualBasic.Interaction]::InputBox("Write reports to what path?", `
    "Path", "$env:userprofile" +'\desktop\' + $domain + ' GPO Reports' )
if ($reportpath.Length -eq 0)   {Exit}

# if folder does not exist...
if (!(Test-Path $ReportPath)) {
# create it
[void](new-item $ReportPath -itemType directory)
}


$FilteredList = Get-GPO -All -Domain $domain `
 |Select-Object -Property DisplayName,Owner, GPOStatus,ID `
 |Out-GridView -OutputMode Multiple -Title "Wait for List, then select GPOs to report and click OK"

#variation of code at
#http://proproit.com/group-policy/the-simplest-way-to-get-group-policy-objects-reports/
#using 2.0 syntax

$FilteredList | foreach `
    {
    $Name = $_.DisplayName;
    Write-Host Writing GPO Report for $name to $reportpath\$name.html 
    Get-GPOReport $_.id -ReportType HTML -Domain $domain -Path $reportpath\$name.html 
    }
