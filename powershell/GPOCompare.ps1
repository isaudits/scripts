#GPOCompare.ps1
#Compare 2 GPO reports
#alan dot kaplan at va dot gov
#Based on my GPO Reporter, GPOReports.ps1
#9/8/2014


#requires -module activedirectory
#requires -module GroupPolicy
#requires -version 2
#but version 3 is better

#and it requires Word for the compare
try
{
    $oWord = New-Object -ComObject Word.Application    
}
    catch
{
    Write-Warning "Execution halted.  This script requires Microsoft Word to compare GPOs"
    exit
}


if ((Test-Path $pshome\PowerShell_ISE.exe) -eq $False) {
    throw write-host "Requires Powershell 2 with ISE or PS 3"
}

Import-module grouppolicy 
Import-Module activedirectory

#old way.  PS3 + use add-type
[void][System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic')  

$domain = [Microsoft.VisualBasic.Interaction]::InputBox("Compare GPOs in what domain?", "Domain", "$env:userdnsdomain")
if ($domain.Length -eq 0)   {Exit}

$ReportPath =  [Microsoft.VisualBasic.Interaction]::InputBox("Write files to what path? (Existing files will be deleted!)", `
    "Path", "$env:userprofile" +'\desktop\' + $domain + ' GPO_Files' )
if ($reportpath.Length -eq 0)   {Exit}

# if folder exists, delete it
if ((Test-Path $ReportPath)) {
    Remove-Item $ReportPath -Force -recurse
}
# create it
[void](new-item $ReportPath -itemType directory)


Write "Reading the list of group policy objects in $domain.  Please wait ...."
$List = Get-GPO -All -server $domain  -Domain $domain  |
Select-Object -Property DisplayName,Owner, GPOStatus,ID 


$filteredList = ""
#break pipeline so the grid is populated all at once.
while ($filteredList.count -ne 2){
    $filteredList = $List |Out-GridView -OutputMode Multiple -Title "Select two GPOs to compare and click OK"  
}

Write "Got the GPOs to compare"

#loosely based on code at
#http://proproit.com/group-policy/the-simplest-way-to-get-group-policy-objects-reports/

$FilteredList | foreach {
    $Name = $_.DisplayName;
    Write-Host "Exporting HTML GPO Report for `"$name`" to`n`t`t $reportpath\$name.html"
    Get-GPOReport $_.id -ReportType HTML -server $domain -Domain $domain -Path $reportpath\$name.html 
    }

#Got the files.  Select the original for compare
[array]$fileList = (gci $ReportPath).FullName.split("`n")
$file1 = $fileList | Out-GridView -Title "Select the GPO 'Original' for comparison" -PassThru
#get the other element in the array
$file2 = $filelist | select-String -simplematch $file1 -NotMatch

$file1 = $file1.toString().Trim()
$file2 = $file2.toString().trim()

$doc = $oWord.Documents.Open($file1)
#if word crashes, increase this value
Start-Sleep -Seconds 1
#use your name as author in compare
#$author=$oWord.UserName
#leave author blank
$author =" "
$CompareFormat = "microsoft.office.interop.word.wdCompareTarget" -as [type]
[ref]$SaveFormat = "microsoft.office.interop.word.WdSaveFormat" -as [type]
write-host "Comparing documents"

#another reason to hate com objects.  Note the required [REF]
#and just try to skip the author field. 
#here we are comparing the second file with the loaded file.  Results to new document
#skip formatting changes and time date info.  See
#http://msdn.microsoft.com/en-us/library/ff192559(v=office.14).aspx

$doc.Compare($file2,[ref]$author,[ref]$CompareFormat::wdCompareTargetNew,[ref]$false,[ref]$false,[ref]$true,[ref]$true,[ref]$true)
Start-Sleep -Seconds 1
$doc.Close()
#Save compared doc.  Presumes modern version
Start-Sleep -Seconds 1
$CompareFile = "$ReportPath\GPO_Comparison.docx"
write-host "Saving $comparefile"
$oWord.ActiveDocument.Saveas([ref]$comparefile, [ref]$saveFormat::wdFormatDocument)
$oWord.Visible =$true

$wshShell = New-Object -ComObject Wscript.Shell
$msg = "Done.  You can print the list of changes in Word by going to Print/Settings "+`
"then choosing `"List of Markup`"."
$wshShell.Popup($msg,15,"Done",64) |Out-Null
