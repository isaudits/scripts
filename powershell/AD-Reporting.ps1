
<#
.Synopsis
   Powershell Script to get details AD reports
.DESCRIPTION
   script fetches below reports
   -> Disabled account details
   -> empty OU
   -> All OU
   -> Password never expire users
   -> GPO links
   -> GPO Details
   -> Inactive accounts
   -> Previlaged Groups
   -> SchemaHistory
   -> w32tm2 status
   -> w32tm1 configuration
   -> DC daig
   -> Computer Objects

.NOTES    
    Name: AD-Reporting.ps1
    Author: Deepak Vishwakarma
    Email : Deepitpro@outlook.com
    Version: 0.1 
    DateCreated: 24 Dec 2017
#>



# Load PowerShell module for Active Directory
try{

Import-Module ActiveDirectory

$Inactivedays = "60" #update nummber of days you are checking
#date  
$date = $((Get-Date).ToString('MM-dd-yyyy_hh-mm'))
#path
$path = ".\AD_Reports_$date"

if (!(Test-path $path))
{
md $path | Out-Null
}
}
catch 
{

Write-Host "Issue while creating the folder Exception : $_.Exception.Message "

}

Write-Host -ForegroundColor Green "!! Collecting Active Directory data... !!"

try{
Write-Host "--------------------------------------------------------------"
Write-Host "Gathering inactive users details..."
Write-Host "--------------------------------------------------------------"
#Get inactive accounts details
$selection = "EmployeeID", "Name", "SamAccountName","ObjectSid","ObjectGUID","Enabled", "UserPrincipalName", "whenChanged", "whenCreated", "PasswordNeverExpires", "PasswordLastSet", "LastLogonDate", "lastLogonTimestamp", "DistinguishedName", "Description"

$resultInactive = Search-ADAccount -usersonly -accountinactive -timespan $Inactivedays

$Inactiveuser = $resultInactive | Get-ADUser -Properties * | select $selection
$INACount = $Inactiveuser.Count

$file1 = "$path\$INACount-Inactive_Account_$(Get-ADDomain | Select -ExpandProperty NetBIOSName)_$date.csv"
$Inactiveuser | Export-Csv $file1 -NoClobber -NoTypeInformation
}
catch 
    {
    Write-Host "Issue while Gathering inactive users details...: $_.Exception.Message"
    }

try{
Write-Host "Gathering Password never expires enabled users details..."
Write-Host "--------------------------------------------------------------"
#Get Password never expires accounts details
$resultPwdneverExp = Search-ADAccount -UsersOnly -PasswordNeverExpires

$psne = $resultPwdneverExp | Get-ADUser -Properties * | select $selection 
$psneCount = $psne.Count
$file2 = "$path\$psneCount-Password_Never_Exp_$(Get-ADDomain | Select -ExpandProperty NetBIOSName)_$date.csv"
$psne | Export-Csv $file2 -NoClobber -NoTypeInformation
}
catch 
    {
    Write-Host "Issue while Gathering Password never expires enabled users details...: $_.Exception.Message"
    }

try{
Write-Host "Gathering disabled users details..."
Write-Host "--------------------------------------------------------------"
#Get Disabled accounts Details

$resultAcctDisabled = Search-ADAccount -UsersOnly -AccountDisabled
$acdi = $resultAcctDisabled | Get-ADUser -Properties * | select $selection 
$acdicount = $acdi.Count
$file3 = "$path\$acdicount-Disabled_Accounts_$(Get-ADDomain | Select -ExpandProperty NetBIOSName)_$date.csv"
$acdi | Export-Csv $file3 -NoClobber -NoTypeInformation
}
catch 
    {
    Write-Host "Issue while Gathering disabled users details...: $_.Exception.Message"
    }

try{
Write-Host "Gathering privileged group details..."
Write-Host "--------------------------------------------------------------"
#Get Previlaged Groups Details
$file4 = "$path\Previlaged_Groups_$(Get-ADDomain | Select -ExpandProperty NetBIOSName)_$date.csv"
$groups = "Domain Admins","Enterprise Admins"
$result =@()
foreach($group in $groups)
{
$result += Get-ADGroupMember -Identity $group -Recursive | select distinguishedName, samaccountname,name,@{Expression={$group};Label="Group Name"}}
 $result| Export-Csv $file4 -NoClobber -NoTypeInformation
}
catch 
    {
    Write-Host "Issue while Gathering privileged group details...: $_.Exception.Message"
    }


try{
Write-Host "Gathering All Computer Object details..."
Write-Host "--------------------------------------------------------------"
#get All Computer Details
$AllComp = Get-ADComputer -Filter * -Property * | Select-Object Name,IPv4Address,Enabled,OperatingSystem,OperatingSystemServicePack,OperatingSystemVersion,Created,LastLogonDate,SID,GUID 
$AllCompCount = $AllComp.Count
$file5 = "$path\$AllCompCount-Computer_Objects_$(Get-ADDomain | Select -ExpandProperty NetBIOSName)_$date.csv"
$AllComp | Export-CSV $file5 -NoClobber -NoTypeInformation
}
catch 
    {
    Write-Host "Issue while Gathering All Computer Object details...: $_.Exception.Message"
    }

try{
Write-Host "Gathering All the OU details..."
Write-Host "--------------------------------------------------------------"
#Get All OU details

$AllOU = Get-ADOrganizationalUnit -Filter * -Property * | Select-Object DistinguishedName , Name, ProtectedFromAccidentalDeletion, CanonicalName,SID,GUID 
$AllouCount = $AllOU.Count
$file6 = "$path\$AllouCount-OU_Details_$(Get-ADDomain | Select -ExpandProperty NetBIOSName)_$date.csv"
$AllOU | Export-Csv $file6 -NoClobber -NoTypeInformation

}
catch 
    {
    Write-Host "Issue while Gathering All the OU details...: $_.Exception.Message"
    }

try{
Write-Host "Gathering All GPO details..."
Write-Host "--------------------------------------------------------------"
#get all GPO details
$file7 = "$path\GPO_Report_$(Get-ADDomain | Select -ExpandProperty NetBIOSName)_$date.HTML"
Get-GPOReport -All -ReportType HTML -Path $file7
}
catch 
    {
    Write-Host "Issue while Gathering All GPO details...: $_.Exception.Message"
    }
try{
Write-Host "Gathering Empty OU details..."
Write-Host "--------------------------------------------------------------"
#Get Empty OU Details
$EmptyOUs = Get-ADOrganizationalUnit -Filter * | Where-Object {-not ( Get-ADObject -Filter * -SearchBase $_.Distinguishedname -SearchScope OneLevel -ResultSetSize 1 )}
$oucount = $EmptyOUs.Count
$file9 = "$path\$oucount-Empty_OU_Details_Count-$(Get-ADDomain | Select -ExpandProperty NetBIOSName)_$date.csv"
$EmptyOUs | Select-Object name ,DistinguishedName | Export-Csv $file9 -NoClobber -NoTypeInformation
}
catch 
    {
    Write-Host "Issue while Gathering Empty OU details...: $_.Exception.Message"
    }

#####################################################
### GET GPO DETAILS WHICH ARE LINKED WITH THE OU'S ##
#####################################################
Write-Host "Gathering GPO links w.r.t OU details..."
try{
Import-Module GroupPolicy
Import-Module ActiveDirectory
$file8 = "$path\GPO_Link_OU_Report_$(Get-ADDomain | Select -ExpandProperty NetBIOSName)_$date.csv"

$GPOs = Get-GPO -All | Select-Object ID, Path, DisplayName, GPOStatus, WMIFilter

$GPOsHash = @{}
ForEach ($GPO in $GPOs) {
    $GPOsHash.Add($GPO.Path,$GPO)
}

# Empty array to hold all possible GPO link SOMs
$gPLinks = @()

# GPOs linked to the root of the domain
#  !!! Get-ADDomain does not return the gPLink attribute
$gPLinks += `
 Get-ADObject -Identity (Get-ADDomain).distinguishedName -Properties name, distinguishedName, gPLink, gPOptions |
 Select-Object name, distinguishedName, gPLink, gPOptions, @{name='Depth';expression={0}}

# GPOs linked to OUs
#  !!! Get-GPO does not return the gPLink attribute
# Calculate OU depth for graphical representation in final report
$gPLinks += `
 Get-ADOrganizationalUnit -Filter * -Properties name, distinguishedName, gPLink, gPOptions |
 Select-Object name, distinguishedName, gPLink, gPOptions, @{name='Depth';expression={($_.distinguishedName -split 'OU=').count - 1}}

# GPOs linked to sites
$gPLinks += `
 Get-ADObject -LDAPFilter '(objectClass=site)' -SearchBase "CN=Sites,$((Get-ADRootDSE).configurationNamingContext)" -SearchScope OneLevel -Properties name, distinguishedName, gPLink, gPOptions |
 Select-Object name, distinguishedName, gPLink, gPOptions, @{name='Depth';expression={0}}

# Empty report array
$report = @()

# Loop through all possible GPO link SOMs collected
ForEach ($SOM in $gPLinks) {
    # Filter out policy SOMs that have a policy linked
    If ($SOM.gPLink) {
        If ($SOM.gPLink.length -gt 1) {
            
            $links = @($SOM.gPLink -split {$_ -eq '[' -or $_ -eq ']'} | Where-Object {$_})
            # Use a for loop with a counter so that we can calculate the precedence value
            For ( $i = $links.count - 1 ; $i -ge 0 ; $i-- ) {
                
                $GPOData = $links[$i] -split {$_ -eq '/' -or $_ -eq ';'}
                # Add a new report row for each GPO link
                $report += New-Object -TypeName PSCustomObject -Property @{
                    Depth             = $SOM.Depth;
                    Name              = $SOM.Name;
                    DistinguishedName = $SOM.distinguishedName;
                    PolicyDN          = $GPOData[2];
                    Precedence        = $links.count - $i
                    GUID              = "{$($GPOsHash[$($GPOData[2])].ID)}";
                    DisplayName       = $GPOsHash[$GPOData[2]].DisplayName;
                    GPOStatus         = $GPOsHash[$GPOData[2]].GPOStatus;
                    WMIFilter         = $GPOsHash[$GPOData[2]].WMIFilter.Name;
                    Config            = $GPOData[3];
                    LinkEnabled       = [bool](!([int]$GPOData[3] -band 1));
                    Enforced          = [bool]([int]$GPOData[3] -band 2);
                    BlockInheritance  = [bool]($SOM.gPOptions -band 1)
                } # End Property hash table
            } # End For
        } Else {
            # BlockInheritance but no gPLink
            $report += New-Object -TypeName PSCustomObject -Property @{
                Depth             = $SOM.Depth;
                Name              = $SOM.Name;
                DistinguishedName = $SOM.distinguishedName;
                BlockInheritance  = [bool]($SOM.gPOptions -band 1)
            }
        } # End If
    } Else {
        # No gPLink at this SOM
        $report += New-Object -TypeName PSCustomObject -Property @{
            Depth             = $SOM.Depth;
            Name              = $SOM.Name;
            DistinguishedName = $SOM.distinguishedName;
            BlockInheritance  = [bool]($SOM.gPOptions -band 1)
        }
    } # End If
} # End ForEach

# Output the results to CSV file for viewing in Excel
$report |
 Select-Object @{name='SOM';expression={$_.name.PadLeft($_.name.length + ($_.depth * 5),'_')}}, `
  DistinguishedName, BlockInheritance, LinkEnabled, Enforced, Precedence, `
  DisplayName, GPOStatus, WMIFilter, GUID, PolicyDN |
 Export-CSV $file8 -NoTypeInformation
 }
 catch 
    {

    Write-Host "Issue with GPO link Report : $_.Exception.Message"

    }
#Schema Report
Write-Host "--------------------------------------------------------------"
Write-Host "Gathering Schema details..."
Write-Host "--------------------------------------------------------------"
try{
$schema = Get-ADObject -SearchBase ((Get-ADRootDSE).schemanamingcontext)-SearchScope OneLevel -Filter * -Properties objectClass, name, whenChanged, whenCreated | Select-Object objectClass, name, whenChanged, @{name="event";expression={($_.whencreated).Date.ToShortDateString()}} |Sort-Object whenCreated
#Details of schema objects changed by date:
$schema | Format-Table objectClass, name, whenCreated, whenChanged -groupby event -autosize | Export-Csv "$path\SchemaHistory_One_$((Get-Date).ToString('MM-dd-yyyy_hh-mm')).csv" -NoTypeInformation 

#nCount of schema objects changed by date:
$schema | Group-object event | Format-Table Count,Name,Group -Autosize | Export-Csv "$path\SchemaHistory_Two_$((Get-Date).ToString('MM-dd-yyyy_hh-mm')).csv" -NoTypeInformation 
}
catch 
    {

    Write-Host "Issue with Schema Report : $_.Exception.Message"

    }
#Time service
try{
Write-Host "Gathering Time service details..."
Write-Host "--------------------------------------------------------------"
cmd /c "w32tm /query /configuration" | Out-File "$path\w32tm1_configuration_$date.txt"
cmd /c "w32tm /query /status" | Out-File "$path\w32tm2_status_$date.txt"
}
catch 
    {

    Write-Host "Issue with TimeService command : $_.Exception.Message"

    }
#DCDaig
try{
Write-Host "Gathering dcdiag details..."
Write-Host "--------------------------------------------------------------"
cmd /c "dcdiag" | Out-File "$path\dcdiag_$date.txt"
}
 catch 
    {
    Write-Host "Issue with DCDaig command : $_.Exception.Message"

    }
Write-Host -ForegroundColor Green "The end of Active Directory report"
Write-Host "--------------------------------------------------------------"

